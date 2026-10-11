//! Allocate and freeze the joint parent before any deposit issuance.
use super::{
    Allocation, Funding, LIMIT, OriginJournal, Slot, check_funding, decode, exact_fields,
    response_bytes,
};
use crate::bootstrap::{BootstrapDraft, BootstrapParameters};
use crate::chain::ChainConfig;
use crate::freshness::SignerClient;
use crate::recovery::OriginRecoveryParameters;
use crate::signing::FundingKey;
use anyhow::{Context, Result, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{OutPoint, ScriptBuf, Transaction};
use zark_protocol::bootstrap::BootstrapBinding;
use zark_protocol::handoff::{Digest, capability_commitment};
use zark_protocol::wire::Command;
use zark_protocol::{point, scalar};

impl OriginJournal {
    /// The allocation request and all private owner keys already exist on disk.
    /// The response contains only the two server points and active share salt.
    pub fn allocate(&mut self, client: &dyn SignerClient) -> Result<ScriptBuf> {
        let response = client.request(&self.saved(&self.record.requests.allocate)?)?;
        exact_fields(
            &response,
            &["parent_server", "active_server", "active_server_salt"],
        )?;
        let allocation = Allocation {
            parent: response_bytes::<64>(&response, "parent_server")?.to_vec(),
            active: response_bytes::<64>(&response, "active_server")?.to_vec(),
            salt: response_bytes(&response, "active_server_salt")?,
        };
        point(&allocation.parent)?;
        point(&allocation.active)?;
        ensure!(
            allocation.parent == allocation.active && allocation.salt != [0; 32],
            "invalid bootstrap allocation"
        );
        if let Some(old) = &self.record.allocation {
            ensure!(
                old.parent == allocation.parent
                    && old.active == allocation.active
                    && old.salt == allocation.salt,
                "bootstrap allocation changed"
            );
        } else {
            self.record.allocation = Some(allocation);
            self.persist()?;
        }
        self.parent_script()
    }

    pub fn parent_script(&self) -> Result<ScriptBuf> {
        let a = self.allocation()?;
        Ok(crate::bitcoin::p2tr(
            &FundingKey::new(point(&a.parent)?, scalar(&self.record.parent_user)?)?.xonly()?,
        ))
    }

    /// Freeze a fully signed external transaction before broadcast. Native
    /// witness inputs keep its txid independent of later signature variation.
    /// Full input validity is checked by the Bitcoin backend before publication.
    pub fn bind_funding(&mut self, transaction: &Transaction, vout: u32) -> Result<()> {
        ensure!(
            self.record.parent_nonce.is_none(),
            "parent nonce already frozen"
        );
        check_funding(
            transaction,
            vout,
            self.record.amount,
            &self.parent_script()?,
        )?;
        let raw = hex::encode(serialize(transaction));
        if let Some(saved) = &self.record.funding {
            ensure!(
                saved.raw == raw && saved.vout == vout,
                "external funding already frozen"
            );
        } else {
            self.record.funding = Some(Funding { raw, vout });
            self.persist()?;
        }
        drop(self.ensure_bootstrap()?);
        Ok(())
    }

    pub fn prepare_parent(&mut self, client: &dyn SignerClient) -> Result<BootstrapBinding> {
        let (parent_funding, active_funding, capability, blinding) =
            self.ensure_bootstrap()?.commitments()?;
        let request = self.freeze(
            Slot::Prepare,
            Command::BootstrapPrepare {
                parent_funding,
                active_funding,
                capability,
                blinding,
            },
        )?;
        let response = client.request(&request)?;
        exact_fields(&response, &["parent_nonce"])?;
        let nonce = response_bytes::<64>(&response, "parent_nonce")?;
        if let Some(old) = &self.record.parent_nonce {
            ensure!(*old == nonce, "parent nonce changed");
        }
        let binding = self
            .ensure_bootstrap()?
            .bind_nonce(&self.record.context, nonce)?;
        self.record.parent_nonce = Some(nonce.to_vec());
        self.persist()?;
        Ok(binding)
    }

    /// Freeze the activation statement without producing or releasing a signature.
    pub fn freeze_parent(&mut self, client: &dyn SignerClient) -> Result<()> {
        let binding = self.bootstrap_binding()?;
        let request = self.freeze(
            Slot::Authorize,
            Command::BootstrapFreeze {
                statement: binding.encode()?,
            },
        )?;
        let response = client.request(&request)?;
        exact_fields(&response, &["frozen", "activation_held"])?;
        ensure!(
            response["frozen"] == true && response["activation_held"] == true,
            "activation draft was not held"
        );
        self.record.parent_authorized = true;
        self.persist()
    }

    pub(super) fn allocation(&self) -> Result<&Allocation> {
        self.record
            .allocation
            .as_ref()
            .context("bootstrap allocation missing")
    }
    pub(super) fn require_chain_control(
        &self,
        chain: &ChainConfig,
        control: &Digest,
    ) -> Result<()> {
        ensure!(
            chain.deployment.id()? == self.policy.deployment
                && chain.deployment.schedule() == self.policy.schedule,
            "origin chain deployment mismatch"
        );
        ensure!(
            zark_protocol::hex32(&chain.deployment.control_key)? == *control,
            "origin control key differs from authenticated deployment"
        );
        Ok(())
    }
    pub(super) fn capability(&self) -> Result<Digest> {
        capability_commitment(
            &self.policy.deployment,
            &self.record.context.coin,
            &self.record.capability,
        )
    }
    pub(super) fn external_transaction(&self) -> Result<Transaction> {
        let funding = self
            .record
            .funding
            .as_ref()
            .context("external funding missing")?;
        let tx: Transaction = deserialize(&decode(&funding.raw, LIMIT)?)?;
        ensure!(
            hex::encode(serialize(&tx)) == funding.raw,
            "noncanonical external funding"
        );
        check_funding(
            &tx,
            funding.vout,
            self.record.amount,
            &self.parent_script()?,
        )?;
        Ok(tx)
    }
    pub(super) fn ensure_bootstrap(&self) -> Result<BootstrapDraft> {
        let external = self.external_transaction()?;
        let funding = self.record.funding.as_ref().unwrap();
        let a = self.allocation()?;
        let path = self.directory.join("activation");
        let draft = if path.try_exists()? {
            BootstrapDraft::open(&path, &self.record.context)?
        } else {
            ensure!(
                self.record.requests.prepare.is_none(),
                "frozen activation draft is missing; refusing regeneration"
            );
            BootstrapDraft::create(
                &path,
                BootstrapParameters {
                    context: self.record.context.clone(),
                    parent: OutPoint::new(external.compute_txid(), funding.vout),
                    amount: self.record.amount,
                    fee: self.record.activation_fee,
                    parent_server: a.parent.as_slice().try_into()?,
                    active_server: a.active.as_slice().try_into()?,
                },
                &self.record.parent_user,
                &self.record.active_user,
                &self.record.capability,
            )?
        };
        let (parent, active, activation) = draft.local_inputs()?;
        ensure!(
            parent.txid == external.compute_txid().to_string()
                && parent.vout == funding.vout
                && parent.amount == self.record.amount
                && active.amount == self.record.amount - self.record.activation_fee
                && active.vout == 0
                && active.txid == activation.compute_txid().to_string(),
            "origin activation record mismatch"
        );
        let pk = FundingKey::new(point(&a.parent)?, scalar(&self.record.parent_user)?)?;
        let ak = FundingKey::new(point(&a.active)?, scalar(&self.record.active_user)?)?;
        ensure!(
            parent.key()? == pk.xonly()?
                && active.key()? == ak.xonly()?
                && draft.commitments()?.2 == self.capability()?,
            "origin activation keys changed"
        );
        Ok(draft)
    }
    pub(super) fn bootstrap_binding(&self) -> Result<BootstrapBinding> {
        let nonce = self
            .record
            .parent_nonce
            .as_ref()
            .context("parent nonce not frozen")?;
        self.ensure_bootstrap()?
            .bind_nonce(&self.record.context, nonce.as_slice().try_into()?)
    }
    pub(super) fn recovery_parameters(&self) -> Result<OriginRecoveryParameters> {
        ensure!(
            self.record.parent_authorized,
            "activation authorization not held"
        );
        let (parent, active, activation) = self.ensure_bootstrap()?.local_inputs()?;
        Ok(OriginRecoveryParameters {
            context: self.record.context.clone(),
            backing: active,
            activation_input: parent,
            activation,
            draft_server: self.allocation()?.active.as_slice().try_into()?,
            initial_capability: self.capability()?,
            schedule: self.policy.schedule,
            fee: self.record.recovery_fee,
        })
    }
}
