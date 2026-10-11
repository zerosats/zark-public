//! Verify and save ownership before acceptance and funding broadcast.
use super::{Certificate, OriginJournal, Slot, decode, exact_fields, response_bytes};
use crate::chain::ChainConfig;
use crate::freshness::{HeadProbe, SignerClient};
use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use k256::schnorr::SigningKey;
use std::path::Path;
use zark_protocol::certificate::OwnerCertificate;
use zark_protocol::handoff::Digest;
use zark_protocol::head::Phase as HeadPhase;
use zark_protocol::lineage::LineageBinding;
use zark_protocol::proof::{PROOF_BYTES, PinnedVerifier};
use zark_protocol::wire::Command;
use zark_protocol::{point, scalar};

impl OriginJournal {
    /// Acknowledge only the exact issued certificate after both signatures are durable.
    pub fn accept_initial_recovery(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
    ) -> Result<Transaction> {
        self.require_issuance(verifier, scratch)?;
        self.require_attached()?;
        self.owner_certificate()?.verify(verifier, scratch)?;
        let issued = self
            .record
            .issued
            .as_ref()
            .context("deposit issuance missing")?;
        let command = Command::AcceptOrigin {
            state: issued.state,
            issuance_identity: issued.identity,
        };
        let request = self.freeze(Slot::Accept, command)?;
        let response = client.request(&request)?;
        exact_fields(&response, &["accepted", "state"])?;
        ensure!(
            response["accepted"] == true
                && response_bytes::<32>(&response, "state")?
                    == self.record.issued.as_ref().unwrap().state,
            "deposit acknowledgement mismatch"
        );
        self.record.acknowledged = true;
        self.persist()?;
        self.ensure_bootstrap()?.completed_activation()
    }

    pub fn freeze_certificate(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<LineageBinding> {
        ensure!(self.record.acknowledged, "deposit not acknowledged");
        self.require_attached()?;
        let certificate = self.owner_certificate()?;
        let binding = certificate.verify(verifier, scratch)?;
        let proof = self.require_issuance(verifier, scratch)?;
        let saved = Certificate {
            statement: hex::encode(binding.encode()?),
            proof: hex::encode(proof),
        };
        if let Some(old) = &self.record.certificate {
            ensure!(
                old.statement == saved.statement && old.proof == saved.proof,
                "origin certificate changed"
            );
        } else {
            self.record.certificate = Some(saved);
            self.persist()?;
        }
        Ok(binding)
    }

    pub(super) fn owner_certificate(&self) -> Result<OwnerCertificate> {
        let request = self.saved(
            self.record
                .requests
                .issue
                .as_ref()
                .context("deposit request missing")?,
        )?;
        let Command::IssueDeposit { statement, proof } = request.command else {
            anyhow::bail!("wrong origin issuance command")
        };
        let issued = self
            .record
            .issued
            .as_ref()
            .context("deposit issuance missing")?;
        let accepted = self
            .record
            .accepted
            .as_ref()
            .context("activation response missing")?;
        Ok(OwnerCertificate::OriginIssued {
            authorization: statement,
            proof,
            partial: issued.partial,
            activation_partial: accepted.activation_partial,
            server_salt: self.allocation()?.salt,
            origin_signature: accepted.origin_signature.clone(),
        })
    }

    /// Sole automated external-deposit publication path. The live signer head
    /// is checked after the durable Bitcoin signatures and base proof, and the
    /// configured Bitcoin backend must validate exact network and transaction.
    pub fn broadcast_funding(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
        control: &Digest,
    ) -> Result<bitcoin::Txid> {
        let (binding, _) = self.verified_certificate(verifier, scratch)?;
        self.require_chain_control(chain, control)?;
        let probe = HeadProbe::new(
            &self.record.context,
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        let response = client.request(probe.request())?;
        let head = probe.verify(
            response,
            control,
            &binding.state,
            &self.capability()?,
            HeadPhase::Accepted,
        )?;
        let transaction = self.external_transaction()?;
        head.require_fresh()?;
        let txid = chain.publish(&transaction)?;
        ensure!(
            txid == transaction.compute_txid(),
            "published external transaction mismatch"
        );
        self.record.funding_broadcast = true;
        self.persist()?;
        Ok(txid)
    }
    pub fn export_recovery(&self, path: &Path) -> Result<()> {
        self.require_attached()?;
        self.ensure_recovery()?.export_portable(path)
    }
    pub(super) fn require_attached(&self) -> Result<()> {
        let receipt = self
            .record
            .accepted
            .as_ref()
            .context("parent release receipt missing")?;
        let draft = self.ensure_recovery()?;
        let lineage = self.lineage_binding(&draft)?;
        lineage.verify_origin_attestation(&receipt.origin_signature.as_slice().try_into()?)?;
        let recovery = draft.completed_transaction()?;
        let activation = draft.completed_activation()?;
        ensure!(
            !recovery.input[0].witness.is_empty()
                && activation == self.ensure_bootstrap()?.completed_activation()?,
            "origin signatures not attached"
        );
        let binding = self.bootstrap_binding()?;
        ensure!(
            receipt.activation_binding == binding.digest()?,
            "parent receipt digest changed"
        );
        ensure!(
            k256::ProjectivePoint::GENERATOR * scalar(&receipt.activation_partial)?
                == point(&binding.parent_nonce)?
                    + point(&binding.parent_server)? * scalar(&binding.blinded_challenge)?,
            "cached activation partial changed"
        );
        Ok(())
    }
    pub(super) fn verified_certificate(
        &self,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<(LineageBinding, Vec<u8>)> {
        ensure!(self.record.acknowledged, "deposit not acknowledged");
        self.require_issuance(verifier, scratch)?;
        self.require_attached()?;
        let certificate = self
            .record
            .certificate
            .as_ref()
            .context("initial certificate not durable")?;
        let binding = self.lineage_binding(&self.ensure_recovery()?)?;
        ensure!(
            certificate.statement == hex::encode(binding.encode()?),
            "origin certificate state mismatch"
        );
        let proof = decode(&certificate.proof, PROOF_BYTES)?;
        ensure!(
            self.owner_certificate()?
                .verify(verifier, scratch)?
                .encode()?
                == binding.encode()?,
            "origin certificate binding mismatch"
        );
        Ok((binding, proof))
    }
}
