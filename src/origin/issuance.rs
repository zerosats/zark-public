//! One combined deposit authorization and durable signature retrieval.
use super::{Accepted, Issued, OriginJournal, Slot, exact_fields, response_bytes};
use crate::freshness::SignerClient;
use crate::recovery::RecoveryDraft;
use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use serde_json::Value;
use std::path::Path;
use zark_protocol::certificate::IssuedOriginRecord;
use zark_protocol::deposit::DepositBinding;
use zark_protocol::lineage::{IssuanceBinding, LineageBinding};
use zark_protocol::proof::PinnedVerifier;
use zark_protocol::wire::Command;

impl OriginJournal {
    pub fn prepare_recovery(&mut self, client: &dyn SignerClient) -> Result<Vec<u8>> {
        self.require_parent_frozen()?;
        let commitments = self.ensure_recovery()?.commitments()?;
        let request = self.freeze(
            Slot::Recovery,
            Command::Prepare {
                recovery: commitments.recovery,
                blinding: commitments.blinding,
            },
        )?;
        let response = client.request(&request)?;
        exact_fields(&response, &["server_nonce", "draft_server", "server_salt"])?;
        let server = response_bytes::<64>(&response, "draft_server")?;
        let salt = response_bytes::<32>(&response, "server_salt")?;
        ensure!(
            server.as_slice() == self.allocation()?.active && salt == self.allocation()?.salt,
            "origin recovery allocation changed"
        );
        let nonce = response_bytes::<64>(&response, "server_nonce")?;
        if let Some(old) = &self.record.recovery_nonce {
            ensure!(*old == nonce, "origin recovery nonce changed");
        }
        let binding = self
            .ensure_recovery()?
            .bind_server_nonce(&self.record.context, nonce)?;
        self.record.recovery_nonce = Some(nonce.to_vec());
        self.persist()?;
        self.issuance_binding(&binding)?.encode()
    }

    /// A primitive authorization cannot enter this path; the complete origin
    /// authorization is checked before its exact signed request is saved/sent.
    pub fn issue_recovery(
        &mut self,
        proof: &[u8],
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
    ) -> Result<Transaction> {
        self.require_parent_frozen()?;
        let binding = self.deposit_binding()?;
        verifier.deposit_authorization(&binding, proof, scratch)?;
        let request = self.freeze(
            Slot::Issue,
            Command::IssueDeposit {
                statement: binding.encode()?,
                proof: proof.to_vec(),
            },
        )?;
        self.apply_issue(&client.request(&request)?, verifier, scratch)
    }
    pub fn retrieve_issued(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
    ) -> Result<Transaction> {
        self.require_issuance(verifier, scratch)?;
        let digest = self.deposit_binding()?.digest()?;
        let request = self.sign(Command::RetrieveIssued {
            binding_digest: digest,
        })?;
        self.apply_issue(&client.request(&request)?, verifier, scratch)
    }
    pub fn retry_issuance(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
    ) -> Result<Transaction> {
        self.require_issuance(verifier, scratch)?;
        let request = self.saved(
            self.record
                .requests
                .issue
                .as_ref()
                .context("origin issuance request missing")?,
        )?;
        self.apply_issue(&client.request(&request)?, verifier, scratch)
    }
    pub(super) fn apply_issue(
        &mut self,
        response: &Value,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<Transaction> {
        self.require_issuance(verifier, scratch)?;
        exact_fields(
            response,
            &[
                "issued",
                "partial",
                "activation_partial",
                "binding_digest",
                "activation_binding_digest",
                "state",
                "capability",
                "origin_signature",
                "issuance_identity",
            ],
        )?;
        ensure!(response["issued"] == true, "deposit was not issued");
        let binding = self.deposit_binding()?;
        let receipt = Issued {
            partial: response_bytes(response, "partial")?,
            binding: response_bytes(response, "binding_digest")?,
            state: response_bytes(response, "state")?,
            capability: response_bytes(response, "capability")?,
            identity: response_bytes(response, "issuance_identity")?,
        };
        let accepted = Accepted {
            activation_partial: response_bytes(response, "activation_partial")?,
            activation_binding: response_bytes(response, "activation_binding_digest")?,
            origin_signature: response_bytes::<64>(response, "origin_signature")?.to_vec(),
        };
        ensure!(
            receipt.binding == binding.digest()?
                && receipt.capability == binding.authorization.signing.next_capability
                && accepted.activation_binding == binding.bootstrap.digest()?,
            "deposit response binding mismatch"
        );
        let request = self.saved(
            self.record
                .requests
                .issue
                .as_ref()
                .context("missing deposit request")?,
        )?;
        let identity = IssuedOriginRecord::from_request(
            &request,
            &binding,
            receipt.partial,
            accepted.activation_partial,
            self.allocation()?.salt,
            receipt.state,
            accepted.origin_signature.clone(),
        )?;
        ensure!(
            identity.identity()? == receipt.identity,
            "deposit issuance identity mismatch"
        );
        // Both signatures are completed and durably saved before acknowledgement or publication.
        let mut draft = self.ensure_recovery()?;
        let recovery = draft.finish(
            &self.record.context,
            binding.authorization.signing.server_nonce,
            receipt.partial,
        )?;
        let activation = self.ensure_bootstrap()?.finish(
            &self.record.context,
            binding.bootstrap.parent_nonce,
            accepted.activation_partial,
        )?;
        draft.attach_completed_activation(&activation)?;
        ensure!(
            self.lineage_binding(&draft)?.state == receipt.state,
            "deposit state mismatch"
        );
        drop(draft);
        if let Some(old) = &self.record.issued {
            ensure!(
                old.partial == receipt.partial
                    && old.binding == receipt.binding
                    && old.state == receipt.state
                    && old.capability == receipt.capability
                    && old.identity == receipt.identity,
                "deposit issuance changed"
            );
        }
        if let Some(old) = &self.record.accepted {
            ensure!(
                old.activation_partial == accepted.activation_partial
                    && old.activation_binding == accepted.activation_binding
                    && old.origin_signature == accepted.origin_signature,
                "deposit activation changed"
            );
        }
        self.record.issued = Some(receipt);
        self.record.accepted = Some(accepted);
        self.persist()?;
        Ok(recovery)
    }

    pub(super) fn ensure_recovery(&self) -> Result<RecoveryDraft> {
        let parameters = self.recovery_parameters()?;
        let path = self.directory.join("own-recovery");
        let draft = if path.try_exists()? {
            RecoveryDraft::open(&path, &self.record.context)?
        } else {
            ensure!(
                self.record.requests.recovery.is_none(),
                "frozen initial recovery is missing; refusing regeneration"
            );
            RecoveryDraft::create_bootstrap_origin(
                &path,
                self.recovery_parameters()?,
                &self.record.active_user,
                &self.record.payout,
            )?
        };
        draft.require_bootstrap_origin_parameters(
            &parameters,
            &self.record.active_user,
            &self.record.payout,
        )?;
        Ok(draft)
    }
    pub(super) fn issuance_binding(
        &self,
        signing: &zark_protocol::handoff::SigningBinding,
    ) -> Result<IssuanceBinding> {
        Ok(IssuanceBinding {
            signing: zark_protocol::handoff::SigningBinding::decode(&signing.encode()?)?,
            policy: self.record.policy,
            origin_key: self.policy.origin_key,
            role_hashes: self.policy.role_hashes,
        })
    }
    pub(super) fn deposit_binding(&self) -> Result<DepositBinding> {
        self.deposit_binding_with_recovery(&self.ensure_recovery()?)
    }
    pub(super) fn deposit_binding_with_recovery(
        &self,
        draft: &RecoveryDraft,
    ) -> Result<DepositBinding> {
        Ok(DepositBinding {
            authorization: self.issuance_binding(&draft.signing_binding()?)?,
            bootstrap: self.bootstrap_binding()?,
        })
    }
    pub(super) fn lineage_binding(&self, draft: &RecoveryDraft) -> Result<LineageBinding> {
        let state = draft.own_state(&self.allocation()?.salt, self.record.policy)?;
        Ok(LineageBinding {
            deployment: state.deployment,
            coin: state.coin,
            funding: state.funding,
            state: state.commitment()?,
            policy: state.policy,
            origin_key: self.policy.origin_key,
            role_hashes: self.policy.role_hashes,
        })
    }
    pub(super) fn require_parent_frozen(&self) -> Result<()> {
        ensure!(self.record.parent_authorized, "activation draft not frozen");
        let saved = self
            .record
            .requests
            .authorize
            .as_ref()
            .context("activation freeze missing")?;
        let Command::BootstrapFreeze { statement } = self.saved(saved)?.command else {
            anyhow::bail!("wrong activation freeze command")
        };
        ensure!(
            statement == self.bootstrap_binding()?.encode()?,
            "activation draft changed"
        );
        Ok(())
    }
    pub(super) fn require_issuance(
        &self,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<Vec<u8>> {
        self.require_parent_frozen()?;
        let saved = self
            .record
            .requests
            .issue
            .as_ref()
            .context("deposit issuance request missing")?;
        let Command::IssueDeposit { statement, proof } = self.saved(saved)?.command else {
            anyhow::bail!("wrong origin issuance command")
        };
        let binding = self.deposit_binding()?;
        ensure!(
            statement == binding.encode()?,
            "deposit authorization changed"
        );
        verifier.deposit_authorization(&binding, &proof, scratch)?;
        Ok(proof)
    }
}
