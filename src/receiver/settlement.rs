//! Signer exchange and recovery retrieval, including batch readiness.
use super::freshness::check_observed_use;
use super::response::{exact_response_fields, response_bytes};
use super::{CurrentUse, ReceiverJournal};
use crate::chain::ChainConfig;
use crate::freshness::SignerClient;
use anyhow::{Result, ensure};
use k256::schnorr::SigningKey;
use std::path::Path;
use zark_protocol::handoff::{Digest, SigningBinding};
use zark_protocol::proof::PinnedVerifier;
use zark_protocol::wire::{Command, Request};

impl ReceiverJournal {
    /// Complete receiver-side claim using exactly the shared request format.
    /// The client must authenticate the endpoint before transmitting delta.
    pub fn claim(&mut self, client: &dyn SignerClient) -> Result<Digest> {
        let saved = self.freeze_claim_request()?;
        let request = Request::from_body(
            self.record.context.clone(),
            saved.body(),
            *saved.signature(),
        )?;
        self.freeze_draft(&client.request(&request)?)
    }

    pub fn prepare_with_signer(
        &mut self,
        fee: u64,
        client: &dyn SignerClient,
    ) -> Result<SigningBinding> {
        let saved = self.prepare_recovery(fee)?;
        let request = Request::from_body(
            self.record.context.clone(),
            saved.body(),
            *saved.signature(),
        )?;
        self.bind_recovery_nonce(&client.request(&request)?)
    }

    /// Native completion is durably saved even if a server's claimed state is
    /// malformed; only an exact matching authenticated response succeeds.
    pub fn apply_issued_response(
        &mut self,
        response: &serde_json::Value,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<bitcoin::Transaction> {
        // A valid response scalar is already enough to recover our funds.
        // Preserve that recovery before rejecting any untrusted reply metadata.
        let transaction = self.complete_recovery(
            response_bytes::<32>(response, "partial")?,
            verifier,
            scratch,
        )?;
        exact_response_fields(
            response,
            &["issued", "partial", "binding_digest", "state", "capability"],
        )?;
        ensure!(response["issued"] == true, "signer did not issue recovery");
        let binding = self.open_recovery()?.signing_binding()?;
        ensure!(
            response_bytes::<32>(response, "binding_digest")? == binding.digest()?
                && response_bytes::<32>(response, "capability")? == binding.next_capability,
            "issued response context mismatch"
        );
        ensure!(
            response_bytes::<32>(response, "state")?
                == self.lineage_binding(&self.open_recovery()?)?.state,
            "issued response state differs from own recovery"
        );
        Ok(transaction)
    }

    pub fn issue(
        &mut self,
        proof: &[u8],
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
    ) -> Result<bitcoin::Transaction> {
        // Live backing is read while the proof is verified and the request is
        // frozen; the request is sent only after both succeed.
        let live = self.live_backing(chain)?;
        // Acquire once before chain helpers can fork. CLOEXEC does not close a
        // draft descriptor during fork: dropping/reopening it while a child is
        // still before exec can contend with our own inherited flock. Retain
        // this checked draft until both sides have joined; never unlock a
        // shared descriptor or relax the exact-retry checks.
        let draft = self.open_recovery()?;
        let (saved, observed) = zark_protocol::local::join_with_helper(
            || self.freeze_issuance_with_draft(&draft, proof, verifier, scratch, None),
            || live.observe(chain),
        )?;
        drop(draft);
        let saved = saved?;
        check_observed_use(
            chain,
            &observed?,
            live.previous,
            live.next,
            CurrentUse::IncomingTransfer,
        )?;
        let request = Request::from_body(
            self.record.context.clone(),
            saved.body(),
            *saved.signature(),
        )?;
        self.apply_issued_response(&client.request(&request)?, verifier, scratch)
    }
    pub(crate) fn ready_batch(
        &mut self,
        proof: Option<&[u8]>,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
    ) -> Result<bool> {
        ensure!(
            self.record.batch.is_some(),
            "receiver has no batch manifest"
        );
        let saved = if let Some(proof) = proof {
            self.freeze_issuance_request(proof, verifier, scratch, Some(chain))?
        } else {
            self.issuance_request(verifier, scratch)?
        };
        self.check_live_backing(chain)?;
        let request = Request::from_body(
            self.record.context.clone(),
            saved.body(),
            *saved.signature(),
        )?;
        let response = client.request(&request)?;
        if response["pending"] == true {
            ensure!(
                response["batch"] == serde_json::json!(self.record.batch.as_ref().unwrap().id),
                "pending batch identity mismatch"
            );
            Ok(false)
        } else {
            self.apply_issued_response(&response, verifier, scratch)?;
            Ok(true)
        }
    }

    /// Local progress hints only. Neither a saved request nor a completed
    /// recovery establishes accepted ownership or a fresh signer head.
    pub fn has_issuance_request(&self) -> bool {
        self.recovery_record()
            .is_ok_and(|record| record.issuance.is_some())
    }

    pub fn has_completed_recovery(&self) -> Result<bool> {
        if !self.has_issuance_request() {
            return Ok(false);
        }
        let draft = self.open_recovery()?;
        Ok(draft.completed_transaction().is_ok())
    }

    /// Recover only the response for an already frozen, verified issuance. No
    /// new key/nonce/operation is made and an old-head chain gate is deliberately
    /// absent: release may have succeeded before the connection was lost.
    pub fn retrieve_issued(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
    ) -> Result<bitcoin::Transaction> {
        self.issuance_request(verifier, scratch)?;
        let binding = self.open_recovery()?.signing_binding()?;
        let request = Request::sign(
            self.record.context.clone(),
            Command::RetrieveIssued {
                binding_digest: binding.digest()?,
            },
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        self.apply_issued_response(&client.request(&request)?, verifier, scratch)
    }
}
