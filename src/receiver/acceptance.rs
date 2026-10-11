//! Save the recovery and ownership certificate before acknowledgement.
use super::persistence::decode_hex;
use super::response::{checked_recovery_request, exact_response_fields, response_bytes};
use super::{CertificateRecord, ReceiverJournal};
use crate::chain::ChainConfig;
use crate::freshness::SignerClient;
use anyhow::{Result, ensure};
use std::path::Path;
use zark_protocol::certificate::{IssuedTransferRecord, OwnerCertificate};
use zark_protocol::handoff::Digest;
use zark_protocol::lineage::LineageBinding;
use zark_protocol::proof::PinnedVerifier;
use zark_protocol::session::Purpose;
use zark_protocol::wire::{Command, MAX_BODY, Request};

impl ReceiverJournal {
    /// Saves the actual current-state certificate after recovery and composed
    /// issuance verification. This still does NOT acknowledge accepted ownership:
    /// a fresh signed signer head and fresh live-chain observation are required.
    pub fn freeze_certificate(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<LineageBinding> {
        self.issuance_request(verifier, scratch)?;
        let binding = self.lineage_binding(&self.open_recovery()?)?;
        let certificate = self.build_certificate()?;
        ensure!(
            certificate.verify(verifier, scratch)?.encode()? == binding.encode()?,
            "certificate differs from completed recovery"
        );
        let encoded = hex::encode(&*certificate.encode_private()?);
        if let Some(saved) = &self.recovery_record()?.certificate {
            ensure!(
                saved.encoded == encoded,
                "recipient certificate is already frozen"
            );
        } else {
            self.recovery_record_mut()?.certificate = Some(CertificateRecord { encoded });
            self.persist()?;
        }
        Ok(binding)
    }

    /// Recovery use remains possible without signer or proof backend. This only
    /// exports the already signed Bitcoin transactions and its own payout key.
    pub fn export_recovery(&self, path: &Path) -> Result<()> {
        self.open_recovery()?.export_portable(path)
    }

    /// Freezes one acceptance request only after the current certificate and
    /// own complete recovery exist. A fresh signed head and live chain are
    /// checked both before server acceptance and before recording local receipt.
    pub fn accept(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
        control: &Digest,
    ) -> Result<LineageBinding> {
        let (binding, _) = self.verified_certificate(verifier, scratch)?;
        self.check_fresh_current(client, chain, control, &binding, true)?;
        let command = self.acknowledgement_command()?;
        let body = command.body()?;
        let saved = if let Some(saved) = &self.recovery_record()?.acceptance {
            checked_recovery_request(
                &self.record.context,
                Purpose::TransferAcknowledgement,
                saved,
                &body,
            )?
        } else {
            let saved = self.sign_body(Purpose::TransferAcknowledgement, &body)?;
            self.recovery_record_mut()?.acceptance = Some(saved);
            self.persist()?;
            checked_recovery_request(
                &self.record.context,
                Purpose::TransferAcknowledgement,
                self.recovery_record()?
                    .acceptance
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("acceptance not saved"))?,
                &body,
            )?
        };
        let request = Request::from_body(
            self.record.context.clone(),
            saved.body(),
            *saved.signature(),
        )?;
        let response = client.request(&request)?;
        exact_response_fields(&response, &["accepted", "state"])?;
        ensure!(
            response["accepted"] == true
                && response_bytes::<32>(&response, "state")? == binding.state,
            "signer acceptance differs from current certificate"
        );
        self.check_fresh_current(client, chain, control, &binding, false)?;
        self.recovery_record_mut()?.accepted = true;
        self.persist()?;
        Ok(binding)
    }

    pub(super) fn verified_certificate(
        &self,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<(LineageBinding, OwnerCertificate)> {
        self.issuance_request(verifier, scratch)?;
        let certificate = self
            .recovery_record()?
            .certificate
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("current recipient certificate is not saved"))?;
        let binding = self.lineage_binding(&self.open_recovery()?)?;
        ensure!(
            certificate.encoded == hex::encode(&*self.build_certificate()?.encode_private()?),
            "recipient certificate context mismatch"
        );
        let certificate =
            OwnerCertificate::decode_private(&decode_hex(&certificate.encoded, 40_000)?)?;
        ensure!(
            certificate.verify(verifier, scratch)?.encode()? == binding.encode()?,
            "saved composite certificate state"
        );
        Ok((binding, certificate))
    }

    pub(super) fn build_certificate(&self) -> Result<OwnerCertificate> {
        let draft = self.open_recovery()?;
        let (signing, partial) = draft.completion_binding()?;
        // Native completion is independently verified before its certificate is saved.
        draft.completed_transaction()?;
        let saved = self
            .recovery_record()?
            .issuance
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("certificate before issuance"))?;
        let proof = self.decode_issuance(saved, &signing)?;
        Ok(OwnerCertificate::TransferIssued {
            authorization: self.issuance_binding(&signing)?.encode()?,
            proof,
            partial,
            server_salt: self.server_salt()?,
        })
    }

    pub(super) fn acknowledgement_command(&self) -> Result<Command> {
        let draft = self.open_recovery()?;
        let (signing, partial) = draft.completion_binding()?;
        let saved = self
            .recovery_record()?
            .issuance
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("acknowledgement before issuance"))?;
        self.decode_issuance(saved, &signing)?;
        let request = Request::from_body(
            self.record.context.clone(),
            &decode_hex(&saved.body, MAX_BODY)?,
            decode_hex(&saved.signature, 64)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("issuance signature length"))?,
        )?;
        let state = self.lineage_binding(&draft)?.state;
        let issued = IssuedTransferRecord::from_request(
            &request,
            &self.issuance_binding(&signing)?,
            partial,
            self.server_salt()?,
            state,
        )?;
        Ok(Command::AcknowledgeTransfer {
            state,
            issuance_identity: issued.identity()?,
        })
    }
}
