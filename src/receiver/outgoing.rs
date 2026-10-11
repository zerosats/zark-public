//! Accepted-owner transfer and exit creation with exact outgoing guards.
use super::persistence::canonical_new_operation_path;
use super::{CurrentUse, OutgoingOperation, ReceiverJournal};
use crate::chain::ChainConfig;
use crate::exit_operation::{ExitOperation, ExitOwner};
use crate::freshness::SignerClient;
use crate::outgoing::{initialize_outgoing, new_staging_path};
use crate::sender::{SenderDraft, SenderParameters};
use anyhow::{Context, Result, ensure};
use std::fs;
use std::path::{Path, PathBuf};
use zark_protocol::address::{AddressNetwork, ReceivingAddress};
use zark_protocol::certificate::OwnerCertificate;
use zark_protocol::handoff::{Digest, RecoveryDelay, policy_commitment};
use zark_protocol::proof::PinnedVerifier;

impl ReceiverJournal {
    /// Bind a reopened outgoing child to local accepted ownership and its saved
    /// guard without requiring the server head to remain Accepted after reserve.
    pub(crate) fn require_saved_sender(
        &self,
        directory: &Path,
        recipient: &ReceivingAddress,
        sender: &SenderDraft,
    ) -> Result<()> {
        let directory = canonical_new_operation_path(directory)?;
        ensure!(
            matches!(&self.recovery_record()?.outgoing,
            Some(OutgoingOperation::Transfer { directory: saved, recipient: to, .. })
            if *saved == directory.to_string_lossy() && *to == recipient.encode()),
            "sender metadata differs from receiver outgoing reservation"
        );
        let binding = self.lineage_binding(&self.open_recovery()?)?;
        sender.require_origin(&self.record.context, &binding.state, recipient)?;
        ensure!(
            sender.context().deployment == binding.deployment
                && sender.context().coin == binding.coin,
            "sender source receiver mismatch"
        );
        Ok(())
    }
    pub(crate) fn clear_aborted_sender(
        &mut self,
        directory: &Path,
        recipient: &ReceivingAddress,
    ) -> Result<()> {
        if self.recovery_record()?.outgoing.is_none() {
            return Ok(());
        }
        let directory = canonical_new_operation_path(directory)?;
        ensure!(
            matches!(&self.recovery_record()?.outgoing,
            Some(OutgoingOperation::Transfer { directory: saved, recipient: to, .. })
            if *saved == directory.to_string_lossy() && *to == recipient.encode()),
            "aborted sender is not the current outgoing operation"
        );
        self.recovery_record_mut()?.outgoing = None;
        self.persist()
    }

    pub(crate) fn require_saved_exit(
        &self,
        directory: &Path,
        destination: &Digest,
        fee: u64,
        exit: &ExitOperation,
    ) -> Result<()> {
        let directory = canonical_new_operation_path(directory)?;
        ensure!(
            matches!(&self.recovery_record()?.outgoing,
            Some(OutgoingOperation::Exit { directory: saved, destination: to, fee: cost, .. })
            if *saved == directory.to_string_lossy() && to == destination && *cost == fee),
            "exit metadata differs from receiver outgoing reservation"
        );
        let binding = self.lineage_binding(&self.open_recovery()?)?;
        exit.require_origin(&binding.state, destination, fee)?;
        ensure!(
            exit.context().deployment == binding.deployment && exit.context().coin == binding.coin,
            "exit source receiver mismatch"
        );
        Ok(())
    }

    /// Narrow current-owner transition. Reopening a saved `accepted` label is
    /// insufficient: the actual certificate, fresh signed head and live Bitcoin
    /// context are checked again before any current private material is consumed.
    #[allow(clippy::too_many_arguments)] // Explicit current-owner verification dependencies.
    pub fn create_sender(
        &mut self,
        directory: &Path,
        recipient: &ReceivingAddress,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
        control: &Digest,
    ) -> Result<SenderDraft> {
        ensure!(
            recipient.network() == AddressNetwork::Test
                && *recipient.deployment() == self.policy.deployment,
            "sender recipient deployment mismatch"
        );
        ensure!(
            self.recovery_record()?.accepted,
            "recipient ownership was not accepted"
        );
        let (certificate, proof) = self.verified_certificate(verifier, scratch)?;
        let current_delay = self.recovery_delays()?.1;
        let next_delay = RecoveryDelay::from_sequence(
            current_delay
                .blocks()
                .checked_sub(self.policy.schedule.gap)
                .context("recovery delay budget exhausted")?,
        )?;
        self.policy
            .schedule
            .check_transition(current_delay, next_delay)?;
        let head = self.check_fresh_current(client, chain, control, &certificate, false)?;
        let directory = canonical_new_operation_path(directory)?;
        let staging = if let Some(outgoing) = &self.recovery_record()?.outgoing {
            ensure!(
                matches!(outgoing, OutgoingOperation::Transfer { directory:saved, recipient:saved_recipient, .. }
                if *saved == directory.to_string_lossy() && *saved_recipient == recipient.encode()),
                "another outgoing operation is already reserved"
            );
            match outgoing {
                OutgoingOperation::Transfer { staging, .. } => PathBuf::from(staging),
                _ => unreachable!(),
            }
        } else {
            ensure!(
                fs::symlink_metadata(&directory)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "outgoing directory already exists"
            );
            let staging = new_staging_path(&directory)?;
            self.recovery_record_mut()?.outgoing = Some(OutgoingOperation::Transfer {
                directory: directory.to_string_lossy().into_owned(),
                staging: staging.to_string_lossy().into_owned(),
                recipient: recipient.encode(),
            });
            self.persist()?;
            staging
        };
        initialize_outgoing(
            &directory,
            &staging,
            |attempt| {
                let native = self.native_offer()?;
                let parameters = SenderParameters {
                    recovery_path: self.directory.join("own-recovery"),
                    recovery_context: self.record.context.clone(),
                    backing: native.common_backing().clone(),
                    activation_input: native.common_activation_input().clone(),
                    activation: native.common_activation().clone(),
                    certificate: OwnerCertificate::decode_private(&proof.encode_private()?)?,
                    // Reserve is rejected unless this is still the signer's
                    // current revision; this constructor must stay local.
                    start_revision: head.revision(),
                    server_salt: self.server_salt()?,
                };
                SenderDraft::create(
                    attempt,
                    parameters,
                    &self.record.capability,
                    recipient,
                    &self.policy,
                    verifier,
                    scratch,
                )
            },
            |published| {
                let sender = SenderDraft::open(published, &self.policy)?;
                sender.require_origin(&self.record.context, &certificate.state, recipient)?;
                ensure!(
                    sender.context().deployment == certificate.deployment
                        && sender.context().coin == certificate.coin
                        && sender.context().previous_state == certificate.state,
                    "saved sender operation differs from current ownership"
                );
                Ok(sender)
            },
        )
    }

    /// Cooperatively spend only this recipient's accepted current state. The
    /// durable outgoing guard is shared with transfers, so concurrent callers
    /// cannot create a different transfer or exit from this journal.
    #[allow(clippy::too_many_arguments)] // Explicit current-owner verification dependencies.
    pub fn create_exit(
        &mut self,
        directory: &Path,
        destination: Digest,
        fee: u64,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
        control: &Digest,
    ) -> Result<ExitOperation> {
        k256::schnorr::VerifyingKey::from_bytes(&destination)?;
        ensure!(
            destination != [0; 32]
                && (1..=10_000).contains(&fee)
                && self.native_offer()?.common_backing().amount > fee + 330,
            "invalid cooperative exit destination or fee"
        );
        ensure!(
            self.recovery_record()?.accepted,
            "recipient ownership was not accepted"
        );
        let (certificate, proof) = self.verified_certificate(verifier, scratch)?;
        let head = self.check_fresh_current_for(
            client,
            chain,
            control,
            &certificate,
            false,
            CurrentUse::CooperativeExit,
        )?;
        let directory = canonical_new_operation_path(directory)?;
        let staging = if let Some(outgoing) = &self.recovery_record()?.outgoing {
            ensure!(
                matches!(outgoing, OutgoingOperation::Exit {
                directory:saved, destination:saved_destination, fee:saved_fee, .. }
                if *saved == directory.to_string_lossy() && *saved_destination == destination && *saved_fee == fee),
                "another outgoing operation is already reserved"
            );
            match outgoing {
                OutgoingOperation::Exit { staging, .. } => PathBuf::from(staging),
                _ => unreachable!(),
            }
        } else {
            ensure!(
                fs::symlink_metadata(&directory)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "outgoing directory already exists"
            );
            let staging = new_staging_path(&directory)?;
            self.recovery_record_mut()?.outgoing = Some(OutgoingOperation::Exit {
                directory: directory.to_string_lossy().into_owned(),
                staging: staging.to_string_lossy().into_owned(),
                destination,
                fee,
            });
            self.persist()?;
            staging
        };
        initialize_outgoing(
            &directory,
            &staging,
            |attempt| {
                let native = self.native_offer()?;
                let parameters = self.recovery_parameters()?;
                let state = self.open_recovery()?.own_state(
                    &self.server_salt()?,
                    policy_commitment(self.policy.schedule)?,
                )?;
                let owner = ExitOwner {
                    head_context: self.record.context.clone(),
                    head_session: self.record.session,
                    backing: native.common_backing().clone(),
                    activation_input: native.common_activation_input().clone(),
                    activation: native.common_activation().clone(),
                    server: parameters.draft_server,
                    state,
                    server_salt: self.server_salt()?,
                    certificate: OwnerCertificate::decode_private(&proof.encode_private()?)?,
                    start_revision: head.revision(),
                };
                ExitOperation::create(
                    attempt,
                    owner,
                    &self.record.user,
                    &self.record.capability,
                    destination,
                    fee,
                    &self.policy,
                    verifier,
                    scratch,
                )
            },
            |published| {
                let exit = ExitOperation::open(published, &self.policy)?;
                exit.require_origin(&certificate.state, &destination, fee)?;
                ensure!(
                    exit.context().deployment == certificate.deployment
                        && exit.context().coin == certificate.coin,
                    "saved exit operation differs from current ownership"
                );
                Ok(exit)
            },
        )
    }
}
