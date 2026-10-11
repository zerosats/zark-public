//! Accepted-owner transfer and exit creation with exact outgoing guards.
use super::persistence::operation_path;
use super::{OriginJournal, Outgoing};
use crate::chain::ChainConfig;
use crate::exit_operation::{ExitOperation, ExitOwner};
use crate::freshness::{HeadProbe, SignerClient, read_with_chain};
use crate::sender::{SenderDraft, SenderParameters};
use anyhow::{Result, ensure};
use k256::schnorr::SigningKey;
use std::fs;
use std::path::{Path, PathBuf};
use zark_protocol::address::{AddressNetwork, ReceivingAddress};
use zark_protocol::handoff::Digest;
use zark_protocol::head::Phase as HeadPhase;
use zark_protocol::proof::PinnedVerifier;

impl OriginJournal {
    /// Local resume binding only. A reserved or transferred source owner must
    /// not need a fresh Accepted head to recover its exact outgoing operation.
    pub(crate) fn require_saved_sender(
        &self,
        directory: &Path,
        recipient: &ReceivingAddress,
        sender: &SenderDraft,
    ) -> Result<()> {
        let directory = operation_path(directory)?;
        ensure!(
            matches!(&self.record.outgoing,
            Some(Outgoing::Transfer { directory: saved, recipient: to, .. })
            if *saved == directory.to_string_lossy() && *to == recipient.encode()),
            "sender metadata differs from origin outgoing reservation"
        );
        let binding = self.lineage_binding(&self.ensure_recovery()?)?;
        sender.require_origin(&self.record.context, &binding.state, recipient)?;
        ensure!(
            sender.context().deployment == binding.deployment
                && sender.context().coin == binding.coin,
            "sender source owner mismatch"
        );
        Ok(())
    }
    pub(crate) fn clear_aborted_sender(
        &mut self,
        directory: &Path,
        recipient: &ReceivingAddress,
    ) -> Result<()> {
        if self.record.outgoing.is_none() {
            return Ok(());
        }
        let directory = operation_path(directory)?;
        ensure!(
            matches!(&self.record.outgoing,
            Some(Outgoing::Transfer { directory: saved, recipient: to, .. })
            if *saved == directory.to_string_lossy() && *to == recipient.encode()),
            "aborted sender is not the current outgoing operation"
        );
        self.record.outgoing = None;
        self.persist()
    }

    pub(crate) fn require_saved_exit(
        &self,
        directory: &Path,
        destination: &Digest,
        fee: u64,
        exit: &ExitOperation,
    ) -> Result<()> {
        let directory = operation_path(directory)?;
        ensure!(
            matches!(&self.record.outgoing,
            Some(Outgoing::Exit { directory: saved, destination: to, fee: cost, .. })
            if *saved == directory.to_string_lossy() && to == destination && *cost == fee),
            "exit metadata differs from origin outgoing reservation"
        );
        let binding = self.lineage_binding(&self.ensure_recovery()?)?;
        exit.require_origin(&binding.state, destination, fee)?;
        ensure!(
            exit.context().deployment == binding.deployment && exit.context().coin == binding.coin,
            "exit source owner mismatch"
        );
        Ok(())
    }
    pub(crate) fn batch_revision(
        &self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        control: &Digest,
    ) -> Result<u64> {
        let (certificate, _) = self.verified_certificate(verifier, scratch)?;
        let probe = HeadProbe::new(
            &self.record.context,
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        let response = client.request(probe.request())?;
        Ok(probe
            .verify(
                response,
                control,
                &certificate.state,
                &self.capability()?,
                HeadPhase::Accepted,
            )?
            .revision())
    }
    /// Verify the saved ownership certificate before using its gross deposit
    /// value in a private swap agreement. No signer-visible amount is created.
    pub(crate) fn verified_deposit_amount(
        &self,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<u64> {
        self.verified_certificate(verifier, scratch)?;
        Ok(self.record.amount)
    }
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
            "origin recipient deployment mismatch"
        );
        ensure!(
            self.record.funding_broadcast,
            "external funding not broadcast"
        );
        let (certificate, _proof) = self.verified_certificate(verifier, scratch)?;
        self.require_chain_control(chain, control)?;
        let (parent, backing, _) = self.ensure_bootstrap()?.local_inputs()?;
        let capability = self.capability()?;
        let probe = HeadProbe::new(
            &self.record.context,
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        let (head, observation) = read_with_chain(
            probe,
            client,
            |probe, response| {
                probe.verify(
                    response,
                    control,
                    &certificate.state,
                    &capability,
                    HeadPhase::Accepted,
                )
            },
            || chain.observe(&backing, &parent),
        )?;
        chain.check_transfer_window(
            &observation,
            self.policy.schedule.delay_after(0)?,
            self.policy.schedule.delay_after(1)?,
        )?;
        head.require_fresh()?;
        let directory = operation_path(directory)?;
        let staging = if let Some(outgoing) = &self.record.outgoing {
            match outgoing {
                Outgoing::Transfer {
                    directory: saved,
                    staging,
                    recipient: to,
                } if *saved == directory.to_string_lossy() && *to == recipient.encode() => {
                    PathBuf::from(staging)
                }
                _ => anyhow::bail!("another origin outgoing operation is already reserved"),
            }
        } else {
            ensure!(
                fs::symlink_metadata(&directory)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "outgoing origin directory already exists"
            );
            let staging = crate::outgoing::new_staging_path(&directory)?;
            self.record.outgoing = Some(Outgoing::Transfer {
                directory: directory.to_string_lossy().into_owned(),
                staging: staging.to_string_lossy().into_owned(),
                recipient: recipient.encode(),
            });
            self.persist()?;
            staging
        };
        let activation = self.ensure_recovery()?.completed_activation()?;
        let current_state = certificate.state;
        let current_coin = certificate.coin;
        let parameters = SenderParameters {
            recovery_path: self.directory.join("own-recovery"),
            recovery_context: self.record.context.clone(),
            backing,
            activation_input: parent,
            activation,
            certificate: self.owner_certificate()?,
            start_revision: head.revision(),
            server_salt: self.allocation()?.salt,
        };
        crate::outgoing::initialize_outgoing(
            &directory,
            &staging,
            |path| {
                SenderDraft::create(
                    path,
                    parameters,
                    &self.record.capability,
                    recipient,
                    &self.policy,
                    verifier,
                    scratch,
                )
            },
            |path| {
                let sender = SenderDraft::open(path, &self.policy)?;
                sender.require_origin(&self.record.context, &current_state, recipient)?;
                ensure!(
                    sender.context().deployment == self.policy.deployment
                        && sender.context().coin == current_coin
                        && sender.context().previous_state == current_state,
                    "saved origin sender context mismatch"
                );
                Ok(sender)
            },
        )
    }

    /// The unsplit first owner can also cooperatively exit. Transfers and exits
    /// share one durable outgoing guard for this accepted state.
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
                && self.record.amount - self.record.activation_fee > fee + 330,
            "invalid origin exit destination or fee"
        );
        ensure!(
            self.record.funding_broadcast,
            "external funding not broadcast"
        );
        let (certificate, _proof) = self.verified_certificate(verifier, scratch)?;
        self.require_chain_control(chain, control)?;
        let (parent, backing, _) = self.ensure_bootstrap()?.local_inputs()?;
        let capability = self.capability()?;
        let probe = HeadProbe::new(
            &self.record.context,
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        let (head, _) = read_with_chain(
            probe,
            client,
            |probe, response| {
                probe.verify(
                    response,
                    control,
                    &certificate.state,
                    &capability,
                    HeadPhase::Accepted,
                )
            },
            || chain.observe(&backing, &parent),
        )?;
        head.require_fresh()?;
        let directory = operation_path(directory)?;
        let staging = if let Some(outgoing) = &self.record.outgoing {
            match outgoing {
                Outgoing::Exit {
                    directory: saved,
                    staging,
                    destination: to,
                    fee: cost,
                } if *saved == directory.to_string_lossy()
                    && *to == destination
                    && *cost == fee =>
                {
                    PathBuf::from(staging)
                }
                _ => anyhow::bail!("another origin outgoing operation is already reserved"),
            }
        } else {
            ensure!(
                fs::symlink_metadata(&directory)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "outgoing origin directory already exists"
            );
            let staging = crate::outgoing::new_staging_path(&directory)?;
            self.record.outgoing = Some(Outgoing::Exit {
                directory: directory.to_string_lossy().into_owned(),
                staging: staging.to_string_lossy().into_owned(),
                destination,
                fee,
            });
            self.persist()?;
            staging
        };
        let draft = self.ensure_recovery()?;
        let state = draft.own_state(&self.allocation()?.salt, self.record.policy)?;
        let current_state = certificate.state;
        let current_coin = certificate.coin;
        let owner = ExitOwner {
            head_context: self.record.context.clone(),
            head_session: self.record.session,
            backing,
            activation_input: parent,
            activation: draft.completed_activation()?,
            server: self.allocation()?.active.as_slice().try_into()?,
            state,
            server_salt: self.allocation()?.salt,
            certificate: self.owner_certificate()?,
            start_revision: head.revision(),
        };
        drop(draft);
        crate::outgoing::initialize_outgoing(
            &directory,
            &staging,
            |path| {
                ExitOperation::create(
                    path,
                    owner,
                    &self.record.active_user,
                    &self.record.capability,
                    destination,
                    fee,
                    &self.policy,
                    verifier,
                    scratch,
                )
            },
            |path| {
                let exit = ExitOperation::open(path, &self.policy)?;
                exit.require_origin(&current_state, &destination, fee)?;
                ensure!(
                    exit.context().deployment == self.policy.deployment
                        && exit.context().coin == current_coin,
                    "saved origin exit context mismatch"
                );
                Ok(exit)
            },
        )
    }
}
