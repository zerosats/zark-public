//! Validate reopened ownership, recovery and immutable offer state.
use super::{
    SenderDraft, cached_cancellation, cached_completion, canonical_any, validate_offer_cache,
    validate_session,
};
use crate::chain::{ChainConfig, LiveBacking};
use crate::common;
use crate::recovery::RecoveryDraft;
use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use std::path::Path;
use zark_protocol::address::{AddressNetwork, ReceivingAddress};
use zark_protocol::certificate::{OwnerCertificate, PredecessorKind};
use zark_protocol::handoff::{
    Digest, RecoveryDelay, TransferContext, capability_commitment, mask_commitment,
    recipient_claim_commitment,
};
use zark_protocol::lineage::LineageBinding;
use zark_protocol::proof::{PinnedVerifier, Relation};
use zark_protocol::wire::{Command, Request};

impl SenderDraft {
    pub(crate) fn require_origin(
        &self,
        recovery_context: &TransferContext,
        state: &Digest,
        recipient: &ReceivingAddress,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            &self.record.recovery_context == recovery_context
                && self.record.context.previous_state == *state
                && self.recipient()?.encode() == recipient.encode(),
            "saved outgoing transfer belongs to different owner or recipient"
        );
        Ok(())
    }
    pub(super) fn recovery(&self) -> Result<RecoveryDraft> {
        RecoveryDraft::open(&self.record.recovery_path, &self.record.recovery_context)
    }
    pub(super) fn current(&self) -> Result<LineageBinding> {
        self.certificate()?.lineage_binding()
    }
    pub(super) fn certificate(&self) -> Result<OwnerCertificate> {
        OwnerCertificate::decode_private(&canonical_any(&self.record.certificate)?)
    }
    pub(super) fn recipient(&self) -> Result<ReceivingAddress> {
        ReceivingAddress::decode(
            &self.record.recipient,
            AddressNetwork::Test,
            &self.policy.deployment,
        )
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.record.schema == "zark-sender-operation" && self.record.version == 3,
            "sender record version"
        );
        ensure!(
            !self.record.aborted || self.record.reservation.is_none(),
            "aborted sender retained reservation"
        );
        let cert = self.current()?;
        self.policy.require(
            &cert.deployment,
            &cert.policy,
            &cert.origin_key,
            &cert.role_hashes,
        )?;
        let ctx = &self.record.context;
        ctx.encode()?;
        ensure!(
            ctx.deployment == cert.deployment
                && ctx.coin == cert.coin
                && ctx.previous_state == cert.state,
            "sender current certificate context"
        );
        validate_session(&self.record.session, ctx)?;
        if let Some(manifest) = &self.record.batch {
            manifest.index(ctx, true)?;
        }
        if let Some(saved) = &self.record.cancellation {
            ensure!(
                self.record.batch.is_none(),
                "ordinary cancellation in batch journal"
            );
            cached_cancellation(ctx, saved)?;
        }
        let recipient = self.recipient()?;
        ensure!(
            recipient.network() == AddressNetwork::Test
                && *recipient.deployment() == cert.deployment
                && ctx.recipient_claim
                    == recipient_claim_commitment(
                        &cert.deployment,
                        &cert.coin,
                        &ctx.operation,
                        &recipient.claim_key()[1..].try_into()?,
                        &self.record.claim_salt
                    )?,
            "sender recipient changed"
        );
        let activation: Transaction = deserialize(&canonical_any(&self.record.activation)?)?;
        ensure!(
            common::validate(
                &cert.deployment,
                &cert.coin,
                &self.record.backing,
                &self.record.activation_input,
                &activation
            )?
            .commitment()?
                == cert.funding,
            "sender common backing changed"
        );
        let recovery = self.recovery()?;
        let state = recovery.own_state(&self.record.server_salt, cert.policy)?;
        ensure!(
            state.commitment()? == cert.state
                && state.funding == cert.funding
                && state.capability
                    == capability_commitment(
                        &cert.deployment,
                        &cert.coin,
                        &self.record.capability
                    )?,
            "sender own opening differs from certificate"
        );
        let tx = recovery.completed_transaction()?;
        self.next_delay(RecoveryDelay::from_sequence(
            tx.input[0].sequence.to_consensus_u32(),
        )?)?;
        if let Some(wire) = &self.record.reservation {
            let r = Request::decode(&canonical_any(wire)?)?;
            ensure!(
                r.context == *ctx
                    && match (&self.record.batch, &r.command) {
                        (None, Command::Reserve { .. }) => true,
                        (Some(expected), Command::BatchReserve { manifest, .. }) =>
                            expected == manifest,
                        _ => false,
                    },
                "sender reservation cache mismatch"
            );
            let owner_authorization = match &r.command {
                Command::Reserve {
                    owner_authorization,
                }
                | Command::BatchReserve {
                    owner_authorization,
                    ..
                } => owner_authorization,
                _ => anyhow::bail!("sender reservation cache role"),
            };
            owner_authorization.verify_reservation(ctx, &state.capability)?;
        }
        if let Some(mask) = &self.record.mask {
            ensure!(self.record.reservation.is_some(), "mask before reservation");
            mask_commitment(&ctx.intent(), &mask.mask, &mask.salt)?;
            ensure!(
                recovery.masked_user(&mask.mask)? == mask.masked,
                "masked owner changed"
            );
        }
        if let Some(wire) = &self.record.handover {
            ensure!(self.record.mask.is_some(), "handover before mask");
            let r = Request::decode(&canonical_any(wire)?)?;
            ensure!(r.context == *ctx, "sender handover cache context");
            match r.command {
                Command::Handover {
                    predecessor,
                    statement,
                    ..
                } => ensure!(
                    predecessor == self.certificate()?.kind()
                        && statement == self.handover_binding_unchecked(&recovery)?.encode()?,
                    "sender handover cache changed"
                ),
                _ => anyhow::bail!("sender handover cache role"),
            }
        }
        validate_offer_cache(
            ctx,
            self.record.offer.as_deref(),
            self.record.offer_digest.as_ref(),
        )?;
        if let Some(wire) = &self.record.completion {
            ensure!(
                self.record.offer.is_some(),
                "sender completion before handoff"
            );
            cached_completion(ctx, wire)?;
        }
        ensure!(
            !self.record.retired || self.record.completion.is_some(),
            "sender retired before completion request"
        );
        ensure!(
            self.record.offer.is_none() || self.record.handover.is_some(),
            "offer before handover"
        );
        Ok(())
    }
    pub(super) fn verify_current(&self, verifier: &PinnedVerifier, scratch: &Path) -> Result<()> {
        self.validate()?;
        self.certificate()?.verify(verifier, scratch)?;
        Ok(())
    }
    pub fn sender_role(&self) -> Result<Relation> {
        Ok(match self.certificate()?.kind() {
            PredecessorKind::Origin => Relation::SenderFromOrigin,
            PredecessorKind::Transfer => Relation::SenderFromTransfer,
        })
    }
    pub(super) fn check_chain(&self, chain: &ChainConfig) -> Result<()> {
        let live = self.live_backing(chain)?;
        chain.check_transfer_window(&live.observe(chain)?, live.previous, live.next)?;
        Ok(())
    }
    pub(super) fn live_backing(&self, chain: &ChainConfig) -> Result<LiveBacking> {
        ensure!(
            chain.deployment.id()? == self.policy.deployment,
            "sender chain deployment"
        );
        let previous = RecoveryDelay::from_sequence(
            self.recovery()?.completed_transaction()?.input[0]
                .sequence
                .to_consensus_u32(),
        )?;
        Ok(LiveBacking {
            backing: self.record.backing.clone(),
            activation_input: self.record.activation_input.clone(),
            previous,
            next: self.next_delay(previous)?,
        })
    }
    pub(super) fn next_delay(&self, previous: RecoveryDelay) -> Result<RecoveryDelay> {
        let next = RecoveryDelay::from_sequence(
            previous
                .blocks()
                .checked_sub(self.policy.schedule.gap)
                .context("recovery delay budget exhausted")?,
        )?;
        self.policy.schedule.check_transition(previous, next)?;
        Ok(next)
    }
}
