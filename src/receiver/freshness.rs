//! Fresh backing and signer-head checks for each ownership use.
use super::{CurrentUse, ReceiverJournal};
use crate::chain::{ChainConfig, LiveBacking, Observation};
use crate::freshness::{FreshHead, HeadProbe, SignerClient, read_with_chain};
use anyhow::{Result, ensure};
use k256::schnorr::SigningKey;
use zark_protocol::handoff::{Digest, RecoveryDelay};
use zark_protocol::head::Phase as HeadPhase;
use zark_protocol::lineage::LineageBinding;

impl ReceiverJournal {
    pub(crate) fn check_live_backing(&self, chain: &ChainConfig) -> Result<()> {
        self.check_live_backing_for(chain, CurrentUse::IncomingTransfer)
    }

    /// The readiness signature binds the exact tip at which live backing and
    /// the receiver's relative recovery window were checked. A later block
    /// must invalidate a pending batch before the signer releases any partial.
    pub(crate) fn checked_live_tip(&self, chain: &ChainConfig) -> Result<Digest> {
        self.checked_live_tip_for(chain, CurrentUse::IncomingTransfer)
    }

    pub(super) fn check_live_backing_for(
        &self,
        chain: &ChainConfig,
        usage: CurrentUse,
    ) -> Result<()> {
        self.checked_live_tip_for(chain, usage).map(|_| ())
    }

    fn checked_live_tip_for(&self, chain: &ChainConfig, usage: CurrentUse) -> Result<Digest> {
        let live = self.live_backing(chain)?;
        let observed = live.observe(chain)?;
        check_observed_use(chain, &observed, live.previous, live.next, usage)?;
        zark_protocol::hex32(&observed.tip_hash)
    }

    pub(super) fn live_backing(&self, chain: &ChainConfig) -> Result<LiveBacking> {
        ensure!(
            chain.deployment.id()? == self.policy.deployment
                && chain.deployment.schedule() == self.policy.schedule,
            "recipient chain deployment mismatch"
        );
        let native = self.native_offer()?;
        let (previous, next) = self.recovery_delays()?;
        Ok(LiveBacking {
            backing: native.common_backing().clone(),
            activation_input: native.common_activation_input().clone(),
            previous,
            next,
        })
    }

    pub(super) fn check_fresh_current(
        &self,
        client: &dyn SignerClient,
        chain: &ChainConfig,
        control: &Digest,
        binding: &LineageBinding,
        allow_issued: bool,
    ) -> Result<FreshHead> {
        self.check_fresh_current_for(
            client,
            chain,
            control,
            binding,
            allow_issued,
            CurrentUse::IncomingTransfer,
        )
    }

    pub(super) fn check_fresh_current_for(
        &self,
        client: &dyn SignerClient,
        chain: &ChainConfig,
        control: &Digest,
        binding: &LineageBinding,
        allow_issued: bool,
        usage: CurrentUse,
    ) -> Result<FreshHead> {
        ensure!(
            *control == zark_protocol::hex32(&chain.deployment.control_key)?,
            "recipient head key differs from authenticated deployment"
        );
        let live = self.live_backing(chain)?;
        let capability = self.claim_binding()?.next_capability;
        let key = SigningKey::from_bytes(&self.record.session)?;
        let probe = HeadProbe::new(&self.record.context, &key)?;
        let (head, observed) = read_with_chain(
            probe,
            client,
            |probe, response| {
                let phase: HeadPhase = serde_json::from_value(response["head"]["phase"].clone())
                    .map_err(|_| anyhow::anyhow!("invalid signer head phase"))?;
                ensure!(
                    phase == HeadPhase::Accepted || (allow_issued && phase == HeadPhase::Issued),
                    "signer head is not current recipient ownership"
                );
                probe.verify(response, control, &binding.state, &capability, phase)
            },
            || live.observe(chain),
        )?;
        check_observed_use(chain, &observed, live.previous, live.next, usage)?;
        head.require_fresh()?;
        Ok(head)
    }
}

pub(super) fn check_observed_use(
    chain: &ChainConfig,
    observed: &Observation,
    previous: RecoveryDelay,
    next: RecoveryDelay,
    usage: CurrentUse,
) -> Result<()> {
    // Both callers must obtain this observation from the live backing adapter.
    // A collaborative exit spends the current output; it does not establish a
    // new receiver recovery and must not reuse an expired incoming-transfer gate.
    if matches!(usage, CurrentUse::IncomingTransfer) {
        chain.check_transfer_window(observed, previous, next)?;
    }
    Ok(())
}
