//! Synthetic allocation fixture; production allocation remains the bootstrap workflow.
use super::{
    Coin, Digest, Engine, Pending, Phase, PredecessorKind, Result, Scalar, TransferContext,
    bootstrap, ensure, nonzero, nonzero_random, origin_previous_state, persistence, scalar,
};

/// Intentionally has no public constructor. The production bootstrap must
/// establish/retire the jointly controlled parent before creating this token.
#[cfg(test)]
pub(super) struct ValidatedAllocation {
    pub(super) context: TransferContext,
    pub(super) funding: Digest,
    pub(super) capability: Digest,
    pub(super) server_secret: Digest,
}

impl Engine {
    #[allow(dead_code)]
    #[cfg(test)]
    pub(super) fn install_validated_allocation(
        &self,
        allocation: ValidatedAllocation,
    ) -> Result<()> {
        let ctx = allocation.context;
        ensure!(
            ctx.deployment == self.policy.deployment
                && ctx.previous_state == origin_previous_state(&ctx.deployment, &ctx.coin)?,
            "invalid origin allocation context"
        );
        nonzero(allocation.funding)?;
        nonzero(allocation.capability)?;
        ensure!(
            scalar(&allocation.server_secret)? != Scalar::ZERO,
            "zero allocated server share"
        );
        let mut pending = Pending::new(true);
        pending.recipient = Some(ctx.clone());
        let server_salt = nonzero_random();
        let bootstrap = bootstrap::Bootstrap::test_frozen(
            &ctx,
            allocation.funding,
            allocation.capability,
            allocation.server_secret,
            server_salt,
        )?;
        let coin = Coin {
            deployment: ctx.deployment,
            coin: ctx.coin,
            funding: allocation.funding,
            state: ctx.previous_state,
            capability: allocation.capability,
            owner_kind: PredecessorKind::Origin,
            server_secret: allocation.server_secret,
            server_salt,
            current_session: ctx,
            phase: Phase::Origin,
            pending: Some(pending),
            exit: None,
            bootstrap: Some(bootstrap),
        };
        coin.validate(&self.policy)?;
        let _lock = persistence::lock(&self.db, &self.checkpoint)?;
        let mut store = self.store()?;
        let floor = store.verify_checkpoint(&self.checkpoint)?;
        store.allocate(&coin, &floor)?;
        store.publish(&self.checkpoint)
    }
}
