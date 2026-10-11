//! Pre-issuance cancellation preserves the live owner and retires only provisional secrets.
#[cfg(test)]
use super::tests;
use super::{
    Digest, Engine, Phase, Request, Result, Store, Value, ensure, json, persistence, sender,
};
use anyhow::Context;
use zeroize::Zeroize;

impl Engine {
    pub(super) fn cancel_transfer(
        &self,
        request: &Request,
        digest: Digest,
        guard: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        let _lock = persistence::lock_guarded(&self.db, &self.checkpoint, guard)?;
        let mut store = Store::open(&self.db, self.config)?;
        let floor = store.verify_checkpoint(&self.checkpoint)?;
        if store.operation_cancelled(&request.context.coin, &request.context.operation)? {
            guard()?;
            return store
                .replay(request, digest)?
                .context("cancellation sender or context mismatch");
        }
        ensure!(
            store
                .batch_for_operation(&request.context.coin, &request.context.operation)?
                .is_none(),
            "batch member requires whole-batch abort"
        );
        let (mut coin, revision) = store
            .coin(&request.context.coin)?
            .context("unknown private coin")?;
        coin.validate(&self.policy)?;
        ensure!(
            matches!(
                coin.phase,
                Phase::Reserved | Phase::Handover | Phase::RecipientProposed | Phase::Prepared
            ),
            "transfer cannot be cancelled in this phase"
        );
        let pending = coin.pending.as_ref().context("no reserved transfer")?;
        ensure!(
            !pending.origin && pending.batch.is_none(),
            "not an ordinary transfer"
        );
        sender(pending, &request.context)?;
        // Keep the old live share, capability, state and owner session. Only
        // pre-issuance material is discarded; no signing contribution is released.
        let mut pending = coin.pending.take().expect("validated pending transfer");
        for secret in [
            &mut pending.mask,
            &mut pending.mask_salt,
            &mut pending.draft_secret,
            &mut pending.draft_salt,
            &mut pending.nonce_secret,
        ]
        .into_iter()
        .flatten()
        {
            secret.zeroize();
        }
        coin.phase = Phase::Accepted;
        coin.validate(&self.policy)?;
        let response = json!({"cancelled":true,"operation":request.context.operation});
        #[cfg(test)]
        self.trip(tests::Fault::BeforeCommit)?;
        guard()?;
        store.commit(
            &coin, revision, request, digest, &response, false, &floor, None,
        )?;
        #[cfg(test)]
        self.trip(tests::Fault::AfterCommit)?;
        store.publish(&self.checkpoint)?;
        #[cfg(test)]
        self.trip(tests::Fault::AfterCheckpoint)?;
        Ok(response)
    }
}
