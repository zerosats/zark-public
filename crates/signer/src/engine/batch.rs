//! Whole-batch readiness, atomic issuance and explicit abort; all responses follow checkpoint publication.
#[cfg(test)]
use super::tests;
use super::{
    BatchManifest, BatchPhase, Coin, Command, Digest, Engine, Phase, Request, Result, Store,
    SystemTime, UNIX_EPOCH, Value, ensure, json, persistence,
};
use anyhow::Context;

type BatchCommitEntry = (Coin, u64, Request, Digest, Value);
impl Engine {
    pub(super) fn batch_now(&self) -> Result<u64> {
        #[cfg(test)]
        {
            let now = self.batch_clock.load(std::sync::atomic::Ordering::SeqCst);
            if now != 0 {
                return Ok(now);
            }
        }
        batch_now()
    }

    pub(super) fn check_batch_reserve(
        &self,
        store: &Store,
        manifest: &BatchManifest,
        request: &Request,
        revision: u64,
    ) -> Result<()> {
        ensure!(
            manifest.deployment == self.policy.deployment,
            "batch deployment mismatch"
        );
        let index = manifest.index(&request.context, true)?;
        ensure!(
            manifest.members[index].revision == revision,
            "batch manifest revision mismatch"
        );
        let now = self.batch_now()?;
        ensure!(
            manifest.expires_at > now && manifest.expires_at <= now + 86_400,
            "batch expiry outside signer limit"
        );
        if let Some(batch) = store.batch(&manifest.id)? {
            ensure!(
                batch.manifest == *manifest
                    && batch.phase == BatchPhase::Joining
                    && !batch.joined[index],
                "batch manifest changed or member already joined"
            );
        }
        Ok(())
    }

    pub(super) fn check_batch_step(&self, store: &Store, coin: &Coin) -> Result<()> {
        if let Some(id) = coin.pending.as_ref().and_then(|p| p.batch) {
            let batch = store.batch(&id)?.context("missing batch for coin")?;
            ensure!(
                batch.phase == BatchPhase::Active
                    && batch.manifest.expires_at > self.batch_now()?,
                "batch is not active"
            );
        }
        Ok(())
    }

    pub(super) fn batch_ready(
        &self,
        request: &Request,
        manifest: &BatchManifest,
        digest: Digest,
        guard: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        ensure!(
            manifest.deployment == self.policy.deployment,
            "batch deployment mismatch"
        );
        let index = manifest.index(&request.context, false)?;
        let observed_tip = match &request.command {
            Command::BatchReady { observed_tip, .. } if *observed_tip != [0; 32] => *observed_tip,
            _ => anyhow::bail!("batch readiness has no Bitcoin tip"),
        };
        let (revision, generation, spec) = {
            let _lock = persistence::lock_guarded(&self.db, &self.checkpoint, guard)?;
            let store = self.store()?;
            let floor = store.verify_checkpoint(&self.checkpoint)?;
            let batch = store.batch(&manifest.id)?.context("unknown batch")?;
            ensure!(batch.manifest == *manifest, "batch manifest changed");
            let (coin, revision) = store
                .coin(&request.context.coin)?
                .context("unknown batch coin")?;
            coin.validate(&self.policy)?;
            guard()?;
            if batch.phase == BatchPhase::Committed {
                return store
                    .replay(request, digest)?
                    .context("committed batch has no issuance response");
            }
            ensure!(
                batch.phase == BatchPhase::Active && manifest.expires_at > self.batch_now()?,
                "batch is not active"
            );
            ensure!(
                self.batch_tip.current_tip()? == observed_tip
                    && batch.ready_tip.is_none_or(|tip| tip == observed_tip),
                "batch readiness Bitcoin tip changed"
            );
            ensure!(
                coin.pending.as_ref().and_then(|p| p.batch) == Some(manifest.id),
                "coin is not bound to batch"
            );
            if let Some((saved, saved_revision)) =
                store.ready(&manifest.id, &request.context.coin)?
            {
                ensure!(
                    saved.digest()? == digest && saved_revision == revision,
                    "batch readiness changed after being frozen"
                );
                return Ok(json!({"pending":true,"batch":manifest.id}));
            }
            let spec = self
                .plan(&coin, request)?
                .context("missing batch issuance proof")?;
            (revision, floor.generation, spec)
        };
        self.verify(
            &spec,
            request.command.proof().context("missing batch proof")?,
            guard,
        )?;
        #[cfg(test)]
        self.trip(tests::Fault::AfterVerification)?;
        let _lock = persistence::lock_guarded(&self.db, &self.checkpoint, guard)?;
        let mut store = self.store()?;
        let floor = store.verify_checkpoint(&self.checkpoint)?;
        ensure!(floor.generation == generation, "stale batch generation");
        let batch = store.batch(&manifest.id)?.context("batch disappeared")?;
        ensure!(
            batch.manifest == *manifest
                && batch.phase == BatchPhase::Active
                && manifest.expires_at > self.batch_now()?,
            "batch changed before readiness"
        );
        ensure!(
            self.batch_tip.current_tip()? == observed_tip
                && batch.ready_tip.is_none_or(|tip| tip == observed_tip),
            "batch readiness Bitcoin tip changed"
        );
        let (current, current_revision) = store
            .coin(&request.context.coin)?
            .context("batch coin disappeared")?;
        ensure!(
            current_revision == revision,
            "stale verified batch revision"
        );
        ensure!(
            self.plan(&current, request)?
                .as_ref()
                .is_some_and(|s| s.relation == spec.relation && s.expected == spec.expected),
            "verified batch statement changed"
        );
        ensure!(
            store.ready(&manifest.id, &request.context.coin)?.is_none(),
            "batch readiness was already saved"
        );
        guard()?;
        let mut prepared = Vec::with_capacity(manifest.members.len());
        let mut all_ready = true;
        for (member_index, member) in manifest.members.iter().enumerate() {
            if member_index == index {
                prepared.push((current.clone(), current_revision, request.clone()));
                continue;
            }
            let Some((saved_request, saved_revision)) = store.ready(&manifest.id, &member.coin)?
            else {
                all_ready = false;
                continue;
            };
            ensure!(
                matches!(&saved_request.command, Command::BatchReady { manifest, .. } if *manifest == batch.manifest),
                "stored batch readiness manifest mismatch"
            );
            ensure!(
                batch.manifest.index(&saved_request.context, false)? == member_index,
                "stored batch readiness member mismatch"
            );
            let (saved_coin, current_revision) = store
                .coin(&member.coin)?
                .context("batch coin disappeared")?;
            saved_coin.validate(&self.policy)?;
            ensure!(
                saved_revision == current_revision,
                "batch readiness became stale"
            );
            ensure!(
                saved_coin
                    .pending
                    .as_ref()
                    .and_then(|pending| pending.batch)
                    == Some(manifest.id),
                "ready coin lost batch binding"
            );
            self.plan(&saved_coin, &saved_request)?
                .context("batch proof no longer applies")?;
            prepared.push((saved_coin, current_revision, saved_request));
        }
        if all_ready {
            let mut entries: Vec<BatchCommitEntry> = Vec::with_capacity(manifest.members.len());
            for (coin, revision, saved_request) in prepared {
                let (next, response, _) = self.apply(coin, &saved_request)?;
                next.validate(&self.policy)?;
                entries.push((
                    next,
                    revision,
                    saved_request.clone(),
                    saved_request.digest()?,
                    response,
                ));
            }
            let response = entries[index].4.clone();
            #[cfg(test)]
            self.trip(tests::Fault::BeforeCommit)?;
            guard()?;
            ensure!(
                manifest.expires_at > self.batch_now()?,
                "batch expired before commit"
            );
            // Keep the final chain observation inside the checkpoint lock,
            // adjacent to the all-member commit it authorizes.
            ensure!(
                self.batch_tip.current_tip()? == observed_tip
                    && batch.ready_tip == Some(observed_tip),
                "batch Bitcoin tip changed before commit"
            );
            store.commit_batch(&batch, &entries, &floor)?;
            #[cfg(test)]
            self.trip(tests::Fault::AfterCommit)?;
            store.publish(&self.checkpoint)?;
            #[cfg(test)]
            self.trip(tests::Fault::AfterCheckpoint)?;
            Ok(response)
        } else {
            #[cfg(test)]
            self.trip(tests::Fault::BeforeCommit)?;
            guard()?;
            ensure!(
                manifest.expires_at > self.batch_now()?,
                "batch expired before readiness"
            );
            ensure!(
                self.batch_tip.current_tip()? == observed_tip,
                "batch Bitcoin tip changed before readiness"
            );
            store.save_ready(&batch, request, revision, observed_tip, &floor)?;
            #[cfg(test)]
            self.trip(tests::Fault::AfterCommit)?;
            store.publish(&self.checkpoint)?;
            #[cfg(test)]
            self.trip(tests::Fault::AfterCheckpoint)?;
            Ok(json!({"pending":true,"batch":manifest.id}))
        }
    }

    pub(super) fn batch_abort(
        &self,
        request: &Request,
        manifest: &BatchManifest,
        guard: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        // A signed original sender must be able to release precommit locks even
        // after short-lived hosted credentials expire. No signing material is returned.
        ensure!(
            manifest.deployment == self.policy.deployment,
            "batch deployment mismatch"
        );
        manifest.index(&request.context, true)?;
        let _lock = persistence::lock_guarded(&self.db, &self.checkpoint, guard)?;
        let mut store = self.store()?;
        let floor = store.verify_checkpoint(&self.checkpoint)?;
        let batch = store.batch(&manifest.id)?.context("unknown batch")?;
        ensure!(batch.manifest == *manifest, "batch abort manifest changed");
        if batch.phase == BatchPhase::Aborted {
            return Ok(json!({"aborted":true}));
        }
        ensure!(
            matches!(batch.phase, BatchPhase::Joining | BatchPhase::Active),
            "committed batch cannot be aborted"
        );
        let mut coins: Vec<Option<(Coin, u64)>> = vec![None; manifest.members.len()];
        for (i, member) in manifest.members.iter().enumerate() {
            if !batch.joined[i] {
                continue;
            }
            let (mut coin, revision) = store
                .coin(&member.coin)?
                .context("batch member disappeared")?;
            ensure!(
                coin.pending.as_ref().and_then(|p| p.batch) == Some(manifest.id)
                    && !matches!(
                        coin.phase,
                        Phase::Issued | Phase::Accepted | Phase::Terminal
                    ),
                "batch member cannot be restored"
            );
            coin.pending = None;
            coin.phase = Phase::Accepted;
            coin.validate(&self.policy)?;
            coins[i] = Some((coin, revision));
        }
        guard()?;
        #[cfg(test)]
        self.trip(tests::Fault::BeforeCommit)?;
        store.abort_batch(&batch, &coins, &floor)?;
        #[cfg(test)]
        self.trip(tests::Fault::AfterCommit)?;
        store.publish(&self.checkpoint)?;
        #[cfg(test)]
        self.trip(tests::Fault::AfterCheckpoint)?;
        Ok(json!({"aborted":true}))
    }
}

pub(super) fn batch_now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
