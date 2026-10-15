//! Single-operation commits and frozen readiness records; publication remains a separate durable step.
use super::{
    Batch, BatchManifest, BatchPhase, Checkpoint, Coin, Command, Context, Digest, MAX_RECORD,
    MAX_REQUESTS, OptionalExtension, Request, Result, Store, TransactionBehavior, Value, Zeroizing,
    advance, ensure, hash, json, params, response_budget, write_batch,
};

impl Store {
    pub fn save_ready(
        &mut self,
        batch: &Batch,
        request: &Request,
        revision: u64,
        tip: Digest,
        floor: &Checkpoint,
    ) -> Result<()> {
        ensure!(tip != [0; 32], "empty batch readiness tip");
        ensure!(
            batch.phase == BatchPhase::Active && batch.ready_tip.is_none_or(|saved| saved == tip),
            "batch readiness Bitcoin tip changed"
        );
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut ready_batch = batch.clone();
        ready_batch.ready_tip = Some(tip);
        write_batch(&tx, &ready_batch)?;
        let encoded = request.encode()?;
        tx.execute(
            "INSERT INTO batch_ready VALUES(?1,?2,?3,?4,?5)",
            params![
                batch.manifest.id.as_slice(),
                request.context.coin.as_slice(),
                revision,
                encoded.as_slice(),
                hash(&[&encoded]).as_slice(),
            ],
        )?;
        advance(
            &tx,
            floor,
            &batch.manifest.id,
            &hash(&[&encoded, &tip]),
            &[0; 32],
        )?;
        tx.commit()?;
        Ok(())
    }
    #[cfg(test)]
    pub fn allocate(&mut self, coin: &Coin, floor: &Checkpoint) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: u64 = tx.query_row("SELECT count(*) FROM coins", [], |r| r.get(0))?;
        ensure!(count < self.limits.coins, "private coin capacity reached");
        let body = Zeroizing::new(serde_json::to_string(coin)?);
        let sum = hash(&[body.as_bytes()]);
        tx.execute(
            "INSERT INTO coins VALUES(?1,1,?2,?3)",
            params![coin.coin.as_slice(), body.as_str(), sum.as_slice()],
        )?;
        advance(&tx, floor, &coin.coin, &sum, &[0; 32])?;
        tx.commit()?;
        Ok(())
    }
    pub fn allocate_request(
        &mut self,
        coin: &Coin,
        request: &Request,
        digest: Digest,
        response: &Value,
        floor: &Checkpoint,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: u64 = tx.query_row("SELECT count(*) FROM coins", [], |r| r.get(0))?;
        ensure!(count < self.limits.coins, "private coin capacity reached");
        let body = Zeroizing::new(serde_json::to_string(coin)?);
        let sum = hash(&[body.as_bytes()]);
        let response = Zeroizing::new(serde_json::to_string(response)?);
        let response_sum = hash(&[response.as_bytes()]);
        ensure!(
            body.len() <= MAX_RECORD && response.len() <= MAX_RECORD,
            "bootstrap allocation record size"
        );
        tx.execute(
            "INSERT INTO coins VALUES(?1,1,?2,?3)",
            params![coin.coin.as_slice(), body.as_str(), sum.as_slice()],
        )?;
        tx.execute(
            "INSERT INTO responses VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                coin.coin.as_slice(),
                request.context.operation.as_slice(),
                request.command.purpose() as u8,
                request.context.session_auth.as_slice(),
                hash(&[&request.context.encode()?]).as_slice(),
                digest.as_slice(),
                response.as_str(),
                response_sum.as_slice()
            ],
        )?;
        advance(&tx, floor, &coin.coin, &sum, &response_sum)?;
        tx.commit()?;
        Ok(())
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "The atomic commit explicitly binds state, revision, exact request/response and checkpoint floor"
    )]
    pub fn commit(
        &mut self,
        coin: &Coin,
        revision: u64,
        request: &Request,
        digest: Digest,
        response: &Value,
        purge_mask: bool,
        floor: &Checkpoint,
        batch_join: Option<(&BatchManifest, usize)>,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: u64 = tx.query_row(
            "SELECT revision FROM coins WHERE coin=?1",
            [coin.coin.as_slice()],
            |r| r.get(0),
        )?;
        ensure!(current == revision, "stale private commit revision");
        if matches!(request.command, Command::CancelTransfer {}) {
            // The authenticated cancellation consumes the reservation's slot,
            // replacing every precommit response with one durable tombstone.
            let deleted = tx.execute(
                "DELETE FROM responses WHERE coin=?1 AND operation=?2",
                params![coin.coin.as_slice(), request.context.operation.as_slice()],
            )?;
            ensure!(deleted > 0, "cancellation has no reserved operation");
        }
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM responses WHERE coin=?1",
            [coin.coin.as_slice()],
            |r| r.get(0),
        )?;
        ensure!(
            count + response_budget(&request.command).max(1) <= MAX_REQUESTS,
            "private operation journal capacity reached"
        );
        let body = Zeroizing::new(serde_json::to_string(coin)?);
        let sum = hash(&[body.as_bytes()]);
        ensure!(body.len() <= MAX_RECORD, "private coin record too large");
        tx.execute(
            "UPDATE coins SET revision=?2,body=?3,checksum=?4 WHERE coin=?1",
            params![
                coin.coin.as_slice(),
                revision.checked_add(1).context("revision exhausted")?,
                body.as_str(),
                sum.as_slice()
            ],
        )?;
        if purge_mask {
            let terminal = serde_json::to_string(&json!({"superseded":true,"completed":true}))?;
            tx.execute("UPDATE responses SET body=?3,checksum=?4 WHERE coin=?1 AND operation=?2 AND purpose IN (1,17)",params![coin.coin.as_slice(),request.context.operation.as_slice(),terminal,hash(&[terminal.as_bytes()]).as_slice()])?;
        }
        let response = Zeroizing::new(serde_json::to_string(response)?);
        let response_sum = hash(&[response.as_bytes()]);
        ensure!(response.len() <= MAX_RECORD, "private response too large");
        tx.execute(
            "INSERT INTO responses VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                coin.coin.as_slice(),
                request.context.operation.as_slice(),
                request.command.purpose() as u8,
                request.context.session_auth.as_slice(),
                hash(&[&request.context.encode()?]).as_slice(),
                digest.as_slice(),
                response.as_str(),
                response_sum.as_slice()
            ],
        )?;
        if let Some((manifest, index)) = batch_join {
            let current: Option<(String, Vec<u8>)> = tx
                .query_row(
                    "SELECT body,checksum FROM batches WHERE id=?1",
                    [manifest.id.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let mut batch = if let Some((raw, checksum)) = current {
                ensure!(
                    hash(&[raw.as_bytes()]).as_slice() == checksum && raw.len() <= MAX_RECORD,
                    "batch checksum mismatch"
                );
                let value: Batch = serde_json::from_str(&raw)?;
                ensure!(
                    value.manifest == *manifest && value.phase == BatchPhase::Joining,
                    "batch manifest changed or unavailable"
                );
                value
            } else {
                let count: u64 = tx.query_row("SELECT count(*) FROM batches", [], |r| r.get(0))?;
                ensure!(count < self.limits.batches, "batch capacity reached");
                Batch {
                    manifest: manifest.clone(),
                    joined: vec![false; manifest.members.len()],
                    phase: BatchPhase::Joining,
                    ready_tip: None,
                }
            };
            batch.check()?;
            ensure!(
                index < batch.joined.len(),
                "batch member index out of bounds"
            );
            ensure!(!batch.joined[index], "batch member already joined");
            batch.joined[index] = true;
            if batch.joined.iter().all(|joined| *joined) {
                batch.phase = BatchPhase::Active;
            }
            batch.check()?;
            write_batch(&tx, &batch)?;
            tx.execute(
                "INSERT INTO batch_members VALUES(?1,?2,?3,?4)",
                params![
                    manifest.id.as_slice(),
                    coin.coin.as_slice(),
                    request.context.operation.as_slice(),
                    index,
                ],
            )?;
        }
        advance(&tx, floor, &coin.coin, &sum, &response_sum)?;
        tx.commit()?;
        Ok(())
    }
}
