//! Atomic multi-coin commit and abort transactions.
use super::{
    Batch, BatchPhase, Checkpoint, Coin, Context, Digest, MAX_RECORD, MAX_REQUESTS, Purpose,
    Request, Result, Store, TransactionBehavior, Value, Zeroizing, advance, ensure, hash, json,
    params, write_batch,
};

impl Store {
    pub fn commit_batch(
        &mut self,
        batch: &Batch,
        entries: &[(Coin, u64, Request, Digest, Value)],
        floor: &Checkpoint,
    ) -> Result<()> {
        ensure!(
            batch.phase == BatchPhase::Active
                && batch.joined.iter().all(|joined| *joined)
                && batch.ready_tip.is_some(),
            "batch is not active"
        );
        batch.check()?;
        ensure!(
            entries.len() == batch.manifest.members.len(),
            "incomplete batch commit"
        );
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut sums = Vec::new();
        for (i, (coin, revision, request, digest, response)) in entries.iter().enumerate() {
            ensure!(
                coin.coin == batch.manifest.members[i].coin,
                "batch commit member order"
            );
            ensure!(
                batch.manifest.index(&request.context, false)? == i,
                "batch commit request member mismatch"
            );
            let current: u64 = tx.query_row(
                "SELECT revision FROM coins WHERE coin=?1",
                [coin.coin.as_slice()],
                |r| r.get(0),
            )?;
            ensure!(current == *revision, "stale batch commit revision");
            let count: u64 = tx.query_row(
                "SELECT count(*) FROM responses WHERE coin=?1",
                [coin.coin.as_slice()],
                |r| r.get(0),
            )?;
            ensure!(
                count < MAX_REQUESTS,
                "private operation journal capacity reached"
            );
            let body = Zeroizing::new(serde_json::to_string(coin)?);
            let response = Zeroizing::new(serde_json::to_string(response)?);
            ensure!(
                body.len() <= MAX_RECORD && response.len() <= MAX_RECORD,
                "batch record too large"
            );
            let body_sum = hash(&[body.as_bytes()]);
            let response_sum = hash(&[response.as_bytes()]);
            tx.execute(
                "UPDATE coins SET revision=?2,body=?3,checksum=?4 WHERE coin=?1",
                params![
                    coin.coin.as_slice(),
                    revision
                        .checked_add(1)
                        .context("batch revision exhausted")?,
                    body.as_str(),
                    body_sum.as_slice(),
                ],
            )?;
            tx.execute(
                "INSERT INTO responses VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    coin.coin.as_slice(),
                    request.context.operation.as_slice(),
                    Purpose::BatchReadiness as u8,
                    request.context.session_auth.as_slice(),
                    hash(&[&request.context.encode()?]).as_slice(),
                    digest.as_slice(),
                    response.as_str(),
                    response_sum.as_slice(),
                ],
            )?;
            let terminal = serde_json::to_string(&json!({"superseded":true,"completed":true}))?;
            tx.execute("UPDATE responses SET body=?3,checksum=?4 WHERE coin=?1 AND operation=?2 AND purpose=?5", params![
                coin.coin.as_slice(), request.context.operation.as_slice(), terminal,
                hash(&[terminal.as_bytes()]).as_slice(), Purpose::BatchReservation as u8,
            ])?;
            tx.execute(
                "DELETE FROM batch_ready WHERE id=?1 AND coin=?2",
                params![batch.manifest.id.as_slice(), coin.coin.as_slice()],
            )?;
            sums.extend(body_sum);
            sums.extend(response_sum);
        }
        let mut committed = batch.clone();
        committed.phase = BatchPhase::Committed;
        write_batch(&tx, &committed)?;
        advance(
            &tx,
            floor,
            &batch.manifest.id,
            &hash(&[&sums]),
            &hash(&[b"commit-batch-v2"]),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn abort_batch(
        &mut self,
        batch: &Batch,
        coins: &[Option<(Coin, u64)>],
        floor: &Checkpoint,
    ) -> Result<()> {
        ensure!(
            matches!(batch.phase, BatchPhase::Joining | BatchPhase::Active),
            "batch cannot be aborted"
        );
        batch.check()?;
        ensure!(
            coins.len() == batch.manifest.members.len(),
            "incomplete batch abort"
        );
        ensure!(
            coins
                .iter()
                .zip(&batch.joined)
                .all(|(coin, joined)| coin.is_some() == *joined),
            "batch abort joined coverage"
        );
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut sums = Vec::new();
        for (i, entry) in coins.iter().enumerate() {
            let Some((coin, revision)) = entry else {
                continue;
            };
            ensure!(
                coin.coin == batch.manifest.members[i].coin,
                "batch abort member order"
            );
            let current: u64 = tx.query_row(
                "SELECT revision FROM coins WHERE coin=?1",
                [coin.coin.as_slice()],
                |r| r.get(0),
            )?;
            ensure!(current == *revision, "stale batch abort revision");
            let body = Zeroizing::new(serde_json::to_string(coin)?);
            ensure!(body.len() <= MAX_RECORD, "batch abort record too large");
            let sum = hash(&[body.as_bytes()]);
            tx.execute(
                "UPDATE coins SET revision=?2,body=?3,checksum=?4 WHERE coin=?1",
                params![
                    coin.coin.as_slice(),
                    revision
                        .checked_add(1)
                        .context("batch revision exhausted")?,
                    body.as_str(),
                    sum.as_slice(),
                ],
            )?;
            tx.execute(
                "DELETE FROM responses WHERE coin=?1 AND operation=?2",
                params![
                    coin.coin.as_slice(),
                    batch.manifest.members[i].operation.as_slice()
                ],
            )?;
            tx.execute(
                "DELETE FROM batch_ready WHERE id=?1 AND coin=?2",
                params![batch.manifest.id.as_slice(), coin.coin.as_slice()],
            )?;
            sums.extend(sum);
        }
        let mut aborted = batch.clone();
        aborted.phase = BatchPhase::Aborted;
        write_batch(&tx, &aborted)?;
        advance(
            &tx,
            floor,
            &batch.manifest.id,
            &hash(&[&sums]),
            &hash(&[b"abort-batch-v2"]),
        )?;
        tx.commit()?;
        Ok(())
    }
}
