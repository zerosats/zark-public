//! Validate the durable coin and batch graph when opening signer storage.
use super::{
    BatchPhase, Command, Context, LineagePolicy, MAX_BATCHES, MAX_COINS, OptionalExtension,
    Purpose, Result, Store, array, ensure, params,
};

impl Store {
    pub fn validate(&self, policy: &LineagePolicy) -> Result<()> {
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        ensure!(integrity == "ok", "private database integrity check failed");
        let mut query = self.connection.prepare("SELECT coin FROM coins")?;
        let ids = query
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            ids.len() <= MAX_COINS as usize,
            "private coin capacity exceeded"
        );
        for id in ids {
            let id = array(id)?;
            let (coin, _) = self.coin(&id)?.context("missing coin")?;
            ensure!(coin.coin == id, "coin row identity mismatch");
            coin.validate(policy)?;
        }
        let mut query = self
            .connection
            .prepare("SELECT id FROM batches ORDER BY id")?;
        let batches = query
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            batches.len() <= MAX_BATCHES as usize,
            "batch capacity exceeded"
        );
        for id in batches {
            let id = array(id)?;
            let batch = self.batch(&id)?.context("batch disappeared")?;
            let member_count: usize = self.connection.query_row(
                "SELECT count(*) FROM batch_members WHERE id=?1",
                [id.as_slice()],
                |row| row.get(0),
            )?;
            ensure!(
                member_count == batch.joined.iter().filter(|joined| **joined).count(),
                "batch contains unexpected membership rows"
            );
            let ready_count: usize = self.connection.query_row(
                "SELECT count(*) FROM batch_ready WHERE id=?1",
                [id.as_slice()],
                |row| row.get(0),
            )?;
            let mut expected_ready = 0;
            for (i, member) in batch.manifest.members.iter().enumerate() {
                let saved: Option<(Vec<u8>, u8)> = self
                    .connection
                    .query_row(
                        "SELECT operation,member_index FROM batch_members WHERE id=?1 AND coin=?2",
                        params![id.as_slice(), member.coin.as_slice()],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                ensure!(
                    saved.is_some() == batch.joined[i],
                    "batch joined flag differs from membership"
                );
                if let Some((operation, index)) = saved {
                    ensure!(
                        array(operation)? == member.operation && index as usize == i,
                        "batch member record differs from manifest"
                    );
                    let (coin, _) = self.coin(&member.coin)?.context("batch coin disappeared")?;
                    if matches!(batch.phase, BatchPhase::Joining | BatchPhase::Active) {
                        ensure!(
                            coin.pending.as_ref().and_then(|p| p.batch) == Some(id),
                            "active batch coin lost its lock"
                        );
                    }
                    if batch.phase == BatchPhase::Aborted {
                        ensure!(
                            coin.pending.as_ref().and_then(|p| p.batch) != Some(id),
                            "aborted batch retained a lock"
                        );
                    }
                    if batch.phase == BatchPhase::Committed {
                        let issued: bool = self.connection.query_row(
                            "SELECT EXISTS(SELECT 1 FROM responses WHERE coin=?1 AND operation=?2 AND purpose=?3)",
                            params![member.coin.as_slice(), member.operation.as_slice(), Purpose::BatchReadiness as u8],
                            |r| r.get(0),
                        )?;
                        ensure!(issued, "committed batch lost issuance response");
                    }
                }
                let ready = self.ready(&id, &member.coin)?;
                expected_ready += usize::from(ready.is_some());
                if let Some((request, _)) = &ready {
                    ensure!(
                        matches!(&request.command, Command::BatchReady { observed_tip, .. } if Some(*observed_tip) == batch.ready_tip),
                        "batch readiness Bitcoin tip differs from batch"
                    );
                }
                ensure!(
                    ready.is_none() || (batch.phase == BatchPhase::Active && batch.joined[i]),
                    "batch readiness outside active member"
                );
            }
            ensure!(
                ready_count == expected_ready,
                "batch contains unexpected readiness rows"
            );
            if batch.phase == BatchPhase::Active {
                ensure!(
                    batch.ready_tip.is_some() == (ready_count > 0),
                    "active batch readiness tip differs from rows"
                );
            }
        }
        self.checkpoint()?;
        Ok(())
    }
}
