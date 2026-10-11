//! Read coin, operation and exact response records; authenticate checksums before decoding.
use super::{
    Batch, CachedResponseRow, Coin, Digest, MAX_RECORD, MAX_REQUESTS, OptionalExtension, Purpose,
    Request, Result, Store, Value, Zeroizing, array, ensure, hash, params, response_budget,
};

impl Store {
    pub fn coin(&self, id: &Digest) -> Result<Option<(Coin, u64)>> {
        let value: Option<(u64, String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT revision,body,checksum FROM coins WHERE coin=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        value
            .map(|(revision, body, checksum)| {
                let body = Zeroizing::new(body);
                ensure!(
                    body.len() <= MAX_RECORD && hash(&[body.as_bytes()]).as_slice() == checksum,
                    "private coin checksum mismatch"
                );
                Ok((serde_json::from_str(&body)?, revision))
            })
            .transpose()
    }
    pub fn operation_exists(&self, coin: &Digest, operation: &Digest) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM responses WHERE coin=?1 AND operation=?2)",
            params![coin.as_slice(), operation.as_slice()],
            |r| r.get(0),
        )?)
    }
    pub fn operation_cancelled(&self, coin: &Digest, operation: &Digest) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM responses WHERE coin=?1 AND operation=?2 AND purpose=?3)",
            params![
                coin.as_slice(),
                operation.as_slice(),
                Purpose::TransferCancellation as u8
            ],
            |r| r.get(0),
        )?)
    }

    /// Reserve the entire admitted flow and a later two-response cooperative exit.
    /// A cancellation replaces its precommit records with one tombstone, so it
    /// requires no additional journal slot. Exact retries do not call this method.
    pub fn admit_operation(&self, request: &Request) -> Result<()> {
        let needed = response_budget(&request.command);
        if needed == 0 {
            return Ok(());
        }
        let count: u64 = self.connection.query_row(
            "SELECT count(*) FROM responses WHERE coin=?1",
            [request.context.coin.as_slice()],
            |r| r.get(0),
        )?;
        ensure!(
            count + needed <= MAX_REQUESTS,
            "private operation journal capacity reached"
        );
        Ok(())
    }
    pub fn batch_for_operation(&self, coin: &Digest, operation: &Digest) -> Result<Option<Digest>> {
        self.connection
            .query_row(
                "SELECT id FROM batch_members WHERE coin=?1 AND operation=?2",
                params![coin.as_slice(), operation.as_slice()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(array)
            .transpose()
    }
    pub fn batch(&self, id: &Digest) -> Result<Option<Batch>> {
        let row: Option<(String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT body,checksum FROM batches WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(body, checksum)| {
            ensure!(
                body.len() <= MAX_RECORD && hash(&[body.as_bytes()]).as_slice() == checksum,
                "batch checksum mismatch"
            );
            let batch: Batch = serde_json::from_str(&body)?;
            batch.check()?;
            ensure!(batch.manifest.id == *id, "batch identity mismatch");
            Ok(batch)
        })
        .transpose()
    }
    pub fn ready(&self, id: &Digest, coin: &Digest) -> Result<Option<(Request, u64)>> {
        let row: Option<(u64, Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT revision,request,checksum FROM batch_ready WHERE id=?1 AND coin=?2",
                params![id.as_slice(), coin.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(revision, request, checksum)| {
            ensure!(
                request.len() <= zark_protocol::wire::MAX_WIRE
                    && hash(&[&request]).as_slice() == checksum,
                "batch ready checksum mismatch"
            );
            let request = Request::decode(&request)?;
            ensure!(request.context.coin == *coin, "batch ready coin mismatch");
            Ok((request, revision))
        })
        .transpose()
    }
    pub fn operation_accepted(&self, coin: &Digest, operation: &Digest) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM responses WHERE coin=?1 AND operation=?2 AND purpose=?3)",
            params![
                coin.as_slice(),
                operation.as_slice(),
                Purpose::TransferAcknowledgement as u8
            ],
            |r| r.get(0),
        )?)
    }
    fn cached(
        &self,
        purpose: Purpose,
        ctx: &super::TransferContext,
    ) -> Result<Option<(Digest, Digest, Value)>> {
        let value:Option<CachedResponseRow>=self.connection.query_row(
            "SELECT context_hash,request_hash,body,checksum FROM responses WHERE coin=?1 AND operation=?2 AND purpose=?3 AND session=?4",
            params![ctx.coin.as_slice(),ctx.operation.as_slice(),purpose as u8,ctx.session_auth.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        value
            .map(|(context, digest, body, checksum)| {
                let body = Zeroizing::new(body);
                ensure!(
                    body.len() <= MAX_RECORD && hash(&[body.as_bytes()]).as_slice() == checksum,
                    "private response checksum mismatch"
                );
                Ok((
                    array(context)?,
                    array(digest)?,
                    serde_json::from_str(&body)?,
                ))
            })
            .transpose()
    }
    pub fn response_for(
        &self,
        purpose: Purpose,
        ctx: &super::TransferContext,
    ) -> Result<Option<Value>> {
        self.cached(purpose, ctx)?
            .map(|(context, _, value)| {
                ensure!(
                    context == hash(&[&ctx.encode()?]),
                    "private replay context changed"
                );
                Ok(value)
            })
            .transpose()
    }
    pub fn replay(&self, request: &Request, digest: Digest) -> Result<Option<Value>> {
        self.cached(request.command.purpose(), &request.context)?
            .map(|(context, saved, value)| {
                ensure!(
                    context == hash(&[&request.context.encode()?]) && saved == digest,
                    "same operation reused with changed request"
                );
                Ok(value)
            })
            .transpose()
    }
}
