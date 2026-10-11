//! Checkpoint commitments, durable publication and explicitly bounded interrupted-publication repair.
use super::{
    Batch, Checkpoint, MAX_BATCH_MEMBERS, MAX_RECORD, Path, Purpose, Result, SCHEMA_VERSION, Store,
    Zeroizing, array, atomic_write, ensure, fs, hash,
};

impl Store {
    pub(super) fn checkpoint(&self) -> Result<Checkpoint> {
        let tx = self.connection.unchecked_transaction()?;
        let (database,config,generation,sequence,chain,previous):(Vec<u8>,Vec<u8>,u64,u64,Vec<u8>,String)=self.connection.query_row(
            "SELECT database_id,config,generation,sequence,chain,previous_floor FROM metadata WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        let database = array(database)?;
        let config = array(config)?;
        let chain = array(chain)?;
        let mut commitments = Vec::new();
        commitments.extend(database);
        commitments.extend(config);
        commitments.extend(generation.to_le_bytes());
        commitments.extend(sequence.to_le_bytes());
        commitments.extend(chain);
        commitments.extend(hash(&[previous.as_bytes()]));
        {
            let mut query = self
                .connection
                .prepare("SELECT coin,revision,body,checksum FROM coins ORDER BY coin")?;
            for row in query.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })? {
                let (id, revision, body, sum) = row?;
                let body = Zeroizing::new(body);
                ensure!(
                    body.len() <= MAX_RECORD && hash(&[body.as_bytes()]).as_slice() == sum,
                    "private coin checksum mismatch"
                );
                commitments.extend(array(id)?);
                commitments.extend(revision.to_le_bytes());
                commitments.extend(array(sum)?);
            }
        }
        {
            let mut query=self.connection.prepare("SELECT coin,operation,purpose,session,context_hash,request_hash,body,checksum FROM responses ORDER BY coin,operation,purpose,session")?;
            for row in query.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, u8>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, Vec<u8>>(7)?,
                ))
            })? {
                let (id, op, purpose, session, context, request, body, sum) = row?;
                let body = Zeroizing::new(body);
                ensure!(
                    ((1..=6).contains(&purpose)
                        || purpose == Purpose::ExitPreparation as u8
                        || purpose == Purpose::ExitIssuance as u8
                        || (13..=15).contains(&purpose)
                        || (17..=18).contains(&purpose)
                        || purpose == Purpose::TransferCancellation as u8
                        || purpose == Purpose::TransferAcknowledgement as u8
                        || purpose == Purpose::DepositIssuance as u8)
                        && body.len() <= MAX_RECORD
                        && hash(&[body.as_bytes()]).as_slice() == sum,
                    "private journal checksum or role mismatch"
                );
                commitments.extend(array(id)?);
                commitments.extend(array(op)?);
                commitments.push(purpose);
                commitments.extend(array(session)?);
                commitments.extend(array(context)?);
                commitments.extend(array(request)?);
                commitments.extend(array(sum)?);
            }
        }
        {
            let mut query = self
                .connection
                .prepare("SELECT id,body,checksum FROM batches ORDER BY id")?;
            for row in query.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })? {
                let (id, body, checksum) = row?;
                let id = array(id)?;
                ensure!(
                    body.len() <= MAX_RECORD && hash(&[body.as_bytes()]).as_slice() == checksum,
                    "batch checkpoint checksum mismatch"
                );
                let batch: Batch = serde_json::from_str(&body)?;
                batch.check()?;
                ensure!(
                    batch.manifest.id == id,
                    "batch checkpoint identity mismatch"
                );
                commitments.extend(id);
                commitments.extend(array(checksum)?);
            }
        }
        {
            let mut query = self.connection.prepare(
                "SELECT id,coin,operation,member_index FROM batch_members ORDER BY id,coin",
            )?;
            for row in query.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, u8>(3)?,
                ))
            })? {
                let (id, coin, operation, index) = row?;
                ensure!((index as usize) < MAX_BATCH_MEMBERS, "batch member index");
                commitments.extend(array(id)?);
                commitments.extend(array(coin)?);
                commitments.extend(array(operation)?);
                commitments.push(index);
            }
        }
        {
            let mut query = self.connection.prepare(
                "SELECT id,coin,revision,request,checksum FROM batch_ready ORDER BY id,coin",
            )?;
            for row in query.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, u64>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                ))
            })? {
                let (id, coin, revision, request, checksum) = row?;
                ensure!(
                    request.len() <= zark_protocol::wire::MAX_WIRE
                        && hash(&[&request]).as_slice() == checksum,
                    "batch ready checkpoint checksum mismatch"
                );
                commitments.extend(array(id)?);
                commitments.extend(array(coin)?);
                commitments.extend(revision.to_le_bytes());
                commitments.extend(array(checksum)?);
            }
        }
        tx.commit()?;
        Ok(Checkpoint {
            schema: SCHEMA_VERSION,
            database,
            config,
            generation,
            sequence,
            root: hash(&[b"ZARK/private-engine/checkpoint/v1", &commitments]),
        })
    }
    pub fn verify_checkpoint(&self, path: &Path) -> Result<Checkpoint> {
        let current = self.checkpoint()?;
        if !path.exists() {
            ensure!(
                current.sequence == 0 && current.generation == 1,
                "missing checkpoint for existing private state"
            );
            atomic_write(path, &serde_json::to_vec(&current)?)?;
        } else {
            ensure!(
                read_floor(path)? == current,
                "private checkpoint mismatch; service paused"
            );
        }
        Ok(current)
    }
    pub fn publish(&self, path: &Path) -> Result<()> {
        atomic_write(path, &serde_json::to_vec(&self.checkpoint()?)?)
    }
    pub fn repair_checkpoint(&self, path: &Path) -> Result<()> {
        let old = read_floor(path)?;
        let current = self.checkpoint()?;
        if old == current {
            return Ok(());
        }
        let previous: String = self.connection.query_row(
            "SELECT previous_floor FROM metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(previous.len() < 4096, "invalid previous checkpoint size");
        let previous: Checkpoint = serde_json::from_str(&previous)?;
        ensure!(
            previous == old
                && old.database == current.database
                && old.config == current.config
                && old.generation == current.generation
                && old.sequence.checked_add(1) == Some(current.sequence),
            "not one interrupted private checkpoint publication"
        );
        self.publish(path)
    }
}
fn read_floor(path: &Path) -> Result<Checkpoint> {
    ensure!(
        fs::metadata(path)?.len() < 4096,
        "private checkpoint too large"
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
