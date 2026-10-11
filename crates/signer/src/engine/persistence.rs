//! Durable signer storage. DB commit and independent checkpoint publication are two
//! durable steps; an interrupted gap fails closed until explicit inspection.
mod batches;
mod checkpoint;
mod commits;
mod queries;
mod validation;

use super::{Coin, Command, Digest, LineagePolicy, Purpose, Request, TransferContext};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};
use zark_protocol::batch::{MAX_BATCH_MEMBERS, Manifest as BatchManifest};
use zark_protocol::{hash, random32, storage::atomic_write};
use zeroize::Zeroizing;

const APP_ID: u32 = 0x5a41524b;
const SCHEMA_VERSION: u32 = 13;
const MAX_COINS: u64 = 1000;
const MAX_REQUESTS: u64 = 256;
const MAX_RECORD: usize = 64 * 1024;
const MAX_BATCHES: u64 = 10_000;
type CachedResponseRow = (Vec<u8>, Vec<u8>, String, Vec<u8>);

fn response_budget(command: &Command) -> u64 {
    match command {
        // Reserve, handover, provisional recipient, prepare, issue/ready, ACK,
        // and the two responses reserved for a later cooperative exit.
        Command::Reserve { .. } | Command::BatchReserve { .. } => 8,
        Command::ExitPrepare { .. } => 2,
        _ => 0,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BatchPhase {
    Joining,
    Active,
    Committed,
    Aborted,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Batch {
    pub manifest: BatchManifest,
    pub joined: Vec<bool>,
    pub phase: BatchPhase,
    /// The active Bitcoin block hash when the first receiver became ready.
    pub ready_tip: Option<Digest>,
}

impl Batch {
    fn check(&self) -> Result<()> {
        self.manifest.validate()?;
        ensure!(
            self.joined.len() == self.manifest.members.len(),
            "batch joined length mismatch"
        );
        ensure!(
            self.ready_tip.is_none_or(|tip| tip != [0; 32]),
            "empty batch readiness tip"
        );
        ensure!(
            self.phase != BatchPhase::Joining || self.ready_tip.is_none(),
            "joining batch has a readiness tip"
        );
        ensure!(
            self.phase != BatchPhase::Committed || self.ready_tip.is_some(),
            "committed batch has no readiness tip"
        );
        ensure!(
            self.phase != BatchPhase::Joining || !self.joined.iter().all(|joined| *joined),
            "active batch marked joining"
        );
        ensure!(
            matches!(self.phase, BatchPhase::Joining | BatchPhase::Aborted)
                || self.joined.iter().all(|joined| *joined),
            "incomplete active batch"
        );
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    schema: u32,
    database: Digest,
    config: Digest,
    pub generation: u64,
    pub sequence: u64,
    root: Digest,
}

pub(super) fn lock(db: &Path, checkpoint: &Path) -> Result<crate::checkpoint::CheckpointLock> {
    lock_guarded(db, checkpoint, &|| Ok(()))
}

pub(super) fn lock_guarded(
    db: &Path,
    checkpoint: &Path,
    guard: &dyn Fn() -> Result<()>,
) -> Result<crate::checkpoint::CheckpointLock> {
    let parent = db.parent().context("private database parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    ensure!(db != checkpoint, "checkpoint cannot be database");
    for path in [db, checkpoint] {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1,
                "unsafe private persistence file"
            );
        }
    }
    crate::checkpoint::CheckpointLock::acquire(db, checkpoint, guard)
}

pub(super) struct Store {
    connection: Connection,
}
impl Store {
    pub fn open(path: &Path, config: Digest) -> Result<Self> {
        let connection = Connection::open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        connection.busy_timeout(Duration::from_secs(2))?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let tables: u32 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        if version == 0 && tables == 0 {
            connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON;
                BEGIN IMMEDIATE;
                CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1), database_id BLOB NOT NULL, config BLOB NOT NULL,
                    generation INTEGER NOT NULL CHECK(generation>0), sequence INTEGER NOT NULL CHECK(sequence>=0), chain BLOB NOT NULL, previous_floor TEXT NOT NULL);
                CREATE TABLE coins(coin BLOB PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision>0), body TEXT NOT NULL, checksum BLOB NOT NULL);
                CREATE TABLE responses(coin BLOB NOT NULL REFERENCES coins(coin), operation BLOB NOT NULL, purpose INTEGER NOT NULL,
                    session BLOB NOT NULL, context_hash BLOB NOT NULL, request_hash BLOB NOT NULL, body TEXT NOT NULL, checksum BLOB NOT NULL,
                    PRIMARY KEY(coin,operation,purpose,session));
                CREATE TABLE batches(id BLOB PRIMARY KEY, body TEXT NOT NULL, checksum BLOB NOT NULL);
                CREATE TABLE batch_members(id BLOB NOT NULL REFERENCES batches(id), coin BLOB NOT NULL REFERENCES coins(coin), operation BLOB NOT NULL,
                    member_index INTEGER NOT NULL CHECK(member_index >= 0 AND member_index < 10), PRIMARY KEY(id,coin), UNIQUE(coin,operation));
                CREATE TABLE batch_ready(id BLOB NOT NULL REFERENCES batches(id), coin BLOB NOT NULL REFERENCES coins(coin),
                    revision INTEGER NOT NULL CHECK(revision>0), request BLOB NOT NULL, checksum BLOB NOT NULL, PRIMARY KEY(id,coin));
                PRAGMA user_version=13;")?;
            connection.pragma_update(None, "application_id", APP_ID)?;
            connection.execute(
                "INSERT INTO metadata VALUES(1,?1,?2,1,0,?3,'')",
                params![
                    random32().as_slice(),
                    config.as_slice(),
                    [0u8; 32].as_slice()
                ],
            )?;
            connection.execute_batch("COMMIT;")?;
            fs::File::open(path.parent().context("database parent")?)?.sync_all()?;
        } else {
            let app: u32 = connection.query_row("PRAGMA application_id", [], |r| r.get(0))?;
            ensure!(
                version == SCHEMA_VERSION && app == APP_ID,
                "not a supported Zark signer database"
            );
            let saved: Vec<u8> =
                connection.query_row("SELECT config FROM metadata WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
            ensure!(saved == config, "private signer configuration changed");
            let journal: String = connection.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
            ensure!(
                journal == "delete",
                "unsupported private signer journal mode"
            );
            connection.execute_batch(
                "PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON;",
            )?;
        }
        Ok(Self { connection })
    }
}
fn write_batch(tx: &rusqlite::Transaction<'_>, batch: &Batch) -> Result<()> {
    batch.check()?;
    let body = serde_json::to_string(batch)?;
    ensure!(body.len() <= MAX_RECORD, "batch record too large");
    let checksum = hash(&[body.as_bytes()]);
    tx.execute("INSERT INTO batches(id,body,checksum) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET body=excluded.body,checksum=excluded.checksum", params![
        batch.manifest.id.as_slice(), body, checksum.as_slice(),
    ])?;
    Ok(())
}
fn array(value: Vec<u8>) -> Result<Digest> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("private persistence digest length"))
}
fn advance(
    tx: &rusqlite::Transaction<'_>,
    floor: &Checkpoint,
    coin: &Digest,
    body: &Digest,
    response: &Digest,
) -> Result<()> {
    let (generation, sequence, chain): (u64, u64, Vec<u8>) = tx.query_row(
        "SELECT generation,sequence,chain FROM metadata WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    ensure!(
        generation == floor.generation && sequence == floor.sequence,
        "stale private checkpoint floor"
    );
    let chain = array(chain)?;
    let next = hash(&[
        b"ZARK/private-engine/commit/v1",
        &chain,
        coin,
        body,
        response,
        &floor.root,
    ]);
    tx.execute(
        "UPDATE metadata SET sequence=?1,chain=?2,previous_floor=?3 WHERE singleton=1",
        params![
            sequence
                .checked_add(1)
                .context("checkpoint sequence exhausted")?,
            next.as_slice(),
            serde_json::to_string(floor)?
        ],
    )?;
    Ok(())
}
