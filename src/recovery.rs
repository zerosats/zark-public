//! Receiver-created native Bitcoin recovery, isolated from live ownership flows.
//!
//! This verifies transaction/key/signature relations, not an ownership certificate,
//! a share-refresh transcript, signer freshness, or live Bitcoin backing/maturity.
//! The caller must establish those separately before exposing a signing binding.
//! Common activation is retained; no predecessor recovery or history is accepted.
//! Local files trust the OS user and do not defend against valid record rollback.
mod completion;
mod creation;
mod witness;
use crate::{
    signing::{Blinding, FundingKey},
    types::Input,
};
use anyhow::{Result, ensure};
use bitcoin::{Transaction, Txid, hashes::Hash};
use serde::{Deserialize, Serialize};
use std::{
    cell::{Ref, RefCell},
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};
use zark_protocol::{
    handoff::{Digest, FundingOpening, RecoveryDelay, RecoverySchedule, TransferContext},
    hex32,
    local::ProcessLock,
    random32,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SCHEMA: &str = "zark-receiver-recovery";
const RECORD_VERSION: u32 = 4;
const RECORD_FILE: &str = "recovery-draft.json";
const LOCK_FILE: &str = "recovery-draft.lock";
const MAX_RECORD_BYTES: u64 = 32768;

/// Recipient-local parameters only, never a signer request or proof statement.
/// Supplied commitments do not establish the truth of their hidden relations.
pub struct RecoveryParameters {
    pub context: TransferContext,
    pub backing: Input,
    pub activation_input: Input,
    pub activation: Transaction,
    pub draft_server: [u8; 64],
    pub refresh_commitment: Digest,
    pub previous_capability: Digest,
    pub next_capability: Digest,
    pub schedule: RecoverySchedule,
    pub previous_delay: RecoveryDelay,
    pub next_delay: RecoveryDelay,
    pub fee: u64,
}

/// Initial allocation only. There is no invented predecessor delay or capability.
/// The context must carry the exact origin-state sentinel. This does not verify
/// an origin authorization proof or authorize a signer to allocate a coin.
pub struct OriginRecoveryParameters {
    pub context: TransferContext,
    pub backing: Input,
    pub activation_input: Input,
    pub activation: Transaction,
    pub draft_server: [u8; 64],
    pub initial_capability: Digest,
    pub schedule: RecoverySchedule,
    pub fee: u64,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RecoveryMode {
    Transfer { previous_delay: u32 },
    Origin {},
    BootstrapOriginPending {},
    BootstrapOriginAttached {},
}

struct DraftParameters {
    context: TransferContext,
    backing: Input,
    activation_input: Input,
    activation: Transaction,
    draft_server: [u8; 64],
    refresh_commitment: Digest,
    previous_capability: Digest,
    next_capability: Digest,
    schedule: RecoverySchedule,
    next_delay: RecoveryDelay,
    fee: u64,
    mode: RecoveryMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryCommitments {
    pub funding: Digest,
    pub recovery: Digest,
    pub blinding: Digest,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Stage {
    Prepared {},
    NonceBound {
        server_nonce: String,
        binding: String,
    },
    Complete {
        server_nonce: String,
        binding: String,
        partial: Digest,
        transaction: String,
    },
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    mode: RecoveryMode,
    #[zeroize(skip)]
    context: TransferContext,
    #[zeroize(skip)]
    backing: Input,
    #[zeroize(skip)]
    activation_input: Input,
    activation: String,
    draft_server: String,
    refresh_commitment: Digest,
    previous_capability: Digest,
    next_capability: Digest,
    initial: u32,
    gap: u32,
    margin: u32,
    next_delay: u32,
    fee: u64,
    user_secret: Digest,
    payout_secret: Digest,
    alpha: Digest,
    beta: Digest,
    backup_salt: Digest,
    nonce_salt: Digest,
    unsigned_transaction: String,
    state: Stage,
}

struct NativeDraft {
    key: FundingKey,
    server: k256::ProjectivePoint,
    blind: Blinding,
    transaction: Transaction,
    message: Digest,
    commitments: RecoveryCommitments,
}

/// Holds a process lock and private recovery material. No public secret getters,
/// Debug, Display or serialization. Methods return only public commitments,
/// restricted signing bindings, or the recipient's completed Bitcoin transaction.
pub struct RecoveryDraft {
    directory: PathBuf,
    record: Record,
    validated: RefCell<Option<(Digest, NativeDraft)>>,
    _lock: ProcessLock,
}

impl RecoveryDraft {
    /// Validation is a pure function of the record. Keying on its exact bytes
    /// means a mutated record can never reuse an earlier result.
    fn native(&self) -> Result<Ref<'_, NativeDraft>> {
        let key = self.record.digest()?;
        if !matches!(&*self.validated.borrow(), Some((saved, _)) if *saved == key) {
            let native = self.record.validate()?;
            *self.validated.borrow_mut() = Some((key, native));
        }
        Ref::filter_map(self.validated.borrow(), |saved| {
            saved.as_ref().map(|(_, native)| native)
        })
        .map_err(|_| anyhow::anyhow!("recovery draft validation unavailable"))
    }
}

impl Record {
    fn digest(&self) -> Result<Digest> {
        Ok(zark_protocol::hash(&[&Zeroizing::new(serde_json::to_vec(
            self,
        )?)]))
    }
}

fn recovery_field(output: &mut String, name: &str, bytes: &[u8]) -> Result<()> {
    let encoded = Zeroizing::new(serde_json::to_string(bytes)?);
    output.push_str(name);
    output.push_str(" = ");
    output.push_str(&encoded);
    output.push('\n');
    Ok(())
}

fn funding_opening(context: &TransferContext, backing: &Input) -> Result<FundingOpening> {
    Ok(FundingOpening {
        deployment: context.deployment,
        coin: context.coin,
        salt: hex32(&backing.funding_salt)?,
        txid: Txid::from_str(&backing.txid)?.to_byte_array(),
        vout: backing.vout,
        amount: backing.amount,
        internal_point: hex::decode(&backing.internal_point)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid backing point length"))?,
    })
}

fn nonzero_random() -> Digest {
    loop {
        let value = random32();
        if value != [0; 32] {
            return value;
        }
    }
}

fn check_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.permissions().mode() & 0o777 == 0o700
            && metadata.uid() == unsafe { libc::geteuid() },
        "recovery draft directory must be private, owned and mode 0700"
    );
    Ok(())
}

fn check_file(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() },
        "recovery draft file must be private, owned, regular and mode 0600"
    );
    Ok(())
}

fn acquire_lock(directory: &Path) -> Result<ProcessLock> {
    let path = directory.join(LOCK_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => check_file(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let lock = ProcessLock::acquire(&path)?;
    check_file(&fs::symlink_metadata(path)?)?;
    Ok(lock)
}

mod validation;
