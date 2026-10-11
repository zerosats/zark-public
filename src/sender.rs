//! Sender-local journal. Only the composed handover and common Bitcoin data
//! leave this journal; the sender's own recovery witnesses stay local.
mod cancellation;
mod creation;
mod handover;
mod validation;
use crate::{freshness::SignerClient, types::Input};
use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zark_protocol::{
    batch::Manifest as BatchManifest,
    certificate::OwnerCertificate,
    handoff::{Digest, OperationScope, TransferContext},
    hash,
    lineage::LineagePolicy,
    local::ProcessLock,
    storage::atomic_write,
    wire::{Command, Request},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const FILE: &str = "sender-operation.json";
const LIMIT: usize = 800_000;

#[cfg(test)]
mod cancellation_tests;

/// Created only by an accepted owner workflow. The common records contain no
/// predecessor private data; recovery_path points to this owner's own recovery.
pub(crate) struct SenderParameters {
    pub recovery_path: PathBuf,
    pub recovery_context: TransferContext,
    pub backing: Input,
    pub activation_input: Input,
    pub activation: Transaction,
    pub certificate: OwnerCertificate,
    pub start_revision: u64,
    pub server_salt: Digest,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Mask {
    mask: Digest,
    salt: Digest,
    masked: Digest,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    #[zeroize(skip)]
    context: TransferContext,
    #[zeroize(skip)]
    recovery_context: TransferContext,
    #[zeroize(skip)]
    recovery_path: PathBuf,
    #[zeroize(skip)]
    backing: Input,
    #[zeroize(skip)]
    activation_input: Input,
    activation: String,
    certificate: String,
    server_salt: Digest,
    capability: Digest,
    token: Digest,
    session: Digest,
    recipient: String,
    claim_salt: Digest,
    masked_salt: Digest,
    bridge_salt: Digest,
    reservation: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    batch: Option<BatchManifest>,
    mask: Option<Mask>,
    handover: Option<String>,
    offer: Option<String>,
    offer_digest: Option<Digest>,
    completion: Option<String>,
    #[serde(default)]
    cancellation: Option<String>,
    retired: bool,
    #[serde(default)]
    aborted: bool,
}

pub struct SenderDraft {
    directory: PathBuf,
    record: Record,
    policy: LineagePolicy,
    _lock: ProcessLock,
}
impl SenderDraft {
    pub fn context(&self) -> &TransferContext {
        &self.record.context
    }
    pub fn bind_batch(&mut self, manifest: &BatchManifest) -> Result<()> {
        let mut context = self.record.context.clone();
        context.scope = OperationScope::Batch {
            manifest_digest: manifest.digest()?,
        };
        manifest.index(&context, true)?;
        ensure!(!self.record.aborted, "sender batch was aborted");
        if let Some(saved) = &self.record.batch {
            ensure!(saved == manifest, "sender batch manifest changed");
            return Ok(());
        }
        ensure!(
            self.record.handover.is_none(),
            "sender handover already frozen"
        );
        ensure!(
            self.record.reservation.is_none(),
            "sender reservation belongs to another batch"
        );
        self.record.context = context;
        self.record.batch = Some(manifest.clone());
        self.persist()?;
        Ok(())
    }
    pub fn batch(&self) -> Option<&BatchManifest> {
        self.record.batch.as_ref()
    }
    pub fn has_reservation_mask(&self) -> bool {
        self.record.mask.is_some()
    }
    pub fn is_aborted(&self) -> bool {
        self.record.aborted
    }
    pub(crate) fn has_reservation_request(&self) -> bool {
        self.record.reservation.is_some()
    }
    fn persist(&self) -> Result<()> {
        self.validate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(bytes.len() <= LIMIT, "sender record size");
        atomic_write(&self.directory.join(FILE), &bytes)?;
        check_file(&fs::symlink_metadata(self.directory.join(FILE))?)
    }
    pub fn offer_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_any(
            self.record
                .offer
                .as_ref()
                .context("sender offer not authorized")?,
        )
    }
    pub fn complete(&mut self, client: &dyn SignerClient) -> Result<bool> {
        self.validate()?;
        ensure!(self.record.offer.is_some(), "sender handoff not exported");
        if self.record.retired {
            return Ok(true);
        }
        let request = if let Some(wire) = &self.record.completion {
            cached_completion(&self.record.context, wire)?
        } else {
            let request = Request::sign(
                self.record.context.clone(),
                Command::CompleteSender {},
                &SigningKey::from_bytes(&self.record.session)?,
            )?;
            self.record.completion = Some(hex::encode(&*request.encode()?));
            self.persist()?;
            request
        };
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            completed: bool,
        }
        let response: Reply = serde_json::from_value(client.request(&request)?)
            .map_err(|_| anyhow::anyhow!("invalid sender completion"))?;
        if response.completed {
            self.record.retired = true;
            self.persist()?;
        }
        Ok(response.completed)
    }
}
fn validate_session(secret: &Digest, context: &TransferContext) -> Result<()> {
    let key = SigningKey::from_bytes(secret)?;
    ensure!(
        key.to_bytes()[..] == *secret && key.verifying_key().to_bytes()[..] == context.session_auth,
        "noncanonical sender session"
    );
    Ok(())
}
fn cached_completion(context: &TransferContext, wire: &str) -> Result<Request> {
    let request = Request::decode(&canonical_any(wire)?)?;
    ensure!(
        request.context == *context && matches!(request.command, Command::CompleteSender {}),
        "sender completion cache mismatch"
    );
    Ok(request)
}
fn cached_cancellation(context: &TransferContext, wire: &str) -> Result<Request> {
    let request = Request::decode(&canonical_any(wire)?)?;
    ensure!(
        request.context == *context && matches!(request.command, Command::CancelTransfer {}),
        "sender cancellation cache mismatch"
    );
    Ok(request)
}
fn saved_offer_digest(context: &TransferContext, bytes: &[u8]) -> Result<Digest> {
    Ok(hash(&[
        b"ZARK/private-handoff/saved-offer/v1",
        &context.encode()?,
        bytes,
    ]))
}
// This detects accidental local ciphertext replacement. It is not an ownership
// certificate, sender authentication, or protection from full local rollback.
fn validate_offer_cache(
    context: &TransferContext,
    offer: Option<&str>,
    digest: Option<&Digest>,
) -> Result<()> {
    match (offer, digest) {
        (None, None) => Ok(()),
        (Some(wire), Some(expected)) => {
            let bytes = canonical_any(wire)?;
            ensure!(
                !bytes.is_empty() && saved_offer_digest(context, &bytes)? == *expected,
                "saved sender ciphertext changed"
            );
            Ok(())
        }
        _ => anyhow::bail!("incomplete saved sender ciphertext"),
    }
}
fn canonical_any(value: &str) -> Result<Vec<u8>> {
    let b = hex::decode(value)?;
    ensure!(hex::encode(&b) == value, "noncanonical sender hex");
    Ok(b)
}
fn field(out: &mut String, name: &str, bytes: &[u8]) -> Result<()> {
    out.push_str(name);
    out.push_str(" = ");
    out.push_str(&serde_json::to_string(bytes)?);
    out.push('\n');
    Ok(())
}
fn recursive(out: &mut String, name: &str, bytes: &[u8], count: usize) -> Result<()> {
    ensure!(bytes.len() == count * 32, "recursive sender field size");
    let fields = bytes
        .chunks_exact(32)
        .map(|v| format!("0x{}", hex::encode(v)))
        .collect::<Vec<_>>();
    out.push_str(name);
    out.push_str(" = ");
    out.push_str(&serde_json::to_string(&fields)?);
    out.push('\n');
    Ok(())
}
fn check_directory(p: &Path) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.permissions().mode() & 0o777 == 0o700,
        "sender directory must be private and owned"
    );
    Ok(())
}
fn check_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.permissions().mode() & 0o777 == 0o600,
        "sender file must be private, regular and owned"
    );
    Ok(())
}
fn lock(p: &Path) -> Result<ProcessLock> {
    let path = p.join("sender.lock");
    match fs::symlink_metadata(&path) {
        Ok(m) => check_file(&m)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let l = ProcessLock::acquire(&path)?;
    check_file(&fs::symlink_metadata(path)?)?;
    Ok(l)
}
fn write_new(p: &Path, bytes: &[u8]) -> Result<()> {
    check_directory(p.parent().context("sender witness parent")?)?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::File::open(p.parent().unwrap())?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod cache_tests;
