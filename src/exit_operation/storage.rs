//! Private exit record loading, validation and durable persistence.
use super::ExitOperation;
use crate::{common, types::Input};
use anyhow::{Context, Result, ensure};
use bitcoin::{
    Transaction,
    consensus::{deserialize, serialize},
};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};
use zark_protocol::{
    certificate::PredecessorKind,
    exit,
    handoff::{Digest, TransferContext},
    lineage::{IssuanceBinding, LineagePolicy},
    local::ProcessLock,
    storage::atomic_write,
    wire::{Command, Request},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub(super) version: u32,
    #[zeroize(skip)]
    pub(super) head_context: TransferContext,
    pub(super) head_session: Digest,
    #[zeroize(skip)]
    pub(super) context: TransferContext,
    pub(super) session: Digest,
    #[zeroize(skip)]
    pub(super) backing: Input,
    #[zeroize(skip)]
    pub(super) activation_input: Input,
    pub(super) activation: String,
    pub(super) certificate: String,
    #[zeroize(skip)]
    pub(super) predecessor: PredecessorKind,
    pub(super) capability: Digest,
    pub(super) server_share: Digest,
    pub(super) destination: Digest,
    pub(super) fee: u64,
    pub(super) prepare: Option<String>,
    pub(super) issue: Option<String>,
    pub(super) terminal: bool,
}
impl ExitOperation {
    pub fn open(directory: &Path, policy: &LineagePolicy) -> Result<Self> {
        check_directory(directory)?;
        let lock = lock(directory)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join("exit-operation.json"))?;
        check_file(&file.metadata()?)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file).take(800_001).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 800_000, "exit operation size");
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid exit operation"))?;
        let result = Self {
            directory: directory.into(),
            record,
            policy: policy.clone(),
            _lock: lock,
        };
        result.validate()?;
        zark_protocol::storage::sync_observed(&file, directory)?;
        Ok(result)
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(self.record.version == 3, "exit operation version");
        exit::validate_context(&self.record.context)?;
        self.record.head_context.encode()?;
        let previous_session = SigningKey::from_bytes(&self.record.head_session)?;
        ensure!(
            previous_session.to_bytes()[..] == self.record.head_session
                && previous_session.verifying_key().to_bytes()[..]
                    == self.record.head_context.session_auth
                && self.record.head_context.deployment == self.record.context.deployment
                && self.record.head_context.coin == self.record.context.coin,
            "invalid current-owner exit head session"
        );
        let cert = self.current()?;
        self.policy.require(
            &cert.deployment,
            &cert.policy,
            &cert.origin_key,
            &cert.role_hashes,
        )?;
        ensure!(
            cert.coin == self.record.context.coin
                && cert.state == self.record.context.previous_state,
            "exit operation state mismatch"
        );
        let session = SigningKey::from_bytes(&self.record.session)?;
        ensure!(
            session.to_bytes()[..] == self.record.session
                && session.verifying_key().to_bytes()[..] == self.record.context.session_auth,
            "noncanonical exit session"
        );
        let tx: Transaction = deserialize(&decode_any(&self.record.activation)?)?;
        ensure!(
            hex::encode(serialize(&tx)) == self.record.activation,
            "noncanonical exit common transaction"
        );
        ensure!(
            common::validate(
                &cert.deployment,
                &cert.coin,
                &self.record.backing,
                &self.record.activation_input,
                &tx
            )?
            .commitment()?
                == cert.funding,
            "exit common backing mismatch"
        );
        let draft = self.draft()?;
        draft.require_destination(&self.record.destination, self.record.fee)?;
        ensure!(
            draft.commitments()?.0 == cert.funding
                && draft.owner_commitments()? == (self.record.capability, self.record.server_share),
            "exit owner opening changed"
        );
        ensure!(
            self.certificate()?.kind() == self.record.predecessor,
            "exit predecessor kind mismatch"
        );
        if let Some(request) = &self.record.prepare {
            let request = Request::decode(&decode_any(request)?)?;
            ensure!(
                request.context == self.record.context,
                "exit preparation context"
            );
            let (funding, exit, blinding) = draft.commitments()?;
            match request.command {
                Command::ExitPrepare {
                    funding: f,
                    server_share,
                    capability,
                    exit: e,
                    blinding: b,
                    owner_authorization,
                } => {
                    ensure!(
                        f == funding
                            && e == exit
                            && b == blinding
                            && server_share == self.record.server_share
                            && capability == self.record.capability,
                        "exit preparation changed"
                    );
                    owner_authorization.verify_exit(
                        &request.context,
                        &capability,
                        &funding,
                        &server_share,
                        &exit,
                        &blinding,
                    )?;
                }
                _ => anyhow::bail!("wrong saved exit preparation"),
            }
        }
        if let Some(request) = &self.record.issue {
            ensure!(
                self.record.prepare.is_some(),
                "exit issue before preparation"
            );
            let request = Request::decode(&decode_any(request)?)?;
            ensure!(
                request.context == self.record.context,
                "exit issuance context"
            );
            let binding = IssuanceBinding {
                signing: draft.signing_binding()?,
                policy: cert.policy,
                origin_key: self.policy.origin_key,
                role_hashes: self.policy.role_hashes,
            };
            match request.command {
                Command::ExitIssue {
                    predecessor,
                    statement,
                    ..
                } => {
                    ensure!(
                        predecessor == self.record.predecessor && statement == binding.encode()?,
                        "exit issuance changed"
                    )
                }
                _ => anyhow::bail!("wrong saved exit issuance"),
            }
        }
        ensure!(
            !self.record.terminal || self.record.issue.is_some(),
            "terminal exit without saved request"
        );
        if self.record.terminal {
            draft.completed_transaction()?;
        }
        Ok(())
    }
    pub(super) fn persist(&self) -> Result<()> {
        self.validate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(bytes.len() <= 800_000, "exit operation size");
        atomic_write(&self.directory.join("exit-operation.json"), &bytes)
    }
}

pub(super) fn decode_any(text: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(text)?;
    ensure!(hex::encode(&bytes) == text, "noncanonical exit encoding");
    Ok(bytes)
}
pub(super) fn check_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700,
        "exit operation directory must be private"
    );
    Ok(())
}
fn check_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o600,
        "exit operation file must be private"
    );
    Ok(())
}
pub(super) fn lock(directory: &Path) -> Result<ProcessLock> {
    let path = directory.join(".lock");
    if path.try_exists()? {
        check_file(&fs::symlink_metadata(&path)?)?;
    }
    let lock = ProcessLock::acquire(&path)?;
    check_file(&fs::symlink_metadata(path)?)?;
    Ok(lock)
}

pub(super) fn create_directory(directory: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    check_directory(directory)?;
    fs::File::open(directory.parent().context("exit operation parent")?)?.sync_all()?;
    Ok(())
}
