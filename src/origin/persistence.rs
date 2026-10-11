//! Durable records, restart validation and exact-request persistence.
use super::{FILE, LIMIT, OriginJournal, Record, Slot, bounds, decode};
use anyhow::{Context, Result, ensure};
use k256::Scalar;
use k256::schnorr::SigningKey;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zark_protocol::certificate::IssuedOriginRecord;
use zark_protocol::handoff::origin_previous_state;
use zark_protocol::lineage::LineagePolicy;
use zark_protocol::local::ProcessLock;
use zark_protocol::storage::atomic_write;
use zark_protocol::wire::{Command, MAX_WIRE, Request};
use zark_protocol::{point, scalar};
use zeroize::Zeroizing;

impl OriginJournal {
    pub fn open(directory: &Path, policy: &LineagePolicy) -> Result<Self> {
        check_directory(directory)?;
        let lock = lock(directory)?;
        let bytes = read_private(&directory.join(FILE), LIMIT)?;
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private origin journal"))?;
        validate(&record, policy)?;
        let journal = Self {
            directory: directory.into(),
            record,
            policy: policy.clone(),
            _lock: lock,
        };
        journal.validate_drafts()?;
        zark_protocol::storage::sync_observed(&fs::File::open(directory.join(FILE))?, directory)?;
        Ok(journal)
    }

    pub(super) fn sign(&self, command: Command) -> Result<Request> {
        Request::sign(
            self.record.context.clone(),
            command,
            &SigningKey::from_bytes(&self.record.session)?,
        )
    }

    pub(super) fn saved(&self, raw: &str) -> Result<Request> {
        let r = Request::decode(&decode(raw, MAX_WIRE)?)?;
        ensure!(
            r.context == self.record.context,
            "origin saved request context mismatch"
        );
        Ok(r)
    }

    pub(super) fn freeze(&mut self, slot: Slot, command: Command) -> Result<Request> {
        let request = self.sign(command)?;
        let encoded = hex::encode(&*request.encode()?);
        let place = match slot {
            Slot::Prepare => &mut self.record.requests.prepare,
            Slot::Authorize => &mut self.record.requests.authorize,
            Slot::Recovery => &mut self.record.requests.recovery,
            Slot::Issue => &mut self.record.requests.issue,
            Slot::Accept => &mut self.record.requests.accept,
        };
        if let Some(saved) = place {
            let old = Request::decode(&decode(saved, MAX_WIRE)?)?;
            ensure!(
                old.context == request.context
                    && *old.command.body()? == *request.command.body()?,
                "origin request already frozen differently"
            );
            return Ok(old);
        }
        *place = Some(encoded);
        self.persist()?;
        Ok(request)
    }

    pub(super) fn validate_drafts(&self) -> Result<()> {
        ensure!(
            self.record.requests.prepare.is_none()
                || self.directory.join("activation").try_exists()?,
            "frozen activation draft missing"
        );
        ensure!(
            self.record.requests.recovery.is_none()
                || self.directory.join("own-recovery").try_exists()?,
            "frozen initial recovery missing"
        );
        if self.record.funding.is_some() && self.directory.join("activation").try_exists()? {
            let draft = self.ensure_bootstrap()?;
            if let Some(saved) = &self.record.requests.prepare {
                let (f, a, cap, n) = draft.commitments()?;
                match self.saved(saved)?.command {
                    Command::BootstrapPrepare {
                        parent_funding,
                        active_funding,
                        capability,
                        blinding,
                    } => ensure!(
                        (parent_funding, active_funding, capability, blinding) == (f, a, cap, n),
                        "saved parent preparation differs from private draft"
                    ),
                    _ => anyhow::bail!("wrong saved parent preparation"),
                }
            }
        }
        if self.record.parent_nonce.is_some() {
            self.bootstrap_binding()?;
        }
        if let Some(saved) = &self.record.requests.authorize {
            match self.saved(saved)?.command {
                Command::BootstrapFreeze { statement, .. } => ensure!(
                    statement == self.bootstrap_binding()?.encode()?,
                    "saved parent authorization differs from private draft"
                ),
                _ => anyhow::bail!("wrong saved parent authorization"),
            }
        }
        if self.directory.join("own-recovery").try_exists()? {
            let draft = self.ensure_recovery()?;
            if let Some(saved) = &self.record.requests.recovery {
                let commitments = draft.commitments()?;
                match self.saved(saved)?.command {
                    Command::Prepare { recovery, blinding } => ensure!(
                        recovery == commitments.recovery && blinding == commitments.blinding,
                        "saved recovery preparation differs from private draft"
                    ),
                    _ => anyhow::bail!("wrong saved recovery preparation"),
                }
            }
            if let Some(nonce) = &self.record.recovery_nonce {
                ensure!(
                    draft.signing_binding()?.server_nonce.as_slice() == nonce,
                    "recovery nonce changed"
                );
            }
            if let Some(saved) = &self.record.requests.issue {
                match self.saved(saved)?.command {
                    Command::IssueDeposit { statement, .. } => ensure!(
                        statement == self.deposit_binding_with_recovery(&draft)?.encode()?,
                        "saved origin issuance differs from private draft"
                    ),
                    _ => anyhow::bail!("wrong saved origin issuance"),
                }
            }
            if let Some(issued) = &self.record.issued {
                let (binding, partial) = draft.completion_binding()?;
                ensure!(
                    partial == issued.partial
                        && self.deposit_binding_with_recovery(&draft)?.digest()? == issued.binding
                        && binding.next_capability == issued.capability
                        && self.lineage_binding(&draft)?.state == issued.state,
                    "origin issued record changed"
                );
            }
        }
        if let Some(accepted) = &self.record.accepted {
            self.require_attached()?;
            let issued = self
                .record
                .issued
                .as_ref()
                .context("deposit issuance missing")?;
            let request = self.saved(
                self.record
                    .requests
                    .issue
                    .as_ref()
                    .context("deposit request missing")?,
            )?;
            let identity = IssuedOriginRecord::from_request(
                &request,
                &self.deposit_binding()?,
                issued.partial,
                accepted.activation_partial,
                self.allocation()?.salt,
                issued.state,
                accepted.origin_signature.clone(),
            )?;
            ensure!(
                identity.identity()? == issued.identity,
                "saved deposit identity changed"
            );
        }
        if self.record.acknowledged {
            let issued = self
                .record
                .issued
                .as_ref()
                .context("deposit issuance missing")?;
            let request = self.saved(
                self.record
                    .requests
                    .accept
                    .as_ref()
                    .context("deposit acknowledgement missing")?,
            )?;
            ensure!(
                matches!(request.command, Command::AcceptOrigin { state, issuance_identity } if state == issued.state && issuance_identity == issued.identity),
                "saved deposit acknowledgement changed"
            );
        }
        Ok(())
    }

    pub(super) fn persist(&self) -> Result<()> {
        validate(&self.record, &self.policy)?;
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(bytes.len() <= LIMIT, "origin journal too large");
        atomic_write(&self.directory.join(FILE), &bytes)?;
        Ok(())
    }
}

pub(super) fn validate(r: &Record, policy: &LineagePolicy) -> Result<()> {
    ensure!(
        r.schema == "zark-origin" && r.version == 3,
        "unsupported origin journal"
    );
    policy.validate()?;
    policy.require(&r.context.deployment, &r.policy, &r.origin, &r.roles)?;
    r.context.encode()?;
    ensure!(
        r.context.previous_state == origin_previous_state(&r.context.deployment, &r.context.coin)?
            && r.context.start_revision == 0
            && r.context.scope == zark_protocol::handoff::OperationScope::Single,
        "origin predecessor changed"
    );
    ensure!(
        SigningKey::from_bytes(&r.session)?
            .verifying_key()
            .to_bytes()[..]
            == r.context.session_auth,
        "origin session changed"
    );
    for secret in [&r.parent_user, &r.active_user, &r.payout] {
        ensure!(scalar(secret)? != Scalar::ZERO, "zero origin key");
    }
    zark_protocol::owner_auth::normalized_key(&r.capability)?;
    bounds(r.amount, r.activation_fee, r.recovery_fee)?;
    let alloc = Request::decode(&decode(&r.requests.allocate, MAX_WIRE)?)?;
    ensure!(
        alloc.context == r.context && matches!(alloc.command, Command::BootstrapAllocate {}),
        "wrong origin allocation request"
    );
    if let Some(a) = &r.allocation {
        point(&a.parent)?;
        point(&a.active)?;
        ensure!(
            a.parent == a.active && r.parent_user == r.active_user && a.salt != [0; 32],
            "invalid origin allocation"
        );
    }
    ensure!(
        r.funding.is_none() || r.allocation.is_some(),
        "funding before allocation"
    );
    ensure!(
        r.parent_nonce.is_none() || (r.funding.is_some() && r.requests.prepare.is_some()),
        "parent nonce before preparation"
    );
    ensure!(
        !r.parent_authorized || (r.parent_nonce.is_some() && r.requests.authorize.is_some()),
        "parent held without authorization"
    );
    ensure!(
        r.recovery_nonce.is_none() || (r.parent_authorized && r.requests.recovery.is_some()),
        "recovery nonce before held parent"
    );
    ensure!(
        r.issued.is_none() || (r.recovery_nonce.is_some() && r.requests.issue.is_some()),
        "recovery receipt before issuance"
    );
    ensure!(
        r.accepted.is_none() || r.issued.is_some(),
        "parent released before recovery"
    );
    ensure!(
        r.certificate.is_none() || (r.accepted.is_some() && r.acknowledged),
        "certificate before parent release"
    );
    ensure!(
        !r.acknowledged || (r.accepted.is_some() && r.requests.accept.is_some()),
        "deposit acknowledgement without saved recovery"
    );
    ensure!(
        !r.funding_broadcast || r.certificate.is_some(),
        "funding broadcast before certificate"
    );
    ensure!(
        r.outgoing.is_none() || (r.certificate.is_some() && r.funding_broadcast),
        "outgoing operation before funded origin"
    );
    ensure!(
        r.requests.prepare.is_none() || r.funding.is_some(),
        "parent preparation before funding"
    );
    ensure!(
        r.requests.authorize.is_none() || r.parent_nonce.is_some(),
        "parent authorization before nonce"
    );
    ensure!(
        r.requests.recovery.is_none() || r.parent_authorized,
        "recovery preparation before held parent"
    );
    ensure!(
        r.requests.issue.is_none() || r.recovery_nonce.is_some(),
        "origin issuance before recovery nonce"
    );
    ensure!(
        r.requests.accept.is_none() || r.issued.is_some(),
        "origin acceptance before completed recovery"
    );
    for (slot, raw) in [
        (0, &r.requests.prepare),
        (1, &r.requests.authorize),
        (2, &r.requests.recovery),
        (3, &r.requests.issue),
        (4, &r.requests.accept),
    ] {
        if let Some(raw) = raw {
            let request = Request::decode(&decode(raw, MAX_WIRE)?)?;
            ensure!(
                request.context == r.context,
                "origin request context changed"
            );
            ensure!(
                match slot {
                    0 => matches!(request.command, Command::BootstrapPrepare { .. }),
                    1 => matches!(request.command, Command::BootstrapFreeze { .. }),
                    2 => matches!(request.command, Command::Prepare { .. }),
                    3 => matches!(request.command, Command::IssueDeposit { .. }),
                    _ => matches!(request.command, Command::AcceptOrigin { .. }),
                },
                "wrong origin request role"
            );
        }
    }
    Ok(())
}

pub(super) fn operation_path(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "outgoing origin path must be absolute");
    let parent = path
        .parent()
        .context("outgoing origin parent")?
        .canonicalize()?;
    check_directory(&parent)?;
    Ok(parent.join(path.file_name().context("outgoing origin name")?))
}

pub(super) fn check_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700,
        "origin directory must be private and owned"
    );
    Ok(())
}

pub(super) fn check_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o600,
        "origin file must be private and owned"
    );
    Ok(())
}

pub(super) fn lock(path: &Path) -> Result<ProcessLock> {
    check_directory(path)?;
    let p = path.join("origin.lock");
    if p.try_exists()? {
        check_file(&fs::symlink_metadata(&p)?)?;
    }
    let lock = ProcessLock::acquire(&p)?;
    check_file(&fs::symlink_metadata(&p)?)?;
    Ok(lock)
}

pub(super) fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    check_directory(path.parent().context("origin file parent")?)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    check_file(&file.metadata()?)?;
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "origin file size");
    Ok(bytes)
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    check_directory(path.parent().context("origin witness parent")?)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
