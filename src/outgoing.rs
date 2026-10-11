//! Atomic publication of an owner-local outgoing journal. Constructors here
//! must not contact a signer or return an unpublished child to another caller.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs,
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
use zark_protocol::{local::ProcessLock, random32, storage::atomic_write};

const PREFIX: &str = ".zark-outgoing-";
const RECEIPT: &str = "initialization.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    attempt: String,
    complete: bool,
}

/// Choose a private staging location without creating anything. The owning
/// journal must durably save this exact path and final operation intent first.
pub(crate) fn new_staging_path(destination: &Path) -> Result<PathBuf> {
    ensure!(
        destination.to_str().is_some(),
        "outgoing destination must have a UTF-8 path"
    );
    let parent = destination
        .parent()
        .context("outgoing destination parent")?;
    check_directory(parent)?;
    loop {
        let path = parent.join(format!("{PREFIX}{}", hex::encode(random32())));
        if missing(&path)? {
            return Ok(path);
        }
    }
}

/// The owner journal's lock must remain held throughout this operation. `create`
/// and `open_validate` operate only on local files, and must fully validate the
/// expected owner and intent. The returned object always points at destination.
pub(crate) fn initialize_outgoing<T>(
    destination: &Path,
    staging: &Path,
    create: impl FnOnce(&Path) -> Result<T>,
    mut open_validate: impl FnMut(&Path) -> Result<T>,
) -> Result<T> {
    validate_paths(destination, staging)?;
    if missing(staging)? {
        fs::DirBuilder::new().mode(0o700).create(staging)?;
        sync_parent(staging)?;
    }
    check_directory(staging)?;
    let lock_path = staging.join("initialization.lock");
    if !missing(&lock_path)? {
        check_file(&fs::symlink_metadata(&lock_path)?)?;
    }
    let _lock = ProcessLock::acquire(&lock_path)?;
    check_file(&fs::symlink_metadata(&lock_path)?)?;
    let mut receipt = read_receipt(staging)?;
    if !missing(destination)? {
        let r = receipt
            .as_ref()
            .context("outgoing destination exists without completion receipt")?;
        ensure!(
            r.complete && missing(&staging.join(&r.attempt))?,
            "ambiguous outgoing publication"
        );
        sync_parent(destination)?;
        fs::File::open(staging)?.sync_all()?;
        // ProcessLock tracks the currently nested lock for child processes.
        // Release the staging scope before returning a new child journal lock.
        drop(_lock);
        return open_validate(destination);
    }
    if let Some(r) = &receipt {
        let attempt = staging.join(&r.attempt);
        if r.complete {
            ensure!(
                !missing(&attempt)?,
                "published outgoing child is missing; refusing regeneration"
            );
            check_directory(&attempt)?;
            drop(open_validate(&attempt)?);
        } else if !missing(&attempt)? {
            check_directory(&attempt)?;
            if let Ok(candidate) = open_validate(&attempt) {
                drop(candidate);
                receipt.as_mut().unwrap().complete = true;
                write_receipt(staging, receipt.as_ref().unwrap())?;
            } else {
                // No child was published or returned, so this incomplete local
                // construction cannot have sent a signing request. Retain it.
                receipt = None;
            }
        }
    }
    if receipt.is_none() {
        receipt = Some(Receipt {
            version: 1,
            attempt: format!("attempt-{}", hex::encode(random32())),
            complete: false,
        });
        write_receipt(staging, receipt.as_ref().unwrap())?;
    }
    let r = receipt.as_mut().unwrap();
    let attempt = staging.join(&r.attempt);
    if !r.complete {
        ensure!(
            missing(&attempt)?,
            "incomplete outgoing attempt unexpectedly exists"
        );
        drop(create(&attempt)?);
        check_directory(&attempt)?;
        drop(open_validate(&attempt)?);
        fs::File::open(&attempt)?.sync_all()?;
        r.complete = true;
        write_receipt(staging, r)?;
    }
    rename_new(&attempt, destination)?;
    // The rename crosses two directories on the same filesystem.
    fs::File::open(staging)?.sync_all()?;
    sync_parent(destination)?;
    drop(_lock);
    open_validate(destination)
}

fn validate_paths(destination: &Path, staging: &Path) -> Result<()> {
    ensure!(
        destination.is_absolute() && staging.is_absolute() && destination != staging,
        "outgoing paths must be distinct and absolute"
    );
    let parent = destination.parent().context("outgoing parent")?;
    ensure!(
        staging.parent() == Some(parent) && parent.canonicalize()? == parent,
        "outgoing stage must share canonical destination parent"
    );
    check_directory(parent)?;
    let name = staging
        .file_name()
        .and_then(|n| n.to_str())
        .context("outgoing stage name")?;
    ensure!(
        generated_name(name, PREFIX),
        "outgoing stage is not a generated private path"
    );
    ensure!(
        destination.file_name().is_some(),
        "outgoing destination name missing"
    );
    Ok(())
}
fn generated_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn missing(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn check_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700,
        "outgoing directory must be private and owned"
    );
    Ok(())
}
fn check_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o600,
        "outgoing receipt must be private and owned"
    );
    Ok(())
}
fn sync_parent(path: &Path) -> Result<()> {
    fs::File::open(path.parent().context("outgoing parent")?)?.sync_all()?;
    Ok(())
}
fn read_receipt(staging: &Path) -> Result<Option<Receipt>> {
    let path = staging.join(RECEIPT);
    if missing(&path)? {
        return Ok(None);
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    check_file(&file.metadata()?)?;
    let mut bytes = Vec::new();
    (&mut file).take(1025).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024, "outgoing receipt size");
    let r: Receipt = serde_json::from_slice(&bytes)?;
    ensure!(
        r.version == 1 && generated_name(&r.attempt, "attempt-"),
        "outgoing receipt version or attempt"
    );
    Ok(Some(r))
}
fn write_receipt(staging: &Path, r: &Receipt) -> Result<()> {
    atomic_write(&staging.join(RECEIPT), &serde_json::to_vec(r)?)?;
    check_file(&fs::symlink_metadata(staging.join(RECEIPT))?)?;
    Ok(())
}
fn rename_new(source: &Path, destination: &Path) -> Result<()> {
    let old = CString::new(source.as_os_str().as_bytes())?;
    let new = CString::new(destination.as_os_str().as_bytes())?;
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            old.as_ptr(),
            libc::AT_FDCWD,
            new.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            old.as_ptr(),
            libc::AT_FDCWD,
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    anyhow::bail!("atomic outgoing publication is unsupported on this platform");
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, io::Write};
    struct Home(PathBuf);
    impl Home {
        fn new() -> Self {
            let p = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("zark-outgoing-test-{}", hex::encode(random32())));
            fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn create(path: &Path) -> Result<String> {
        fs::DirBuilder::new().mode(0o700).create(path)?;
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path.join("record"))?;
        f.write_all(b"exact completed operation")?;
        f.sync_all()?;
        open(path)
    }
    fn open(path: &Path) -> Result<String> {
        check_directory(path)?;
        let s = fs::read_to_string(path.join("record"))?;
        ensure!(s == "exact completed operation", "incomplete child");
        Ok(s)
    }
    #[test]
    fn retries_partial_creation_without_returning_or_deleting_unpublished_child() -> Result<()> {
        let home = Home::new();
        let target = home.0.join("child");
        let stage = new_staging_path(&target)?;
        let failed = initialize_outgoing::<String>(
            &target,
            &stage,
            |p| {
                fs::DirBuilder::new().mode(0o700).create(p)?;
                anyhow::bail!("crash before child record")
            },
            open,
        );
        assert!(failed.is_err());
        assert!(!target.exists());
        let original = read_receipt(&stage)?.unwrap().attempt;
        assert_eq!(
            initialize_outgoing(&target, &stage, create, open)?,
            "exact completed operation"
        );
        assert!(stage.join(original).is_dir());
        assert_eq!(
            initialize_outgoing(
                &target,
                &stage,
                |_| anyhow::bail!("must not reconstruct"),
                open
            )?,
            "exact completed operation"
        );
        Ok(())
    }
    #[test]
    fn reuses_complete_pending_child_and_survives_publication_before_reply() -> Result<()> {
        let home = Home::new();
        let target = home.0.join("child");
        let stage = new_staging_path(&target)?;
        assert!(
            initialize_outgoing::<String>(
                &target,
                &stage,
                |p| {
                    create(p)?;
                    anyhow::bail!("crash after durable child")
                },
                open
            )
            .is_err()
        );
        let original = read_receipt(&stage)?.unwrap().attempt;
        let opens = Cell::new(0);
        assert!(
            initialize_outgoing(
                &target,
                &stage,
                |_| anyhow::bail!("must reuse durable child"),
                |p| {
                    opens.set(opens.get() + 1);
                    if p == target {
                        anyhow::bail!("crash after atomic publication");
                    }
                    open(p)
                }
            )
            .is_err()
        );
        assert!(target.exists());
        assert!(!stage.join(&original).exists());
        assert!(opens.get() > 0);
        assert_eq!(
            initialize_outgoing(
                &target,
                &stage,
                |_| anyhow::bail!("must not reconstruct"),
                open
            )?,
            "exact completed operation"
        );
        fs::rename(&target, home.0.join("retained-published-child"))?;
        assert!(initialize_outgoing(&target, &stage, create, open).is_err());
        assert!(!target.exists());
        Ok(())
    }
    #[test]
    fn never_replaces_existing_destination_or_accepts_foreign_stage() -> Result<()> {
        let home = Home::new();
        let target = home.0.join("child");
        let stage = new_staging_path(&target)?;
        create(&target)?;
        assert!(initialize_outgoing(&target, &stage, create, open).is_err());
        assert_eq!(open(&target)?, "exact completed operation");
        let alternate = home.0.join("alternate");
        assert!(initialize_outgoing(&alternate, &home.0.join("arbitrary"), create, open).is_err());
        let source = home.0.join("source");
        create(&source)?;
        assert!(rename_new(&source, &target).is_err());
        assert!(source.exists());
        assert_eq!(open(&target)?, "exact completed operation");
        Ok(())
    }
}
