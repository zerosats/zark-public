//! Private CLI metadata and crash-safe local operation initialization.
use super::Metadata;
use anyhow::{Context, Result, ensure};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zark_protocol::hash;
use zark_protocol::local::ProcessLock;
use zeroize::Zeroizing;

pub(super) fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = path.parent().context("path parent")?.canonicalize()?;
    Ok(parent.join(path.file_name().context("path file name")?))
}

pub(super) fn read_metadata(path: &Path) -> Result<Metadata> {
    private_directory(path)?;
    serde_json::from_slice(&read_private(&path.join("operation.json"), 100_000)?)
        .map_err(|_| anyhow::anyhow!("invalid operation metadata"))
}

pub(super) fn initialize_metadata(path: &Path, expected: &Metadata) -> Result<Metadata> {
    initialize_cli_local(
        path,
        &serde_json::to_vec(expected)?,
        |attempt| {
            new_directory(attempt)?;
            write_new(
                &attempt.join("operation.json"),
                &serde_json::to_vec(expected)?,
            )?;
            new_directory(&attempt.join("proofs"))?;
            new_directory(&attempt.join("verify"))?;
            Ok(expected.clone())
        },
        |published| {
            let saved = read_metadata(published)?;
            ensure!(
                saved == *expected,
                "operation parameters are already frozen"
            );
            for child in ["proofs", "verify"] {
                private_directory(&published.join(child))?;
            }
            Ok(saved)
        },
    )
}

pub(super) fn initialization_path(destination: &Path) -> Result<PathBuf> {
    let parent = destination.parent().context("initialization parent")?;
    ensure!(
        destination.is_absolute() && parent.canonicalize()? == parent,
        "initialization requires an absolute path with canonical parent"
    );
    private_directory(parent)?;
    let encoded = destination
        .to_str()
        .context("initialization path must be UTF-8")?;
    Ok(parent.join(format!(
        ".zark-outgoing-{}",
        hex::encode(hash(&[
            b"ZARK/cli-local-initialization/v1",
            encoded.as_bytes()
        ]))
    )))
}

/// Constructors are strictly local and must not release an unpublished object
/// to a signer caller. The stable staging path recovers the exact local intent;
/// incomplete attempts stay private and are never mistaken for active journals.
pub(super) fn initialize_cli_local<T>(
    destination: &Path,
    intent: &[u8],
    create: impl FnOnce(&Path) -> Result<T>,
    mut validate: impl FnMut(&Path) -> Result<T>,
) -> Result<T> {
    if destination.try_exists()? {
        return validate(destination);
    }
    let staging = initialization_path(destination)?;
    if !staging.try_exists()? {
        new_directory(&staging)?;
    }
    private_directory(&staging)?;
    let _lock = ProcessLock::acquire(&staging.join(".cli-intent.lock"))?;
    let saved = staging.join("intent.json");
    if saved.try_exists()? {
        ensure!(
            *read_private(&saved, 100_000)? == intent,
            "initialization intent already frozen"
        );
    } else {
        zark_protocol::storage::atomic_write(&saved, intent)?;
    }
    // The shared helper owns its own scope. Release the intent lock before
    // returning a native journal, so subprocess lock tracking follows that child.
    drop(_lock);
    crate::outgoing::initialize_outgoing(destination, &staging, create, validate)
}
pub(super) fn new_directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    fs::File::open(path.parent().context("directory parent")?)?.sync_all()?;
    Ok(())
}
pub(super) fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700,
        "operation directory must be private (0700)"
    );
    Ok(())
}
pub(super) fn read_bounded(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "expected a regular file");
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input file too large");
    Ok(bytes)
}
pub(super) fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o600,
        "private file must have mode 0600 and one link"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "private input file too large");
    Ok(bytes)
}
pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().context("file parent")?)?.sync_all()?;
    Ok(())
}
pub(super) fn write_exact(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.try_exists()? {
        ensure!(
            *read_private(path, 4_000_000)? == bytes,
            "existing output differs; refusing to replace it"
        );
        Ok(())
    } else {
        write_new(path, bytes)
    }
}
