//! Bounded reads for authenticated, public deployment assets.
//!
//! Configured public symlinks (for example Homebrew executables and CRS caches)
//! are resolved before opening a regular file. This is not a private-key reader
//! or a defense against another process running as the same operating-system
//! user. Callers must still compare the exact bytes or digest to their trusted
//! deployment pin.
use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
mod authenticated;
pub(crate) use authenticated::AuthenticatedFile;

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_CIRCUIT_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_CRS_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const VK_BYTES: usize = 115 * 32;
pub const MAX_VK_METADATA_BYTES: usize = 16 * 1024;

/// Barretenberg creates this empty runtime lock beside the pinned CRS data.
/// It is not a proof asset. Never exempt links, writable shared files or data.
pub fn is_crs_runtime_lock(path: &Path) -> Result<bool> {
    if path.file_name() != Some(std::ffi::OsStr::new("crs.lock")) {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.len() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0,
        "invalid CRS runtime lock"
    );
    Ok(true)
}

#[test]
fn crs_runtime_lock_accepts_only_empty_regular_unshared_lock() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root =
        std::env::temp_dir().join(format!("zark-crs-lock-{}", hex::encode(crate::random32())));
    fs::create_dir(&root)?;
    let lock = root.join("crs.lock");
    fs::write(&lock, [])?;
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
    assert!(is_crs_runtime_lock(&lock)?);
    assert!(!is_crs_runtime_lock(&root.join("other.lock"))?);
    fs::write(&lock, b"not runtime metadata")?;
    assert!(is_crs_runtime_lock(&lock).is_err());
    fs::write(&lock, [])?;
    fs::hard_link(&lock, root.join("alias"))?;
    assert!(is_crs_runtime_lock(&lock).is_err());
    fs::remove_file(&lock)?;
    symlink(root.join("alias"), &lock)?;
    assert!(is_crs_runtime_lock(&lock).is_err());
    fs::remove_dir_all(root)?;
    Ok(())
}

fn open_regular(path: &Path, limit: u64) -> Result<(File, fs::Metadata)> {
    ensure!(limit < u64::MAX, "public asset limit overflow");
    let resolved = path.canonicalize()?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(resolved)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "public asset must be a regular file");
    ensure!(metadata.len() <= limit, "public asset exceeds size limit");
    Ok((file, metadata))
}

fn unchanged(file: &File, before: &fs::Metadata, length: u64) -> Result<()> {
    let after = file.metadata()?;
    ensure!(
        length == before.len()
            && length == after.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "public asset changed while reading"
    );
    Ok(())
}

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let (file, before) = open_regular(path, u64::try_from(limit)?)?;
    read_opened(&file, &before, limit)
}

fn read_opened(file: &File, before: &fs::Metadata, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit)? + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "public asset exceeds size limit");
    unchanged(file, before, bytes.len() as u64)?;
    Ok(bytes)
}

/// SHA256 over the exact file contents, with fixed 64-KiB working storage.
/// Metadata and the streamed byte count are both bounded; a growing file does
/// not evade the limit checked before reading.
pub fn sha256_bounded(path: &Path, limit: u64) -> Result<[u8; 32]> {
    let (file, before) = open_regular(path, limit)?;
    hash_opened(&file, &before, limit)
}

fn hash_opened(file: &File, before: &fs::Metadata, limit: u64) -> Result<[u8; 32]> {
    let mut reader = file.take(limit + 1);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut length = 0u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length += count as u64;
        ensure!(length <= limit, "public asset exceeds size limit");
        digest.update(&buffer[..count]);
    }
    unchanged(file, before, length)?;
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CString, os::unix::fs::symlink};

    fn directory() -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("zark-assets-{}", hex::encode(crate::random32())));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn streamed_hash_matches_exact_bytes_and_resolves_public_links() {
        let root = directory();
        let path = root.join("asset");
        let bytes: Vec<u8> = (0..150_001).map(|n| (n % 251) as u8).collect();
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read_bounded(&path, bytes.len()).unwrap(), bytes);
        assert_eq!(
            sha256_bounded(&path, bytes.len() as u64).unwrap(),
            crate::hash(&[&bytes])
        );
        symlink(&path, root.join("configured-link")).unwrap();
        assert_eq!(
            sha256_bounded(&root.join("configured-link"), bytes.len() as u64).unwrap(),
            crate::hash(&[&bytes])
        );
        assert!(read_bounded(&path, bytes.len() - 1).is_err());
        assert!(sha256_bounded(&path, bytes.len() as u64 - 1).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_sparse_files_and_special_files_fail_before_reading() {
        let root = directory();
        let path = root.join("oversized");
        File::create(&path)
            .unwrap()
            .set_len(MAX_CRS_BYTES + 1)
            .unwrap();
        assert!(read_bounded(&path, MAX_CONFIG_BYTES).is_err());
        assert!(sha256_bounded(&path, MAX_CRS_BYTES).is_err());
        assert!(read_bounded(&root, MAX_CONFIG_BYTES).is_err());
        let fifo = root.join("fifo");
        let c_path = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // Synthetic FIFO verifies that the nonblocking open cannot hang before
        // the regular-file check. No writer process is started.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(read_bounded(&fifo, 10).is_err());
        assert!(sha256_bounded(&fifo, 10).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
