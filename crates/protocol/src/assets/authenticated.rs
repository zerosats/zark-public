//! Process-local authentication of a retained public asset, never persisted.
//! Replacements and edits invalidate the lifetime; a changed asset must be
//! authenticated by a new verifier. Every check compares the full contents to
//! immutable, SHA256-authenticated bytes; timestamps alone cannot detect edits
//! within one filesystem clock tick. Like the bounded reader, this is not an
//! OS sandbox against the same user or root.
use super::{open_regular, read_opened};
use anyhow::{Result, ensure};
use std::{
    fs::{self, File},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    owner: (u32, u32),
    links: u64,
}
impl Identity {
    fn read(m: &fs::Metadata) -> Result<Self> {
        ensure!(m.is_file(), "authenticated asset is not a regular file");
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
            mode: m.mode(),
            owner: (m.uid(), m.gid()),
            links: m.nlink(),
        })
    }
}

pub(crate) struct AuthenticatedFile {
    target: PathBuf,
    // Retaining the authenticated inode prevents inode reuse from making a
    // replacement look like the original file. Paths alone are insufficient.
    file: File,
    identity: Identity,
    // Bounded by the caller's asset limit. Retaining exact bytes trades memory
    // for avoiding repeated SHA256, without relying on timestamp granularity.
    bytes: Box<[u8]>,
    invalid: AtomicBool,
}
impl AuthenticatedFile {
    pub(crate) fn new(path: &Path, expected: &[u8; 32], limit: u64) -> Result<Self> {
        let target = path.canonicalize()?;
        let (file, before) = open_regular(&target, limit)?;
        let identity = Identity::read(&before)?;
        let bytes = read_opened(&file, &before, usize::try_from(limit)?)?.into_boxed_slice();
        ensure!(
            crate::hash(&[&bytes]) == *expected,
            "private relation artifact changed"
        );
        let authenticated = Self {
            target,
            file,
            identity,
            bytes,
            invalid: AtomicBool::new(false),
        };
        // Check the SAME descriptor and configured path after hashing, including
        // bytes: a concurrent edit can leave all metadata unchanged on Linux.
        authenticated.check(path)?;
        Ok(authenticated)
    }

    pub(crate) fn check(&self, path: &Path) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.invalid.load(Ordering::Acquire),
                "authenticated asset invalidated"
            );
            self.check_identity(path)?;
            self.check_contents()?;
            self.check_identity(path)?;
            ensure!(
                !self.invalid.load(Ordering::Acquire),
                "authenticated asset invalidated"
            );
            Ok(())
        })();
        if result.is_err() {
            // Once a change is observed, restoring bytes or metadata must not
            // silently reactivate a verifier or one of its cached proofs.
            self.invalid.store(true, Ordering::Release);
        }
        result
    }

    fn check_identity(&self, path: &Path) -> Result<()> {
        let target = path.canonicalize()?;
        ensure!(
            target == self.target
                && Identity::read(&self.file.metadata()?)? == self.identity
                && Identity::read(&fs::symlink_metadata(&target)?)? == self.identity,
            "authenticated asset changed; reload verifier"
        );
        Ok(())
    }

    fn check_contents(&self) -> Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        let mut offset = 0;
        for expected in self.bytes.chunks(buffer.len()) {
            // Positional reads keep concurrent checks independent of the shared
            // descriptor's cursor, including the read used at authentication.
            let actual = &mut buffer[..expected.len()];
            self.file.read_exact_at(actual, offset)?;
            ensure!(actual == expected, "authenticated asset contents changed");
            offset += expected.len() as u64;
        }
        ensure!(
            self.file.read_at(&mut buffer[..1], offset)? == 0,
            "authenticated asset grew"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::FileTimes;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn identical_metadata_cannot_hide_edits_or_restore_invalidated_assets() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../work")
            .join(format!(
                "asset-same-stamp-{}",
                hex::encode(crate::random32())
            ));
        fs::create_dir_all(&root)?;
        let path = root.join("asset");
        let bytes = vec![0x42; 150_001];
        fs::write(&path, &bytes)?;
        let mut authenticated =
            AuthenticatedFile::new(&path, &crate::hash(&[&bytes]), bytes.len() as u64)?;
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        for _ in 0..10 {
                            authenticated.check(&path).unwrap();
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
        });
        let mut changed = bytes.clone();
        changed[130_000] ^= 1;
        fs::write(&path, &changed)?;
        // Force the metadata comparison to match on every test platform. This
        // models the timestamp collision that reproduced naturally on Linux.
        authenticated.identity = Identity::read(&fs::metadata(&path)?)?;
        authenticated.check_identity(&path)?;
        assert!(authenticated.check(&path).is_err());
        fs::write(&path, &bytes)?;
        authenticated.identity = Identity::read(&fs::metadata(&path)?)?;
        authenticated.check_identity(&path)?;
        authenticated.check_contents()?;
        assert!(authenticated.check(&path).is_err());
        AuthenticatedFile::new(&path, &crate::hash(&[&bytes]), bytes.len() as u64)?.check(&path)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn authentication_detects_edits_replacements_and_retargeted_links() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../work")
            .join(format!(
                "authenticated-assets-{}",
                hex::encode(crate::random32())
            ));
        fs::create_dir_all(&root)?;
        let path = root.join("asset");
        let pin = crate::hash(&[b"original"]);
        fs::write(&path, b"original")?;
        let authenticated = AuthenticatedFile::new(&path, &pin, 8)?;
        authenticated.check(&path)?;
        let modified = fs::metadata(&path)?.modified()?;
        fs::write(&path, b"modified")?;
        File::options()
            .write(true)
            .open(&path)?
            .set_times(FileTimes::new().set_modified(modified))?;
        assert!(authenticated.check(&path).is_err());
        assert!(AuthenticatedFile::new(&path, &pin, 8).is_err());
        fs::write(&path, b"original")?;
        assert!(authenticated.check(&path).is_err()); // Never refresh after change.
        let authenticated = AuthenticatedFile::new(&path, &pin, 8)?;
        fs::write(root.join("replacement"), b"original")?;
        fs::rename(root.join("replacement"), &path)?;
        assert!(authenticated.check(&path).is_err());
        let link = root.join("link");
        symlink("asset", &link)?;
        let authenticated = AuthenticatedFile::new(&link, &pin, 8)?;
        authenticated.check(&link)?;
        fs::write(root.join("other"), b"original")?;
        fs::remove_file(&link)?;
        symlink("other", &link)?;
        assert!(authenticated.check(&link).is_err());
        let authenticated = AuthenticatedFile::new(&path, &pin, 8)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        assert!(authenticated.check(&path).is_err());
        assert!(AuthenticatedFile::new(&root, &pin, 8).is_err());
        assert!(AuthenticatedFile::new(&path, &pin, 7).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
