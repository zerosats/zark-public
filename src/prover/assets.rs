//! Process-local authentication lifetime for public proving assets.
//!
//! Hash and semantically validate every asset when loading a prover. Later phase
//! boundaries require the same filesystem objects, including ctime (so restoring
//! mtime does not hide an edit). Never persist these stamps or refresh them
//! after a change. Like the bounded asset reader, this is not an OS sandbox
//! against the same user.
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(super) struct AuthenticatedAssets(BTreeMap<PathBuf, Stamp>);

#[derive(PartialEq, Eq)]
struct Stamp {
    target: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    owner: (u32, u32),
    links: u64,
}

impl Stamp {
    fn read(path: &Path) -> Result<Self> {
        // Configured public executables may be symlinks. Bind both their resolved
        // location and target identity.
        let target = path.canonicalize()?;
        let m = fs::symlink_metadata(&target)?;
        ensure!(m.is_file(), "invalid proving asset type");
        Ok(Self {
            target,
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

impl AuthenticatedAssets {
    pub(super) fn authenticate(
        files: &[PathBuf],
        validate: impl FnOnce() -> Result<()>,
    ) -> Result<Self> {
        let mut assets = Self(BTreeMap::new());
        for path in files {
            assets.0.insert(path.to_owned(), Stamp::read(path)?);
        }
        // Capture before hashing, then recheck afterwards: a mutation during
        // authentication must not become the supposedly authenticated snapshot.
        validate()?;
        assets.check()?;
        Ok(assets)
    }

    pub(super) fn check(&self) -> Result<()> {
        for (path, expected) in &self.0 {
            ensure!(
                Stamp::read(path)? == *expected,
                "authenticated proving asset changed: {}",
                path.display()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "assets_tests.rs"]
mod tests;
