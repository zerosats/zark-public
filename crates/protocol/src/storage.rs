//! Durable writes shared by local adapters.
use crate::random32;
use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{LazyLock, Mutex},
};

/// File and directory fsync: acknowledgement never precedes durable rename.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let _timing = crate::timing::Span::new(crate::timing::Phase::LocalDurableWrite);
    let parent = path.parent().context("file directory")?;
    let temp = parent.join(format!(".write-{}", hex::encode(random32())));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    result
}

/// Make a reopened record durable before acting on it: its writer may have
/// stopped after `rename` but before the directory sync. The sync is skipped
/// only when this process already synced the identical file inode and directory
/// and neither has changed since. Records are replaced by [`atomic_write`], so
/// every write is a new inode and is synced again on its first observation.
pub fn sync_observed(file: &fs::File, directory: &Path) -> Result<()> {
    let directory = fs::File::open(directory)?;
    let observed = observe(file, &directory)?;
    if already_synced(&observed) {
        return Ok(());
    }
    file.sync_all()?;
    directory.sync_all()?;
    // Remember only a state that provably did not change across the syncs.
    if observe(file, &directory)? == observed
        && let Ok(mut synced) = SYNCED.lock()
    {
        if synced.len() >= SYNCED_LIMIT {
            synced.clear();
        }
        synced.insert((observed.0.device, observed.0.inode), observed);
    }
    Ok(())
}

const SYNCED_LIMIT: usize = 1024;
static SYNCED: LazyLock<Mutex<HashMap<(u64, u64), Observed>>> = LazyLock::new(Default::default);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Version {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
type Observed = (Version, Version);

fn version(metadata: &fs::Metadata) -> Version {
    Version {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

fn observe(file: &fs::File, directory: &fs::File) -> Result<Observed> {
    Ok((version(&file.metadata()?), version(&directory.metadata()?)))
}

fn already_synced(observed: &Observed) -> bool {
    SYNCED
        .lock()
        .is_ok_and(|synced| synced.get(&(observed.0.device, observed.0.inode)) == Some(observed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn sync_is_reused_only_for_the_same_unchanged_file_and_directory() -> Result<()> {
        let directory = std::env::temp_dir()
            .canonicalize()?
            .join(format!("zark-storage-test-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let record = directory.join("record");
        let check = |expected: bool| -> Result<()> {
            let file = fs::File::open(&record)?;
            let observed = observe(&file, &fs::File::open(&directory)?)?;
            assert_eq!(already_synced(&observed), expected);
            sync_observed(&file, &directory)?;
            assert!(already_synced(&observe(
                &file,
                &fs::File::open(&directory)?
            )?));
            Ok(())
        };
        let result = (|| {
            atomic_write(&record, b"first")?;
            check(false)?;
            check(true)?;
            atomic_write(&record, b"first")?;
            check(false)?;
            // Give the directory a known old mtime before the next entry is
            // created: quick mutations may share a timestamp on Linux.
            fs::File::open(&directory)?.set_modified(std::time::SystemTime::UNIX_EPOCH)?;
            check(false)?;
            fs::write(directory.join("unrelated"), b"entry")?;
            check(false)?;
            check(true)
        })();
        fs::remove_dir_all(&directory)?;
        result
    }
}
