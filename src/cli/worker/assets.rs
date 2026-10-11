//! A worker may retain authentication only while its original files remain
//! unchanged. This follows the prover's process-local file-identity contract;
//! it is not an OS sandbox against another process running as the same user.
use super::super::config::App;
use crate::prover::Program;
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use zark_protocol::{
    assets::{MAX_CONFIG_BYTES, is_crs_runtime_lock, read_bounded},
    deployment::ROLE_NAMES,
};

#[derive(PartialEq, Eq)]
pub(super) struct Stamp {
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
    pub(super) fn read(path: &Path) -> Result<Self> {
        let target = path.canonicalize()?;
        let m = fs::symlink_metadata(&target)?;
        ensure!(m.is_file(), "invalid worker asset type");
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
    pub(super) fn check(&self, path: &Path) -> Result<()> {
        ensure!(
            *self == Self::read(path)?,
            "wallet assets changed; restart the wallet"
        );
        Ok(())
    }
}

pub(super) struct Assets {
    files: BTreeMap<PathBuf, Stamp>,
    crs: PathBuf,
    crs_target: PathBuf,
    crs_names: Vec<std::ffi::OsString>,
}
impl Assets {
    // Capture BEFORE full authentication and check again afterwards. These
    // stamps are never updated in a running worker, even after restoring bytes.
    pub(super) fn capture(app: &App, config: &Path) -> Result<Self> {
        let c = &app.config;
        let mut files = BTreeMap::new();
        for path in [
            config,
            &c.manifest,
            &c.programs,
            &c.nargo.path,
            &c.bb.path,
            &c.chain.bitcoin_cli,
        ] {
            files.insert(path.to_owned(), Stamp::read(path)?);
        }
        let suite = c.manifest.parent().context("suite directory")?;
        for role in ROLE_NAMES {
            for name in ["circuit.json", "vk", "vk.json"] {
                let path = suite.join(role).join(name);
                files.insert(path.clone(), Stamp::read(&path)?);
            }
        }
        let programs: Vec<Program> =
            serde_json::from_slice(&read_bounded(&c.programs, MAX_CONFIG_BYTES)?)?;
        for program in programs {
            files.insert(program.artifact.clone(), Stamp::read(&program.artifact)?);
        }
        if let Some(runtime) = &c.fast_runtime {
            for pin in [&runtime.executor, &runtime.prover, &runtime.helper] {
                files.insert(pin.path.clone(), Stamp::read(&pin.path)?);
            }
        }
        for name in c.crs_sha256.keys() {
            let path = c.crs.join(name);
            files.insert(path.clone(), Stamp::read(&path)?);
        }
        Ok(Self {
            files,
            crs: c.crs.clone(),
            crs_target: c.crs.canonicalize()?,
            crs_names: crs_names(&c.crs)?,
        })
    }
    pub(super) fn check(&self) -> Result<()> {
        let _timing =
            zark_protocol::timing::Span::new(zark_protocol::timing::Phase::WorkerAssetCheck);
        for (path, stamp) in &self.files {
            stamp.check(path)?;
        }
        ensure!(
            self.crs.canonicalize()? == self.crs_target && crs_names(&self.crs)? == self.crs_names,
            "wallet CRS directory changed; restart the wallet"
        );
        Ok(())
    }
}
fn crs_names(path: &Path) -> Result<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        // BB may create its qualified empty lock after worker authentication.
        if !is_crs_runtime_lock(&entry.path())? {
            names.push(entry.file_name());
        }
        ensure!(names.len() <= 128, "too many CRS entries");
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::FileTimes,
        os::unix::fs::{PermissionsExt, symlink},
    };
    #[test]
    fn stamps_reject_edits_restored_mtime_replacement_and_retargeting() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("work")
            .join(format!(
                "worker-assets-{}",
                hex::encode(zark_protocol::random32())
            ));
        fs::create_dir_all(&root)?;
        let tool = root.join("tool");
        fs::write(&tool, b"honest")?;
        // Linux can assign multiple writes the same coarse clock timestamp.
        // Exercise a metadata change, rather than relying on instruction timing.
        crate::test_support::after_filesystem_tick(&tool)?;
        let stamp = Stamp::read(&tool)?;
        let mtime = fs::metadata(&tool)?.modified()?;
        stamp.check(&tool)?;
        fs::write(&tool, b"mutant")?;
        fs::File::open(&tool)?.set_times(FileTimes::new().set_modified(mtime))?;
        assert!(stamp.check(&tool).is_err());
        fs::write(&tool, b"honest")?;
        assert!(stamp.check(&tool).is_err());
        let stamp = Stamp::read(&tool)?;
        fs::write(root.join("replacement"), b"honest")?;
        fs::rename(root.join("replacement"), &tool)?;
        assert!(stamp.check(&tool).is_err());
        let link = root.join("link");
        symlink("tool", &link)?;
        let stamp = Stamp::read(&link)?;
        fs::write(root.join("other"), b"honest")?;
        fs::remove_file(&link)?;
        symlink("other", &link)?;
        assert!(stamp.check(&link).is_err());
        let stamp = Stamp::read(&tool)?;
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o400))?;
        assert!(stamp.check(&tool).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn only_valid_runtime_lock_is_exempt_from_directory_membership() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("work")
            .join(format!(
                "worker-crs-{}",
                hex::encode(zark_protocol::random32())
            ));
        fs::create_dir_all(&root)?;
        fs::write(root.join("points.dat"), b"points")?;
        let before = crs_names(&root)?;
        let lock = root.join("crs.lock");
        fs::write(&lock, [])?;
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
        assert_eq!(crs_names(&root)?, before);
        fs::write(root.join("extra.dat"), b"extra")?;
        assert_ne!(crs_names(&root)?, before);
        fs::write(&lock, b"invalid")?;
        assert!(crs_names(&root).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
