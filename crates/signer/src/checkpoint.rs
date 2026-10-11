//! Bounded admission and a process lock for the independently retained floor.
//! Locking does not make the database and checkpoint an atomic storage domain;
//! the engine detects an interrupted publication and requires explicit repair.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, Instant},
};
use zark_protocol::local::ProcessLock;

pub(crate) struct CheckpointLock {
    _lock: ProcessLock,
    _permit: crate::admission::Permit,
}
impl CheckpointLock {
    pub fn acquire(db: &Path, checkpoint: &Path, guard: &dyn Fn() -> Result<()>) -> Result<Self> {
        // Queueing and cross-process contention share the existing five-second
        // admission budget. Hosted guards can impose an earlier request deadline.
        Self::acquire_until(
            db,
            checkpoint,
            Instant::now() + Duration::from_secs(5),
            guard,
        )
    }

    fn acquire_until(
        db: &Path,
        checkpoint: &Path,
        deadline: Instant,
        guard: &dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        let directory = checkpoint.parent().context("checkpoint directory")?;
        fs::create_dir_all(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        let canonical = fs::canonicalize(directory)?;
        ensure!(
            canonical != fs::canonicalize(db.parent().context("database directory")?)?,
            "checkpoint must be outside the database directory"
        );
        let lock = canonical.join(
            checkpoint
                .with_extension("lock")
                .file_name()
                .context("checkpoint lock name")?,
        );
        let permit = crate::admission::Permit::acquire(&lock, deadline, guard)?;
        let lock = crate::admission::acquire_process_lock(
            &lock,
            deadline,
            guard,
            "checkpoint busy: lock deadline",
        )?;
        Ok(Self {
            _lock: lock,
            _permit: permit,
        })
    }
}

#[cfg(test)]
mod tests;
