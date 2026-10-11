//! Timing preconditions for tests of filesystem metadata, not wallet logic.
use anyhow::{Result, ensure};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};

pub(crate) fn after_filesystem_tick(file: &Path) -> Result<()> {
    let before = fs::metadata(file)?;
    let changed = (before.ctime(), before.ctime_nsec());
    let probe = file.with_extension("clock-probe");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        fs::write(&probe, b"clock")?;
        let now = fs::metadata(&probe)?;
        if (now.ctime(), now.ctime_nsec()) > changed {
            fs::remove_file(probe)?;
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "test filesystem clock did not advance"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
