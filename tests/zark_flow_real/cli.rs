//! Separate full CLI/TLS qualification. No Engine or wallet journal API is used
//! to carry out a coin operation: only authenticated executables, CLI JSON and
//! the fresh isolated Bitcoin node. Private subprocess logs remain in the run.
#[path = "cli/batch.rs"]
mod batch;
#[path = "cli/latency.rs"]
pub(super) mod latency;
#[path = "cli/process.rs"]
mod process;
#[path = "cli/scenario.rs"]
mod scenario;
#[path = "cli/worker.rs"]
mod worker;
use batch::run_batch_after_first_origin;
use process::{SignerProcess, WalletCli, args, reject_metadata_change, text_field, word};
use scenario::run_inner;

use super::*;
use std::{
    ffi::{OsStr, OsString},
    io::Read,
    net::{SocketAddr, TcpStream},
    os::unix::process::CommandExt,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use zark_protocol::{
    assets::{MAX_CRS_BYTES, MAX_EXECUTABLE_BYTES, is_crs_runtime_lock, sha256_bounded},
    storage::atomic_write,
};

#[path = "cli/multi.rs"]
mod multi;

const OUTPUT_LIMIT: u64 = 2_000_000;
const STDERR_LIMIT: u64 = 16_000_000;
const COMMAND_DEADLINE: Duration = Duration::from_secs(3 * 60 * 60);

#[derive(Clone, Copy, PartialEq, Eq)]
enum BatchSenderMode {
    Sequential,
    Concurrent,
    Multi(usize, usize, bool),
}

/// Inspect completed owner-local jobs, including any unexpectedly added role.
fn require_proof_jobs(operation: &Path, expected: &[&str]) -> Result<()> {
    let mut actual = Vec::new();
    for entry in fs::read_dir(operation.join("proofs"))? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with("-job"))
        {
            let job: Value = serde_json::from_slice(&fs::read(path.join("job.json"))?)?;
            ensure!(
                path.join("completed.json").is_file(),
                "unfinished proof job"
            );
            actual.push(job["role"].as_str().context("proof role")?.to_owned());
        }
    }
    actual.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    ensure!(
        actual == expected,
        "unexpected fresh proof jobs: {actual:?}"
    );
    Ok(())
}

fn deposit_receipt(operation: &Path) -> Result<Vec<u8>> {
    require_proof_jobs(operation, &["deposit_authorization"])?;
    Ok(fs::read(
        operation.join("proofs/deposit-authorization-job/completed.json"),
    )?)
}

fn pin(pin: &BinaryPin) -> Result<()> {
    ensure!(
        pin.path.is_absolute()
            && sha256_bounded(&pin.path, MAX_EXECUTABLE_BYTES)? == hex32(&pin.sha256)?,
        "CLI qualification executable pin mismatch"
    );
    Ok(())
}

pub(super) fn run() -> Result<()> {
    run_inner(None, false, false)
}
pub(super) fn run_batch() -> Result<()> {
    run_inner(Some(BatchSenderMode::Sequential), false, false)
}
pub(super) fn run_batch_concurrent() -> Result<()> {
    run_inner(Some(BatchSenderMode::Concurrent), false, false)
}
pub(super) fn run_public(batch: bool) -> Result<()> {
    run_inner(batch.then_some(BatchSenderMode::Sequential), true, false)
}
pub(super) fn run_worker() -> Result<()> {
    run_inner(None, true, true)
}
pub(super) fn run_multi(left: usize, right: usize) -> Result<()> {
    run_inner(
        Some(BatchSenderMode::Multi(left, right, false)),
        true,
        false,
    )
}
pub(super) fn run_multi_wrong_amount() -> Result<()> {
    run_inner(Some(BatchSenderMode::Multi(1, 3, true)), true, false)
}

pub(super) fn run_origin_worker() -> Result<()> {
    scenario::run_with_transfers(None, true, true, 0)
}
