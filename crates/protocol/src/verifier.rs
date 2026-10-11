//! Bounded external Barretenberg verification of exact public byte statements.
use crate::{public_fields, random32, storage::atomic_write};
use anyhow::{Result, ensure};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn verify_proof(
    bb: &Path,
    vk: &Path,
    crs: &Path,
    parent: &Path,
    proof: &[u8],
    statement: &[u8],
) -> Result<()> {
    verify_proof_with_threads(bb, vk, crs, parent, proof, statement, 2)
}

/// Local proving output checks may select a qualified worker profile. Network
/// verification keeps the bounded default; process resource limits still apply.
pub fn verify_proof_with_threads(
    bb: &Path,
    vk: &Path,
    crs: &Path,
    parent: &Path,
    proof: &[u8],
    statement: &[u8],
    threads: u16,
) -> Result<()> {
    ensure!((1..=8).contains(&threads), "invalid verifier worker count");
    ensure!(!proof.is_empty() && proof.len() < 1_000_000, "proof size");
    let dir = parent.join(format!("verify-{}", hex::encode(random32())));
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let result = (|| {
        atomic_write(&dir.join("proof"), proof)?;
        atomic_write(&dir.join("public_inputs"), &public_fields(statement))?;
        let mut command = Command::new(bb);
        crate::verifier_process::restrict(&mut command)?;
        for name in [
            "HARDWARE_CONCURRENCY",
            "BB_HARDWARE_CONCURRENCY",
            "RAYON_NUM_THREADS",
            "OMP_NUM_THREADS",
        ] {
            command.env(name, threads.to_string());
        }
        command.env("TMPDIR", &dir);
        command
            .args(["verify", "-t", "noir-recursive", "-p"])
            .arg(dir.join("proof"))
            .arg("-i")
            .arg(dir.join("public_inputs"))
            .arg("-k")
            .arg(vk)
            .arg("-c")
            .arg(crs)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = crate::verifier_process::Process::spawn(&mut command)?;
        let _span = crate::timing::Span::new(crate::timing::Phase::VerifierProcessWait);
        let deadline = Instant::now() + Duration::from_secs(crate::verifier_process::WALL_SECONDS);
        loop {
            let status = match child.0.try_wait()? {
                Some(status) => Some(status),
                None => child.enforce_runtime_limits()?,
            };
            if let Some(status) = status {
                ensure!(status.success(), "ZK proof rejected");
                break;
            }
            if Instant::now() >= deadline {
                anyhow::bail!("proof verification deadline exceeded");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    })();
    fs::remove_dir_all(&dir)?;
    result
}
