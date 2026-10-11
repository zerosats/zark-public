//! Authenticated direct witness execution and local private hint lifecycle.
use super::{BinaryPin, assets::AuthenticatedAssets, check_binary, process};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    os::fd::AsRawFd,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zark_protocol::hash;
use zark_protocol::timing::{Phase, Span};

/// Keys of the retired runtime that ran a Python helper from a pinned
/// interpreter, standard library and helper directory.
const RETIRED_KEYS: [&str; 4] = [
    "python",
    "python_assets",
    "helper_directory",
    "helper_sha256",
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FastRuntime {
    pub executor: BinaryPin,
    pub prover: BinaryPin,
    /// The `zark-fast-helper` executable. Its hint tables are compiled in, so
    /// this one pin authenticates all helper code and constants.
    pub helper: BinaryPin,
    pub witness_threads: u16,
    pub prove_threads: u16,
    pub verify_threads: u16,
    /// Opt-in for newly derived deposit/transfer-exit witness artifacts.
    /// Omitted for existing runtimes so their frozen identity stays unchanged.
    #[serde(default, skip_serializing_if = "is_false")]
    pub extended_native_hints: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl FastRuntime {
    /// Name a wallet configuration that still pins the retired Python helper
    /// instead of reporting a generic parse error. It is never migrated here:
    /// its pending jobs are frozen under that runtime's identity.
    pub fn reject_retired(config: &[u8]) -> Result<()> {
        let retired = serde_json::from_slice::<serde_json::Value>(config)
            .ok()
            .and_then(|config| {
                let runtime = config.get("fast_runtime")?.as_object()?;
                Some(RETIRED_KEYS.iter().any(|key| runtime.contains_key(*key)))
            })
            .unwrap_or(false);
        ensure!(
            !retired,
            "this wallet configuration pins the retired Python fast-prover helper; keep it and its pending proofs with the wallet build that created it, or set up a fresh profile from a bundle containing zark-fast-helper"
        );
        Ok(())
    }

    pub(super) fn authenticate(&self) -> Result<AuthenticatedAssets> {
        AuthenticatedAssets::authenticate(
            &[
                self.executor.path.clone(),
                self.prover.path.clone(),
                self.helper.path.clone(),
            ],
            || self.check(),
        )
    }

    fn check(&self) -> Result<()> {
        for pin in [&self.executor, &self.prover, &self.helper] {
            check_binary(pin)?;
        }
        ensure!(
            (1..=64).contains(&self.witness_threads) && (1..=64).contains(&self.prove_threads),
            "invalid fast prover worker profile"
        );
        ensure!(
            (1..=8).contains(&self.verify_threads),
            "invalid verifier worker profile"
        );
        Ok(())
    }

    /// Bound into every frozen job. Any executable pin, path or worker change,
    /// including the retired Python helper configuration, is a different
    /// runtime, so a job prepared under another runtime never resumes here.
    pub(super) fn identity(&self) -> Result<String> {
        Ok(hex::encode(hash(&[&serde_json::to_vec(self)?])))
    }

    pub(super) fn execute(&self, role: &str, artifact: &Path, directory: &Path) -> Result<()> {
        let helper = if needs_helper(role)
            || (self.extended_native_hints
                && matches!(role, "deposit_authorization" | "exit_from_transfer"))
        {
            Some(self.start_helper(directory)?)
        } else {
            None
        };
        let mut execute = Command::new(&self.executor.path);
        execute
            .arg("execute")
            .arg("--artifact-path")
            .arg(artifact)
            .arg("--prover-file")
            .arg(directory.join("input.toml"))
            .arg("--output-dir")
            .arg(directory)
            .args(["--witness-name", "witness"]);
        if let Some((_, url)) = &helper {
            execute.arg("--oracle-resolver").arg(url);
        }
        process::run(
            &mut execute,
            directory,
            "private witness execution failed",
            self.witness_threads,
            false,
        )?;
        // The RAII guard kills and reaps the helper on both success and errors,
        // before proof generation or acknowledgement. No private payload logs.
        drop(helper);
        Ok(())
    }

    fn start_helper(&self, directory: &Path) -> Result<(process::Running, String)> {
        let mut command = Command::new(&self.helper.path);
        command.args(["--port", "0"]);
        process::prepare(&mut command, directory, self.witness_threads, false)?;
        command.stdout(Stdio::piped());
        let mut child = {
            let _span = Span::new(Phase::HelperProcessSpawn);
            process::Running(command.spawn().context("start private helper")?)
        };
        let _span = Span::new(Phase::HelperReadiness);
        let mut pipe = child.0.stdout.take().context("helper readiness pipe")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut line = Vec::new();
        loop {
            ensure!(
                Instant::now() < deadline,
                "private helper readiness timeout"
            );
            let mut poll = libc::pollfd {
                fd: pipe.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut poll, 1, 100) };
            ensure!(ready >= 0, "helper readiness poll failed");
            if ready == 0 {
                continue;
            }
            let mut byte = [0];
            ensure!(
                pipe.read(&mut byte)? == 1,
                "private helper ended before readiness"
            );
            if byte[0] == b'\n' {
                break;
            }
            ensure!(line.len() < 1024, "invalid helper readiness");
            line.push(byte[0]);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ready {
            ready: bool,
            host: String,
            port: u16,
            url: String,
            cache: bool,
        }
        let ready: Ready = serde_json::from_slice(&line)
            .map_err(|_| anyhow::anyhow!("invalid helper readiness"))?;
        let url = format!("http://127.0.0.1:{}/", ready.port);
        ensure!(
            ready.ready
                && ready.host == "127.0.0.1"
                && ready.port != 0
                && ready.url == url
                && !ready.cache,
            "private helper boundary mismatch"
        );
        ensure!(child.0.try_wait()?.is_none(), "private helper stopped");
        Ok((child, url))
    }
}

/// Exactly the roles whose admitted artifacts call helper oracles (the lock's
/// `native` roles). Origin exit's batched predecessor check uses
/// `zark_glv_batch_hint_v1`, so it is native too.
pub(super) fn needs_helper(role: &str) -> bool {
    matches!(
        role,
        "sender_from_origin"
            | "sender_from_transfer"
            | "receiver_authorization"
            | "exit_from_origin"
    )
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
