//! Bound both pipes while the child runs, not after Command::output allocates.
//! Raw stderr is discarded; operator credentials/paths never enter errors.
use anyhow::{Result, ensure};
use std::{
    io::{self, Read},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const STDOUT_LIMIT: usize = 4_000_000;
const STDERR_LIMIT: usize = 64_000;
const OUTER_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) fn run(command: &mut Command) -> Result<Vec<u8>> {
    run_bounded(command, STDOUT_LIMIT, STDERR_LIMIT, OUTER_TIMEOUT)
}

struct Running(Child);
impl Running {
    fn kill_group(&mut self) {
        // The child was spawned as leader of its own process group. This also
        // stops ordinary descendants retaining the pipes or inherited lock FD.
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.kill();
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.kill_group();
        let _ = self.0.wait();
    }
}

fn nonblocking(stream: &impl AsRawFd) -> Result<()> {
    let fd = stream.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "Bitcoin RPC output pipe setup failed"
    );
    Ok(())
}

struct Capture {
    bytes: Option<Vec<u8>>,
    count: usize,
    limit: usize,
    eof: bool,
    name: &'static str,
}
impl Capture {
    fn new(limit: usize, keep: bool, name: &'static str) -> Self {
        Self {
            bytes: keep.then(|| Vec::with_capacity(limit.min(16_384))),
            count: 0,
            limit,
            eof: false,
            name,
        }
    }
    fn drain(&mut self, stream: &mut impl Read) -> Result<()> {
        if self.eof {
            return Ok(());
        }
        let mut buffer = [0u8; 4096];
        // Bound work per pass so continuous output cannot starve the opposite
        // pipe, child status checks, or the outer wall clock deadline.
        for _ in 0..16 {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => {
                    self.count = self
                        .count
                        .checked_add(n)
                        .ok_or_else(|| anyhow::anyhow!("Bitcoin RPC output size overflow"))?;
                    ensure!(
                        self.count <= self.limit,
                        "Bitcoin RPC {} exceeded its size limit",
                        self.name
                    );
                    if let Some(bytes) = &mut self.bytes {
                        bytes.extend_from_slice(&buffer[..n]);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => anyhow::bail!("Bitcoin RPC output pipe failed"),
            }
        }
        Ok(())
    }
}

fn run_bounded(
    command: &mut Command,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    ensure!(
        stdout_limit > 0 && stderr_limit > 0 && !timeout.is_zero(),
        "invalid Bitcoin RPC subprocess limits"
    );
    let deadline = Instant::now() + timeout;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = Running(
        command
            .spawn()
            .map_err(|_| anyhow::anyhow!("Bitcoin RPC executable could not start"))?,
    );
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Bitcoin RPC stdout unavailable"))?;
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Bitcoin RPC stderr unavailable"))?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut out = Capture::new(stdout_limit, true, "stdout");
    let mut err = Capture::new(stderr_limit, false, "stderr");
    let mut status = None;
    loop {
        ensure!(
            Instant::now() < deadline,
            "Bitcoin RPC exceeded its outer time limit"
        );
        out.drain(&mut stdout)?;
        err.drain(&mut stderr)?;
        if status.is_none() {
            status = child
                .0
                .try_wait()
                .map_err(|_| anyhow::anyhow!("Bitcoin RPC process status unavailable"))?;
            if status.is_some() {
                child.kill_group();
            }
        }
        if let Some(status) = status
            && out.eof
            && err.eof
        {
            ensure!(status.success(), "Bitcoin RPC process failed");
            return Ok(out.bytes.take().unwrap_or_default());
        }
        thread::sleep(
            Duration::from_millis(5).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn script(text: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", text]);
        command
    }
    #[test]
    fn normal_json_string_and_empty_gettxout_parsing_are_preserved() {
        let mut command = script("printf '{\"confirmations\":2}'; printf 'operator detail' >&2");
        let out = run_bounded(&mut command, 1000, 1000, Duration::from_secs(2)).unwrap();
        assert_eq!(
            super::super::parse_rpc_response("getrawtransaction", &out).unwrap()["confirmations"],
            2
        );
        assert!(
            super::super::parse_rpc_response("gettxout", b" \n\t")
                .unwrap()
                .is_null()
        );
        let hash = "ab".repeat(32);
        assert_eq!(
            super::super::parse_rpc_response("getblockhash", format!("{hash}\n").as_bytes())
                .unwrap(),
            hash
        );
        assert!(super::super::parse_rpc_response("getblockchaininfo", hash.as_bytes()).is_err());
    }
    #[test]
    fn stdout_and_stderr_are_capped_during_execution() {
        for (script_text, stream) in [
            ("while :; do printf '0123456789abcdef'; done", "stdout"),
            (
                "while :; do printf 'private operator detail' >&2; done",
                "stderr",
            ),
        ] {
            let before = Instant::now();
            let error = run_bounded(&mut script(script_text), 1024, 1024, Duration::from_secs(2))
                .unwrap_err()
                .to_string();
            assert!(error.contains(stream) && error.contains("size limit"));
            assert!(!error.contains("private operator detail"));
            assert!(before.elapsed() < Duration::from_secs(2));
        }
    }
    #[test]
    fn hung_process_and_inherited_pipe_descendant_do_not_hold_the_caller() {
        let before = Instant::now();
        let error = run_bounded(
            &mut script("sleep 20"),
            1024,
            1024,
            Duration::from_millis(150),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("outer time limit"));
        assert!(before.elapsed() < Duration::from_secs(2));
        let before = Instant::now();
        let out = run_bounded(
            &mut script("sleep 20 & printf '{}'; exit 0"),
            1024,
            1024,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(out, b"{}");
        assert!(before.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn nonzero_exit_and_malformed_output_never_echo_operator_secrets() {
        let error = run_bounded(
            &mut script("printf 'rpcpassword=secret-value' >&2; exit 9"),
            1024,
            1024,
            Duration::from_secs(2),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "Bitcoin RPC process failed");
        assert!(!error.contains("secret-value"));
        let error = super::super::parse_rpc_response("getblockchaininfo", b"secret-value not json")
            .unwrap_err()
            .to_string();
        assert_eq!(error, "Bitcoin RPC returned invalid JSON");
        let error = super::super::parse_rpc_response("getblockhash", b"secret-value")
            .unwrap_err()
            .to_string();
        assert_eq!(error, "Bitcoin RPC returned an invalid transaction hash");
    }
}
