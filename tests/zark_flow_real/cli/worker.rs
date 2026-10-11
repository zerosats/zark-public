//! The real-flow harness can exercise the same persistent stdio API as desktop.
use super::*;
use process::{OwnedProcess, private_log};
use std::{
    io::{BufRead, BufReader},
    process::ChildStdin,
    sync::mpsc::{self, Receiver},
};

pub(super) struct Worker {
    process: OwnedProcess,
    input: ChildStdin,
    replies: Receiver<Result<Vec<u8>>>,
    stderr: PathBuf,
    next_id: u64,
}
impl Worker {
    pub(super) fn start(client: &WalletCli) -> Result<Self> {
        let stderr = client.logs.join(format!(
            "{}-worker-{}.stderr.log",
            client.actor, client.count
        ));
        let mut child = Command::new(&client.binary.path)
            .args(["--config"])
            .arg(&client.config)
            .arg("worker")
            .env("HARDWARE_CONCURRENCY", "4")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(private_log(&stderr)?))
            .process_group(0)
            .spawn()?;
        let input = child.stdin.take().context("worker input")?;
        let stdout = child.stdout.take().context("worker output")?;
        let (tx, replies) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let result = (|| {
                    let mut bytes = Vec::new();
                    let n = (&mut reader)
                        .take(OUTPUT_LIMIT + 1)
                        .read_until(b'\n', &mut bytes)?;
                    ensure!(
                        n > 0 && n as u64 <= OUTPUT_LIMIT && bytes.last() == Some(&b'\n'),
                        "invalid worker reply framing"
                    );
                    Ok(bytes)
                })();
                let failed = result.is_err();
                if tx.send(result).is_err() || failed {
                    break;
                }
            }
        });
        let worker = Self {
            process: OwnedProcess {
                child,
                reaped: false,
            },
            input,
            replies,
            stderr,
            next_id: 1,
        };
        let ready = worker.reply(Duration::from_secs(120))?;
        ensure!(
            ready == json!({"worker_version":1,"ready":true}),
            "worker did not authenticate its assets"
        );
        Ok(worker)
    }
    fn reply(&self, timeout: Duration) -> Result<Value> {
        let bytes = self
            .replies
            .recv_timeout(timeout)
            .context("worker response deadline")??;
        ensure!(
            fs::metadata(&self.stderr)?.len() <= STDERR_LIMIT,
            "worker diagnostic limit"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }
    /// Diagnostics are written before the reply, so offsets bound one command.
    pub(super) fn stderr_position(&self) -> Result<(String, u64)> {
        let name = self.stderr.file_name().context("worker log name")?;
        Ok((
            name.to_string_lossy().into_owned(),
            fs::metadata(&self.stderr)?.len(),
        ))
    }
    pub(super) fn execute(&mut self, args: &[OsString]) -> Result<Value> {
        ensure!(self.process.child.try_wait()?.is_none(), "worker exited");
        let args = args
            .iter()
            .map(|s| s.to_str().context("worker argument encoding"))
            .collect::<Result<Vec<_>>>()?;
        serde_json::to_writer(
            &mut self.input,
            &json!({"version":1,"id":self.next_id,"args":args}),
        )?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        let response = self.reply(COMMAND_DEADLINE)?;
        ensure!(
            response["worker_version"] == 1
                && response["id"] == self.next_id
                && response.get("fatal").is_none(),
            "worker response context"
        );
        self.next_id += 1;
        Ok(response["response"].clone())
    }

    pub(super) fn reject_changed_config(&mut self, config: &Path, operation: &Path) -> Result<()> {
        // Replace only this test's synthetic configuration with identical bytes.
        // Even a same-content replacement must retire the warm authentication.
        let bytes = fs::read(config)?;
        atomic_write(config, &bytes)?;
        serde_json::to_writer(
            &mut self.input,
            &json!({"version":1,"id":self.next_id,
            "args":["new-address","--directory",operation]}),
        )?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        let response = self.reply(Duration::from_secs(10))?;
        ensure!(
            response["worker_version"] == 1
                && response["id"] == self.next_id
                && response["fatal"] == true
                && response["response"]["ok"] == false,
            "changed worker configuration was not rejected"
        );
        ensure!(
            !operation.exists(),
            "changed-config request performed a mutation"
        );
        Ok(())
    }
}
