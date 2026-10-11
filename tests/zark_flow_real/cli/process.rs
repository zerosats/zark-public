//! Pinned wallet and signer processes and private CLI invocation helpers.
use super::*;

pub(super) fn private_log(path: &Path) -> Result<fs::File> {
    Ok(fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

/// Only a child process group created by this test may be terminated. A failed
/// assertion also reaps that direct child. Prover jobs create separate groups:
/// their own durable job locks, subprocess guards and alarm remain responsible
/// for cleanup if the CLI is killed. This is not whole-descendant-tree cleanup.
pub(super) struct OwnedProcess {
    pub(super) child: Child,
    pub(super) reaped: bool,
}
impl OwnedProcess {
    pub(super) fn kill_and_reap(&mut self) {
        if self.reaped {
            return;
        }
        // SAFETY: process_group(0) made this child's PID its own process group.
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

pub(super) struct WalletCli {
    pub(super) worker_enabled: bool,
    pub(super) worker: Option<super::worker::Worker>,
    pub(super) network: Option<Arc<super::latency::Stats>>,
    pub(super) binary: BinaryPin,
    pub(super) config: PathBuf,
    pub(super) logs: PathBuf,
    pub(super) actor: &'static str,
    pub(super) count: usize,
    pub(super) commands: Vec<Value>,
    pub(super) last_process_window: Option<(Instant, Instant)>,
}
impl WalletCli {
    pub(super) fn execute(
        &mut self,
        label: &str,
        args: &[OsString],
        success: bool,
    ) -> Result<Value> {
        self.last_process_window = None;
        pin(&self.binary)?;
        self.count += 1;
        let stem = format!("{}-{:02}-{label}", self.actor, self.count);
        let stdout_path = self.logs.join(format!("{stem}.stdout.json"));
        let stderr_path = self.logs.join(format!("{stem}.stderr.log"));
        if self.worker_enabled {
            let start = Instant::now();
            if self.worker.is_none() {
                self.worker = Some(super::worker::Worker::start(self)?);
            }
            let worker = self.worker.as_mut().context("native worker")?;
            let (log, from) = worker.stderr_position()?;
            let network = self.network.as_ref().map(|stats| stats.snapshot());
            let command_start = Instant::now();
            let value = worker.execute(args)?;
            let elapsed = command_start.elapsed().as_secs_f64();
            let (_, to) = worker.stderr_position()?;
            self.last_process_window = Some((start, Instant::now()));
            private_log(&stdout_path)?.write_all(&serde_json::to_vec(&value)?)?;
            ensure!(
                value["api_version"] == 1 && value["ok"] == success,
                "unexpected worker outcome at {stem}; inspect private logs"
            );
            let mut record = json!({"actor":self.actor,"stage":label,"transport":"persistent-worker",
                "expected_success":success,"elapsed_seconds":start.elapsed().as_secs_f64(),
                "command_seconds":elapsed,"stderr_log":log,"stderr_range":[from,to]});
            if let (Some(stats), Some(before)) = (&self.network, network) {
                record["network"] = super::latency::Stats::delta(before, stats.snapshot());
            }
            self.commands.push(record);
            return Ok(value[if success { "result" } else { "error" }].clone());
        }
        let stdout = private_log(&stdout_path)?;
        let stderr = private_log(&stderr_path)?;
        eprintln!("cli-flow: {} {label}", self.actor);
        let start = Instant::now();
        let child = Command::new(&self.binary.path)
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .env("HARDWARE_CONCURRENCY", "4")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .process_group(0)
            .spawn()
            .context("could not start pinned wallet CLI")?;
        let process_started = Instant::now();
        let mut process = OwnedProcess {
            child,
            reaped: false,
        };
        let status = loop {
            ensure!(
                fs::metadata(&stdout_path)?.len() <= OUTPUT_LIMIT
                    && fs::metadata(&stderr_path)?.len() <= STDERR_LIMIT,
                "CLI output exceeded its private log bound at {stem}"
            );
            if let Some(status) = process.child.try_wait()? {
                process.reaped = true;
                break status;
            }
            ensure!(
                start.elapsed() < COMMAND_DEADLINE,
                "CLI wall timeout at {stem}"
            );
            thread::sleep(Duration::from_millis(100));
        };
        self.last_process_window = Some((process_started, Instant::now()));
        ensure!(
            fs::metadata(&stdout_path)?.len() <= OUTPUT_LIMIT
                && fs::metadata(&stderr_path)?.len() <= STDERR_LIMIT,
            "CLI final private log bound at {stem}"
        );
        let mut bytes = Vec::new();
        fs::File::open(&stdout_path)?
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= OUTPUT_LIMIT, "CLI final output bound");
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
            anyhow::anyhow!("CLI did not return one JSON result at {stem}; inspect private logs")
        })?;
        ensure!(value["api_version"] == 1, "CLI API version at {stem}");
        ensure!(
            status.success() == success && value["ok"] == success,
            "unexpected CLI outcome at {stem}; inspect its private logs"
        );
        self.commands.push(json!({"actor":self.actor,"stage":label,
            "expected_success":success,"elapsed_seconds":start.elapsed().as_secs_f64()}));
        if success {
            ensure!(value["result"].is_object(), "CLI result object at {stem}");
            Ok(value["result"].clone())
        } else {
            Ok(value["error"].clone())
        }
    }

    pub(super) fn ok(&mut self, label: &str, args: &[OsString]) -> Result<Value> {
        self.execute(label, args, true)
    }
}

pub(super) fn args(items: &[&OsStr]) -> Vec<OsString> {
    items.iter().map(|s| (*s).to_owned()).collect()
}
pub(super) fn word(text: &str) -> &OsStr {
    OsStr::new(text)
}
pub(super) fn text_field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("CLI result field {key}"))
}

/// Modify only operator metadata around an already completed native journal.
/// Restore exact bytes even if the CLI assertion fails; no extra proof is made.
pub(super) fn reject_metadata_change(
    client: &mut WalletCli,
    operation: &Path,
    checkpoint: &Path,
    field: &str,
    replacement: Value,
    label: &str,
) -> Result<()> {
    let metadata_path = operation.join("operation.json");
    let original = fs::read(&metadata_path)?;
    let mut metadata: Value = serde_json::from_slice(&original)?;
    let record = match text_field(&metadata["kind"], "kind")? {
        "sender" => "sender-operation.json",
        "exit" => "exit-operation.json",
        _ => anyhow::bail!("metadata regression requires an outgoing operation"),
    };
    let journal = operation.join("journal").join(record);
    let before_journal = sha256_bounded(&journal, 4_000_000)?;
    let before_checkpoint = sha256_bounded(checkpoint, 64_000)?;
    ensure!(
        metadata["kind"].get(field).is_some(),
        "missing operation metadata field"
    );
    ensure!(
        metadata["kind"][field] != replacement,
        "metadata mutation did not change value"
    );
    metadata["kind"][field] = replacement;
    atomic_write(&metadata_path, &serde_json::to_vec_pretty(&metadata)?)?;
    let rejected = client.execute(
        label,
        &args(&[word("resume"), word("--operation"), operation.as_os_str()]),
        false,
    );
    let restored = atomic_write(&metadata_path, &original);
    restored?;
    let rejected = rejected?;
    ensure!(
        text_field(&rejected, "message")?.contains("metadata"),
        "modified operation was not rejected by the local metadata binding"
    );
    ensure!(
        sha256_bounded(&journal, 4_000_000)? == before_journal
            && sha256_bounded(checkpoint, 64_000)? == before_checkpoint,
        "metadata rejection changed native journal or signer checkpoint"
    );
    Ok(())
}

pub(super) struct SignerProcess {
    pub(super) binary: BinaryPin,
    pub(super) config: PathBuf,
    pub(super) listen: SocketAddr,
    pub(super) log_directory: PathBuf,
    pub(super) generation: usize,
    pub(super) process: Option<OwnedProcess>,
}
impl SignerProcess {
    pub(super) fn start(&mut self) -> Result<()> {
        ensure!(self.process.is_none(), "CLI test signer already running");
        pin(&self.binary)?;
        self.generation += 1;
        let log = private_log(
            &self
                .log_directory
                .join(format!("signer-{}.log", self.generation)),
        )?;
        let child = Command::new(&self.binary.path)
            .arg("--config")
            .arg(&self.config)
            .env("HARDWARE_CONCURRENCY", "4")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .process_group(0)
            .spawn()?;
        self.process = Some(OwnedProcess {
            child,
            reaped: false,
        });
        let started = Instant::now();
        loop {
            ensure!(
                self.process
                    .as_mut()
                    .context("owned signer")?
                    .child
                    .try_wait()?
                    .is_none()
                    && started.elapsed() < Duration::from_secs(90),
                "isolated TLS signer did not start; inspect private signer log"
            );
            if TcpStream::connect_timeout(&self.listen, Duration::from_millis(100)).is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    pub(super) fn restart(&mut self) -> Result<()> {
        self.process.take(); // Drop kills only this test process and reaps it.
        self.start()
    }
}
