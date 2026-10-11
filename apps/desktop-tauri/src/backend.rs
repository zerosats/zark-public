//! Owns the wallet runtime child process, newline framing and request lifetimes.
//!
//! This mirrors the macOS shell's `BackendClient`: every stdout line must decode
//! as a typed display event, so the webview only ever receives the small
//! projection below, never signing material or relay tokens. A failing shell
//! closes the runtime's stdin and lets the saved native step drain; it never
//! kills an in-flight operation.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

/// Largest buffered backend output before the shell gives up, as in the macOS shell.
pub const MAX_BUFFER: usize = 4_000_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CoinItem {
    pub id: String,
    pub amount_sat: i64,
    pub owner_operation: String,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwapOffer {
    pub id: String,
    pub amount_sat: i64,
    pub own: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwapApproval {
    pub id: String,
    pub outgoing_count: i64,
    pub incoming_count: i64,
    pub amount_sat: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ActivityItem {
    pub id: String,
    pub label: String,
    pub amount_sat: i64,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WalletSnapshot {
    pub total_sat: i64,
    pub coins: Vec<CoinItem>,
    pub offers: Vec<SwapOffer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvals: Option<Vec<SwapApproval>>,
    pub activity: Vec<ActivityItem>,
    pub connected: bool,
}

/// One runtime message. Unknown fields are dropped before reaching the webview.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackendEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<WalletSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_amount_sat: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faucet_amount_sat: Option<i64>,
}

/// What the shell forwards to the window.
#[derive(Clone, Debug, PartialEq)]
pub enum Output {
    Event {
        event: Box<BackendEvent>,
        is_reply: bool,
    },
    Error(String),
}

type Sink = Box<dyn Fn(Output) + Send + Sync>;

pub struct Backend {
    stdin: Mutex<Option<ChildStdin>>,
    pending: Mutex<HashMap<String, Sender<()>>>,
    failed: AtomicBool,
    exited: (Mutex<bool>, Condvar),
    next_id: AtomicU64,
    sink: Sink,
}

impl Backend {
    /// Starts the runtime (`node main.mjs`) with the inherited environment.
    /// Returns `None` after reporting an error when it cannot be started.
    pub fn start(
        program: &Path,
        args: &[&Path],
        env: &[(String, String)],
        sink: Sink,
    ) -> Option<Arc<Self>> {
        let mut child = match Command::new(program)
            .args(args)
            .envs(env.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => {
                sink(Output::Error("Wallet could not start".into()));
                return None;
            }
        };
        let backend = Arc::new(Self {
            stdin: Mutex::new(child.stdin.take()),
            pending: Mutex::new(HashMap::new()),
            failed: AtomicBool::new(false),
            exited: (Mutex::new(false), Condvar::new()),
            next_id: AtomicU64::new(1),
            sink,
        });
        let stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        // Backend stderr is deliberately not rendered; structured errors are sanitized.
        thread::spawn(move || {
            let mut sink = [0u8; 8192];
            while matches!(stderr.read(&mut sink), Ok(n) if n > 0) {}
        });
        let reader = Arc::clone(&backend);
        thread::spawn(move || reader.consume(stdout));
        let waiter = Arc::clone(&backend);
        thread::spawn(move || {
            let _ = child.wait();
            waiter.fail("Wallet stopped. Reopen Zark.");
            let (lock, done) = &waiter.exited;
            *lock.lock().unwrap() = true;
            done.notify_all();
        });
        Some(backend)
    }

    pub fn is_running(&self) -> bool {
        !self.failed.load(Ordering::SeqCst) && self.stdin.lock().unwrap().is_some()
    }

    /// Sends one request and waits for its reply (or for the backend to fail).
    /// Returns immediately when the backend is not running.
    pub fn request(&self, action: &str, args: Map<String, Value>) -> std::sync::mpsc::Receiver<()> {
        let (done, wait) = channel();
        let mut stdin = self.stdin.lock().unwrap();
        let Some(input) = stdin
            .as_mut()
            .filter(|_| !self.failed.load(Ordering::SeqCst))
        else {
            let _ = done.send(());
            return wait;
        };
        let id = format!("ui-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        self.pending.lock().unwrap().insert(id.clone(), done);
        let mut line =
            serde_json::to_vec(&serde_json::json!({"id": id, "action": action, "args": args}))
                .expect("request serializes");
        line.push(b'\n');
        if input.write_all(&line).and_then(|_| input.flush()).is_err() {
            if let Some(done) = self.pending.lock().unwrap().remove(&id) {
                let _ = done.send(());
            }
            (self.sink)(Output::Error("Wallet unavailable".into()));
        }
        wait
    }

    /// Closes admission and blocks until the runtime has drained and exited.
    pub fn shutdown(&self) {
        self.stdin.lock().unwrap().take();
        let (lock, done) = &self.exited;
        let mut exited = lock.lock().unwrap();
        while !*exited {
            exited = done.wait(exited).unwrap();
        }
    }

    fn consume(&self, stdout: impl Read) {
        let mut reader = BufReader::new(stdout);
        let mut line = Vec::new();
        loop {
            line.clear();
            // Bound each line before buffering it completely.
            match (&mut reader)
                .take(MAX_BUFFER as u64)
                .read_until(b'\n', &mut line)
            {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            if line.last() != Some(&b'\n') {
                if line.len() >= MAX_BUFFER {
                    return self.fail("Wallet response too large. Reopen Zark.");
                }
                return; // EOF without a final newline: the exit watcher reports it.
            }
            line.pop();
            let Ok(event) = parse_event(&line) else {
                return self.fail("Wallet response invalid. Reopen Zark.");
            };
            if self.failed.load(Ordering::SeqCst) {
                return;
            }
            let done = event
                .id
                .as_ref()
                .and_then(|id| self.pending.lock().unwrap().remove(id));
            (self.sink)(Output::Event {
                event: Box::new(event),
                is_reply: done.is_some(),
            });
            if let Some(done) = done {
                let _ = done.send(());
            }
        }
    }

    fn fail(&self, message: &str) {
        if self.failed.swap(true, Ordering::SeqCst) {
            return;
        }
        (self.sink)(Output::Error(message.into()));
        // Let the backend finish its saved journal step and release the wallet
        // lock. Never kill a native operation mid-flight.
        self.stdin.lock().unwrap().take();
        for (_, done) in self.pending.lock().unwrap().drain() {
            let _ = done.send(());
        }
    }
}

/// Decodes one runtime line; like the macOS shell, only a JSON object is valid.
pub fn parse_event(line: &[u8]) -> Result<BackendEvent, ()> {
    match serde_json::from_slice::<Value>(line) {
        Ok(value @ Value::Object(_)) => serde_json::from_value(value).map_err(|_| ()),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::Receiver;
    use std::time::Duration;

    fn start(script: &str) -> (Arc<Backend>, Receiver<Output>) {
        let (tx, rx) = channel();
        let tx = Mutex::new(tx);
        let backend = Backend::start(
            Path::new("/bin/sh"),
            &[Path::new("-c"), Path::new(script)],
            &[],
            Box::new(move |output| {
                let _ = tx.lock().unwrap().send(output);
            }),
        );
        (backend.expect("start"), rx)
    }

    fn next(rx: &Receiver<Output>) -> Output {
        rx.recv_timeout(Duration::from_secs(10))
            .expect("backend output")
    }

    fn event(value: Value) -> Box<BackendEvent> {
        Box::new(serde_json::from_value(value).unwrap())
    }

    #[test]
    fn events_keep_only_known_display_fields() {
        let event = parse_event(br#"{"id":"1","progress":"Proving","token":"secret","snapshot":{"totalSat":5,"coins":[],"offers":[],"activity":[],"connected":true,"relay":"x"}}"#).unwrap();
        let forwarded = serde_json::to_value(&event).unwrap();
        assert_eq!(
            forwarded,
            serde_json::json!({"id":"1","progress":"Proving","snapshot":{"totalSat":5,"coins":[],"offers":[],"activity":[],"connected":true}})
        );
        assert!(parse_event(br#"{"snapshot":{"totalSat":"5"}}"#).is_err());
        assert!(parse_event(b"").is_err());
        assert!(parse_event(b"[]").is_err());
    }

    #[test]
    fn replies_resolve_their_request_and_background_events_do_not() {
        let (backend, rx) =
            start(r#"read request; printf '{"progress":"Working"}\n{"id":"ui-1"}\n'; read eof"#);
        backend
            .request("refresh", Map::new())
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        assert_eq!(
            next(&rx),
            Output::Event {
                event: event(serde_json::json!({"progress": "Working"})),
                is_reply: false
            }
        );
        assert_eq!(
            next(&rx),
            Output::Event {
                event: event(serde_json::json!({"id": "ui-1"})),
                is_reply: true
            }
        );
        backend.shutdown();
    }

    #[test]
    fn invalid_output_fails_but_lets_the_runtime_drain() {
        let marker = std::env::temp_dir().join(format!("zark-drain-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let script = format!(
            "printf 'not json\\n'; read eof; touch '{}'",
            marker.display()
        );
        let (backend, rx) = start(&script);
        assert_eq!(
            next(&rx),
            Output::Error("Wallet response invalid. Reopen Zark.".into())
        );
        // Requests after a failure return at once instead of hanging.
        backend
            .request("refresh", Map::new())
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        backend.shutdown();
        assert!(
            marker.exists(),
            "runtime must exit on its own after stdin closes"
        );
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn oversized_output_and_exit_are_reported_once() {
        let (backend, rx) = start("head -c 4000001 /dev/zero | tr '\\0' a; read eof");
        assert_eq!(
            next(&rx),
            Output::Error("Wallet response too large. Reopen Zark.".into())
        );
        backend.shutdown();
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
        let (stopped, rx) = start("exit 0");
        assert_eq!(
            next(&rx),
            Output::Error("Wallet stopped. Reopen Zark.".into())
        );
        assert!(!stopped.is_running());
    }
}
