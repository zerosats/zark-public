//! Measurement-only network emulation for latency qualification. Every byte and
//! every new TCP connection pays a fixed one-way delay; chain RPC follows the
//! desktop path (local bridge, pinned TLS gateway) instead of direct regtest RPC.
//! Disabled unless the flow config names it; correctness checks are unchanged.
use super::*;
use process::{OwnedProcess, private_log};
use std::{
    net::{Shutdown, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        mpsc,
    },
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkEmulation {
    one_way_delay_ms: u64,
    /// Idle time before each send/receive so pooled connections expire as they
    /// do between interactive actions.
    #[serde(default)]
    pub(crate) idle_before_transfer_ms: u64,
    node: PathBuf,
    python: PathBuf,
    chain_bridge: PathBuf,
    gateway: PathBuf,
}

#[derive(Default)]
pub(super) struct Counters {
    connections: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
}
impl Counters {
    fn snapshot(&self) -> [u64; 3] {
        [
            self.connections.load(Relaxed),
            self.up.load(Relaxed),
            self.down.load(Relaxed),
        ]
    }
}

#[derive(Default)]
pub(super) struct Stats {
    signer: Counters,
    chain: Counters,
}
impl Stats {
    pub(super) fn snapshot(&self) -> [[u64; 3]; 2] {
        [self.signer.snapshot(), self.chain.snapshot()]
    }
    pub(super) fn delta(before: [[u64; 3]; 2], after: [[u64; 3]; 2]) -> Value {
        let item = |i: usize| {
            json!({"connections":after[i][0]-before[i][0],
                "bytes_up":after[i][1]-before[i][1],"bytes_down":after[i][2]-before[i][2]})
        };
        json!({"signer":item(0),"chain":item(1)})
    }
}

pub(super) struct Emulation {
    pub(super) signer: SocketAddr,
    pub(super) stats: Arc<Stats>,
    pub(super) idle_before_transfer: Duration,
    bridge: PathBuf,
    bridge_port: u16,
    _processes: Vec<OwnedProcess>,
}

impl Emulation {
    pub(super) fn start(
        settings: &NetworkEmulation,
        run: &Path,
        signer: SocketAddr,
        node: &Regtest,
    ) -> Result<Self> {
        let delay = Duration::from_millis(settings.one_way_delay_ms);
        let stats = Arc::new(Stats::default());
        let signer = proxy(signer, delay, stats.clone(), |s| &s.signer)?;

        let directory = run.join("chain-path");
        private_dir(&directory)?;
        let certificate = rcgen::generate_simple_self_signed(vec!["chain.internal".into()])?;
        let certificate_path = directory.join("gateway.pem");
        let key_path = directory.join("gateway.key");
        write_private(&certificate_path, certificate.cert.pem().as_bytes())?;
        write_private(
            &key_path,
            certificate.signing_key.serialize_pem().as_bytes(),
        )?;
        let assets = directory.join("assets");
        private_dir(&assets)?;
        let manifest = directory.join("assets.json");
        write_private(&manifest, br#"{"version":1,"files":[]}"#)?;
        let gateway_port = free_port()?;
        let mut processes = Vec::new();
        processes.push(spawn(
            Command::new(&settings.python)
                .arg("-B")
                .arg(&settings.gateway)
                .args(["--listen", "127.0.0.1", "--port", &gateway_port.to_string()])
                .args(["--rpc-port", &node.port.to_string()])
                .arg("--assets")
                .arg(&assets)
                .arg("--manifest")
                .arg(&manifest)
                .arg("--certificate")
                .arg(&certificate_path)
                .arg("--private-key")
                .arg(&key_path)
                .arg("--rpc-auth")
                .arg(node.datadir.join("regtest/.cookie")),
            &run.join("logs/chain-gateway.log"),
        )?);
        wait_listening(gateway_port)?;
        let gateway = proxy(
            SocketAddr::from(([127, 0, 0, 1], gateway_port)),
            delay,
            stats.clone(),
            |s| &s.chain,
        )?;

        let bridge = run.join("bridge");
        private_dir(&bridge)?;
        let cookie = bridge.join(".cookie");
        write_private(
            &cookie,
            format!("__cookie__:{}\n", hex::encode(random32())).as_bytes(),
        )?;
        let bridge_port = free_port()?;
        let bridge_config = bridge.join("bridge.json");
        write_private(
            &bridge_config,
            &serde_json::to_vec(&json!({"version":1,"port":bridge_port,"cookie_file":cookie,
                "address":gateway.to_string(),"server_name":"chain.internal",
                "certificate_sha256":hex::encode(hash(&[certificate.cert.der().as_ref()]))}))?,
        )?;
        let runner = directory.join("bridge-runner.mjs");
        write_private(
            &runner,
            b"import { pathToFileURL } from 'node:url';\n\
              const [module, config, certificate] = process.argv.slice(2);\n\
              const { startBridge } = await import(pathToFileURL(module).href);\n\
              await startBridge(config, certificate);\n",
        )?;
        processes.push(spawn(
            Command::new(&settings.node)
                .arg(&runner)
                .arg(&settings.chain_bridge)
                .arg(&bridge_config)
                .arg(&certificate_path)
                .env("ZARK_TIMINGS", "1")
                .env(
                    "ZARK_TIMINGS_FILE",
                    run.join("logs/chain-bridge-timings.jsonl"),
                ),
            &run.join("logs/chain-bridge.log"),
        )?);
        wait_listening(bridge_port)?;
        Ok(Self {
            signer,
            stats,
            idle_before_transfer: Duration::from_millis(settings.idle_before_transfer_ms),
            bridge,
            bridge_port,
            _processes: processes,
        })
    }

    /// The wallet reaches regtest only through the desktop bridge credential.
    pub(super) fn chain(&self, node: &Regtest, deployment: Deployment) -> ChainConfig {
        let mut chain = node.chain(deployment);
        chain.datadir = self.bridge.clone();
        chain.rpc_cookie = Some(self.bridge.join(".cookie"));
        chain.rpc_port = self.bridge_port;
        chain
    }
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn spawn(command: &mut Command, log: &Path) -> Result<OwnedProcess> {
    let log = private_log(log)?;
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .process_group(0)
        .spawn()?;
    Ok(OwnedProcess {
        child,
        reaped: false,
    })
}

fn wait_listening(port: u16) -> Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let started = Instant::now();
    while TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err() {
        ensure!(
            started.elapsed() < Duration::from_secs(30),
            "emulated chain path did not start; inspect its private log"
        );
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn proxy(
    target: SocketAddr,
    delay: Duration,
    stats: Arc<Stats>,
    select: fn(&Stats) -> &Counters,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { continue };
            let accepted = Instant::now();
            let Ok(server) = TcpStream::connect(target) else {
                continue;
            };
            select(&stats).connections.fetch_add(1, Relaxed);
            let _ = client.set_nodelay(true);
            let _ = server.set_nodelay(true);
            let (Ok(client_read), Ok(server_read)) = (client.try_clone(), server.try_clone())
            else {
                continue;
            };
            // The client's first byte follows a TCP handshake round trip.
            let up = (accepted + 2 * delay, true);
            pump(client_read, server, delay, up, stats.clone(), select);
            pump(
                server_read,
                client,
                delay,
                (accepted, false),
                stats.clone(),
                select,
            );
        }
    });
    Ok(address)
}

fn pump(
    mut from: TcpStream,
    mut to: TcpStream,
    delay: Duration,
    (not_before, up): (Instant, bool),
    stats: Arc<Stats>,
    select: fn(&Stats) -> &Counters,
) {
    let (tx, rx) = mpsc::channel::<(Instant, Vec<u8>)>();
    thread::spawn(move || {
        let mut buffer = vec![0; 64 * 1024];
        while let Ok(n @ 1..) = from.read(&mut buffer) {
            let counters = select(&stats);
            if up { &counters.up } else { &counters.down }.fetch_add(n as u64, Relaxed);
            let due = Instant::now().max(not_before) + delay;
            if tx.send((due, buffer[..n].to_vec())).is_err() {
                break;
            }
        }
    });
    thread::spawn(move || {
        while let Ok((due, bytes)) = rx.recv() {
            thread::sleep(due.saturating_duration_since(Instant::now()));
            if to.write_all(&bytes).is_err() {
                break;
            }
        }
        let _ = to.shutdown(Shutdown::Write);
    });
}
