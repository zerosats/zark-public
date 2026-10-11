//! Bounded, authenticated TLS data plane for the Zark signer.
//! Request bodies, peer addresses, proofs and credentials are not logged.
mod admission;
mod config;
mod keepalive;
mod transport;
use admission::{Permit, UsageMap, admit, admit_start, continuation, guard, queue_for, recovery};
pub use config::{Credential, HostedConfig, PublicAccess};
use keepalive::{Held, Ingress, park};
use transport::{DeadlineStream, Tls, classify, decode, failure, read_request, reply, unexpired};

use crate::{engine::Engine, input::read_bounded};
use anyhow::{Context, Result, ensure};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zark_protocol::{
    hash, hex32,
    remote::ALPN,
    wire::{Command, MAX_WIRE, Request},
};
use zeroize::{Zeroize, Zeroizing};

const REQUEST_LIFETIME: Duration = Duration::from_secs(90);
const NETWORK_LIFETIME: Duration = Duration::from_secs(8);
const OUTER_LIMIT: usize = MAX_WIRE * 2 + 1024;
// This worker and queue cannot be occupied by proof-bearing requests. TLS
// handshakes and request parsing still share the bounded network ingress.
const RECOVERY_WORKERS: usize = 1;
const CONTINUATION_WORKERS: usize = 1;

fn workers<T: Send + 'static>(
    receiver: mpsc::Receiver<T>,
    count: usize,
    handle: impl Fn(T) + Send + Sync + 'static,
) {
    let receiver = Arc::new(Mutex::new(receiver));
    let handle = Arc::new(handle);
    for _ in 0..count {
        let receiver = receiver.clone();
        let handle = handle.clone();
        thread::spawn(move || {
            loop {
                let Ok(job) = receiver.lock().unwrap().recv() else {
                    break;
                };
                handle(job);
            }
        });
    }
}
struct Work {
    stream: Tls,
    request: Request,
    digest: Option<String>,
    deadline: Instant,
    queued: Instant,
    _permits: Vec<Permit>,
}
struct MailWork {
    stream: Tls,
    request: zark_protocol::mail::Request,
    _permits: Vec<Permit>,
    deadline: Instant,
}
enum Incoming {
    Signing(Box<Request>, Option<String>, Vec<Permit>),
    Mail(zark_protocol::mail::Request, Vec<Permit>),
    Early,
}

/// Caller constructs a pinned Engine and holds its service process lock. This
/// function exposes no import, restore, arbitrary signing or migration method.
pub fn serve(config_path: &Path, engine: Arc<Engine>) -> Result<()> {
    let config = HostedConfig::load(config_path)?;
    let listener = TcpListener::bind(config.listen)?;
    serve_listener(listener, config_path, config, engine)
}
fn serve_listener(
    listener: TcpListener,
    path: &Path,
    config: HostedConfig,
    engine: Arc<Engine>,
) -> Result<()> {
    ensure!(
        fs::symlink_metadata(&config.private_key)?.is_file()
            && fs::metadata(&config.private_key)?.permissions().mode() & 0o077 == 0,
        "private TLS key permissions"
    );
    let pem = read_bounded(&config.certificate, 1_000_000)?;
    let certs =
        rustls_pemfile::certs(&mut pem.as_slice()).collect::<std::result::Result<Vec<_>, _>>()?;
    let key_bytes = Zeroizing::new(read_bounded(&config.private_key, 1_000_000)?);
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())?.context("private TLS key")?;
    let mut tls =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![
        zark_protocol::remote::SESSION_ALPN.to_vec(),
        zark_protocol::remote::EARLY_SESSION_ALPN.to_vec(),
        ALPN.to_vec(),
        zark_protocol::mail::SESSION_ALPN.to_vec(),
        zark_protocol::mail::ALPN.to_vec(),
    ];
    let tls = Arc::new(tls);
    let (connections, rx) = mpsc::sync_channel::<(Ingress, Instant)>(config.queue_capacity);
    let idle_connections =
        keepalive::start(connections.clone(), config.queue_capacity, Held::Sessions);
    let early_connections = keepalive::start(
        connections.clone(),
        config.queue_capacity,
        Held::FirstRequests,
    );
    let rx = Arc::new(Mutex::new(rx));
    let (work, work_rx) = mpsc::sync_channel::<Work>(config.queue_capacity);
    let (continuation_work, continuation_rx) = mpsc::sync_channel::<Work>(config.queue_capacity);
    let (recovery_work, recovery_rx) = mpsc::sync_channel::<Work>(config.queue_capacity);
    let usage = Arc::new(Mutex::new(BTreeMap::new()));
    // Neither ordinary credentials nor proof-bearing continuation sessions can
    // exhaust the recovery lane's bounded admission table.
    let continuation_usage = Arc::new(Mutex::new(BTreeMap::new()));
    let recovery_usage = Arc::new(Mutex::new(BTreeMap::new()));
    let mail_usage: UsageMap = Arc::new(Mutex::new(BTreeMap::new()));
    let mail_config = config.messaging.clone();
    let deployment = engine.deployment();
    let (mail_jobs, mail_rx) = mpsc::sync_channel::<MailWork>(8);
    let mail_path = path.to_path_buf();
    let mail_idle = idle_connections.clone();
    let (started, startup) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mail_service = match mail_config
            .as_ref()
            .map(|c| crate::mail::Service::open(c, deployment))
            .transpose()
        {
            Ok(service) => {
                let _ = started.send(Ok(()));
                service
            }
            Err(error) => {
                let _ = started.send(Err(error));
                return;
            }
        };
        while let Ok(mut job) = mail_rx.recv() {
            let result = (|| -> Result<Value> {
                unexpired(job.deadline)?;
                let current = HostedConfig::load(&mail_path)?;
                ensure!(
                    current
                        .messaging
                        .as_ref()
                        .zip(mail_config.as_ref())
                        .is_some_and(|(a, b)| a.directory == b.directory),
                    "messaging disabled"
                );
                let service = mail_service.as_ref().context("messaging disabled")?;
                let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
                Ok(service.handle(job.request, now))
            })();
            let written = reply(&mut job.stream, result.unwrap_or_else(|e| classify(&e)));
            drop(job._permits);
            park(&mail_idle, job.stream, written);
        }
    });
    startup.recv().context("mail worker startup")??;
    // Each of the three queues has queue_capacity slots. Two reserved workers
    // are additional to proof_workers; actual external verification retains
    // the Engine's shared bounded FIFO and one-verifier-per-database limit.
    for (jobs, count) in [
        (work_rx, config.proof_workers),
        (continuation_rx, CONTINUATION_WORKERS),
        (recovery_rx, RECOVERY_WORKERS),
    ] {
        let engine = engine.clone();
        let path = path.to_path_buf();
        let idle_connections = idle_connections.clone();
        workers(jobs, count, move |mut job| {
            zark_protocol::timing::record(
                zark_protocol::timing::Phase::SignerQueue,
                job.queued.elapsed(),
            );
            let check = || guard(&path, &job.request, job.digest.as_deref(), job.deadline);
            let response = match check().and_then(|_| engine.handle_guarded(&job.request, check)) {
                Ok(response) => json!({"ok":true,"result":{"version":10,"response":response}}),
                Err(error) => classify(&error),
            };
            let written = reply(&mut job.stream, response);
            // Release per-request permits before admitting another frame. Every
            // request still passes parsing, admission and the fresh Engine guard.
            drop(job._permits);
            park(&idle_connections, job.stream, written);
        });
    }
    for _ in 0..config.network_workers {
        let rx = rx.clone();
        let tls = tls.clone();
        let work = work.clone();
        let continuation_work = continuation_work.clone();
        let recovery_work = recovery_work.clone();
        let usage = usage.clone();
        let continuation_usage = continuation_usage.clone();
        let recovery_usage = recovery_usage.clone();
        let mail_usage = mail_usage.clone();
        let mail_jobs = mail_jobs.clone();
        let connections = connections.clone();
        let early_connections = early_connections.clone();
        let path = path.to_path_buf();
        thread::spawn(move || {
            loop {
                let Ok((socket, accepted)) = rx.lock().unwrap().recv() else {
                    break;
                };
                if accepted.elapsed() >= NETWORK_LIFETIME {
                    continue;
                }
                let new = matches!(socket, Ingress::New(_));
                let mut stream = match socket {
                    Ingress::New(socket) => {
                        let Ok(connection) = ServerConnection::new(tls.clone()) else {
                            continue;
                        };
                        let _ = socket.set_nodelay(true);
                        StreamOwned::new(
                            connection,
                            DeadlineStream {
                                stream: socket,
                                deadline: accepted + NETWORK_LIFETIME,
                            },
                        )
                    }
                    Ingress::Reused(stream) => {
                        let mut stream = *stream;
                        stream.sock.deadline = accepted + NETWORK_LIFETIME;
                        stream
                    }
                    Ingress::Handshaken(stream) => *stream,
                };
                let parsed = (|| -> Result<Incoming> {
                    let _timing = zark_protocol::timing::Span::new(
                        zark_protocol::timing::Phase::SignerIngress,
                    );
                    while stream.conn.is_handshaking() {
                        stream.conn.complete_io(&mut stream.sock)?;
                    }
                    // Early connections exist before their request does. Waiting
                    // for one here would let idle peers hold every network worker.
                    if new
                        && stream.conn.alpn_protocol()
                            == Some(zark_protocol::remote::EARLY_SESSION_ALPN)
                        && !keepalive::request_started(&mut stream)?
                    {
                        return Ok(Incoming::Early);
                    }
                    if zark_protocol::mail::is_alpn(stream.conn.alpn_protocol()) {
                        let current = HostedConfig::load(&path)?;
                        let limits = current.messaging.context("messaging disabled")?;
                        // Separate budgets and worker: mailbox traffic never uses proof permits.
                        let peer = stream.sock.stream.peer_addr()?.ip().to_canonical();
                        let permits = vec![
                            admit(
                                &mail_usage,
                                "mail:global".into(),
                                limits.max_inflight,
                                limits.requests_per_minute,
                            )?,
                            admit(
                                &mail_usage,
                                format!("mail:peer:{peer}"),
                                limits.peer_max_inflight,
                                limits.peer_requests_per_minute,
                            )?,
                        ];
                        let bytes = read_request(&mut stream, zark_protocol::mail::MAX_WIRE)?;
                        let request = serde_json::from_slice(&bytes)
                            .map_err(|_| anyhow::anyhow!("invalid mail request"))?;
                        return Ok(Incoming::Mail(request, permits));
                    }
                    ensure!(
                        stream.conn.alpn_protocol() == Some(ALPN)
                            || zark_protocol::remote::is_session_alpn(stream.conn.alpn_protocol()),
                        "private TLS protocol mismatch"
                    );
                    let (request, digest) = decode(&read_request(&mut stream, OUTER_LIMIT)?)?;
                    let permits = if continuation(&request.command) {
                        // The Engine authenticates the frozen operation/session
                        // (and claim proof where required). Service credential
                        // expiry/revocation cannot strand admitted operations.
                        vec![admit(
                            if recovery(&request.command) {
                                &recovery_usage
                            } else {
                                &continuation_usage
                            },
                            format!("session:{}", hex::encode(request.context.session_auth)),
                            2,
                            60,
                        )?]
                    } else {
                        let current = HostedConfig::load(&path)?;
                        admit_start(
                            &current,
                            if matches!(request.command, Command::ExitPrepare { .. }) {
                                &continuation_usage
                            } else {
                                &usage
                            },
                            &request,
                            digest.as_deref(),
                            stream.sock.stream.peer_addr()?.ip(),
                        )?
                    };
                    Ok(Incoming::Signing(Box::new(request), digest, permits))
                })();
                let (request, digest, permits) = match parsed {
                    Ok(Incoming::Signing(request, digest, permits)) => (*request, digest, permits),
                    Ok(Incoming::Early) => {
                        keepalive::hold(&early_connections, &connections, stream);
                        continue;
                    }
                    Ok(Incoming::Mail(request, permits)) => {
                        let job = MailWork {
                            stream,
                            request,
                            _permits: permits,
                            deadline: accepted + NETWORK_LIFETIME,
                        };
                        if let Err(e) = mail_jobs.try_send(job) {
                            let mut job = match e {
                                mpsc::TrySendError::Full(j)
                                | mpsc::TrySendError::Disconnected(j) => j,
                            };
                            reply(&mut job.stream, failure("overloaded", true));
                        }
                        continue;
                    }
                    Err(error) => {
                        reply(&mut stream, classify(&error));
                        continue;
                    }
                };
                let job = Work {
                    stream,
                    request,
                    digest,
                    deadline: accepted + REQUEST_LIFETIME,
                    queued: Instant::now(),
                    _permits: permits,
                };
                if let Err(error) = queue_for(
                    &job.request.command,
                    &work,
                    &continuation_work,
                    &recovery_work,
                )
                .try_send(job)
                {
                    let mut job = match error {
                        mpsc::TrySendError::Full(j) | mpsc::TrySendError::Disconnected(j) => j,
                    };
                    reply(&mut job.stream, failure("overloaded", true));
                }
            }
        });
    }
    for socket in listener.incoming() {
        match socket {
            Ok(socket) => {
                let _ = connections.try_send((Ingress::New(socket), Instant::now()));
            }
            Err(_) => {
                // Temporary socket/resource exhaustion must not stop the signer.
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
