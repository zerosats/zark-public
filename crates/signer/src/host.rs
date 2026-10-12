//! Bounded, authenticated TLS data plane for the Zark signer.
//! Request bodies, peer addresses, proofs and credentials are not logged.
mod admission;
mod browser;
mod config;
mod dispatch;
mod keepalive;
mod reply;
mod transport;
use admission::{Permit, UsageMap};
#[cfg(test)]
use admission::{admit, admit_start, continuation, guard, queue_for, recovery};
pub use browser::Config as BrowserConfig;
pub use config::{Credential, HostedConfig, PublicAccess};
use dispatch::Dispatch;
use keepalive::{Held, Ingress};
use reply::Reply;
#[cfg(test)]
use transport::failure;
use transport::{DeadlineStream, Tls, classify, decode, read_request, reply, unexpired};

use crate::{engine::Engine, input::read_bounded};
use anyhow::{Context, Result, ensure};
#[cfg(test)]
use rustls::ServerConfig;
use rustls::{ServerConnection, StreamOwned};
use serde::Deserialize;
use serde_json::{Value, json};
#[cfg(test)]
use std::fs;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
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
    reply: Reply,
    request: Request,
    digest: Option<String>,
    deadline: Instant,
    queued: Instant,
    _permits: Vec<Permit>,
}
struct MailWork {
    reply: Reply,
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
    let tls = transport::tls_config(
        &config.certificate,
        &config.private_key,
        vec![
            zark_protocol::remote::SESSION_ALPN.to_vec(),
            zark_protocol::remote::EARLY_SESSION_ALPN.to_vec(),
            ALPN.to_vec(),
            zark_protocol::mail::SESSION_ALPN.to_vec(),
            zark_protocol::mail::ALPN.to_vec(),
        ],
    )?;
    let tls = Arc::new(tls);
    // Bind and validate both listeners before starting any service threads.
    let browser = config
        .browser
        .as_ref()
        .map(browser::Listener::bind)
        .transpose()?;
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
        while let Ok(job) = mail_rx.recv() {
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
            job.reply.finish(
                result.unwrap_or_else(|e| classify(&e)),
                &mail_idle,
                job._permits,
            );
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
        workers(jobs, count, move |job| {
            zark_protocol::timing::record(
                zark_protocol::timing::Phase::SignerQueue,
                job.queued.elapsed(),
            );
            let response = dispatch::execute(&engine, &path, &job);
            job.reply.finish(response, &idle_connections, job._permits);
        });
    }
    let dispatch = Dispatch {
        path: path.to_path_buf(),
        ordinary: work,
        continued: continuation_work,
        recovered: recovery_work,
        mail: mail_jobs,
        usage,
        continuation_usage,
        recovery_usage,
        mail_usage,
    };
    if let Some(browser) = browser {
        browser.start(
            dispatch.clone(),
            config.network_workers,
            config.queue_capacity,
        );
    }
    for _ in 0..config.network_workers {
        let rx = rx.clone();
        let tls = tls.clone();
        let dispatch = dispatch.clone();
        let connections = connections.clone();
        let early_connections = early_connections.clone();
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
                        // Separate budgets and worker: mailbox traffic never uses proof permits.
                        let peer = stream.sock.stream.peer_addr()?.ip().to_canonical();
                        let permits = dispatch.mail_permits(peer)?;
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
                    let permits = dispatch.signing_permits(
                        &request,
                        digest.as_deref(),
                        stream.sock.stream.peer_addr()?.ip(),
                    )?;
                    Ok(Incoming::Signing(Box::new(request), digest, permits))
                })();
                let (request, digest, permits) = match parsed {
                    Ok(Incoming::Signing(request, digest, permits)) => (*request, digest, permits),
                    Ok(Incoming::Early) => {
                        keepalive::hold(&early_connections, &connections, stream);
                        continue;
                    }
                    Ok(Incoming::Mail(request, permits)) => {
                        dispatch.messaging(Reply::Native(stream), request, permits, accepted);
                        continue;
                    }
                    Err(error) => {
                        reply(&mut stream, classify(&error));
                        continue;
                    }
                };
                dispatch.signing(Reply::Native(stream), request, digest, permits, accepted);
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
#[cfg(test)]
pub(crate) use browser::tests::signer_roundtrip as browser_test_roundtrip;
