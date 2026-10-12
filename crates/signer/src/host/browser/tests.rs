use super::http::{read_body, read_head};
use super::*;
mod fetch;
mod mail;
use k256::schnorr::SigningKey;
use std::{
    fs,
    io::{Cursor, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
};
use zark_protocol::{
    handoff::{OperationScope, TransferContext},
    wire::{Command, Request},
};

const ORIGIN: &str = "https://wallet.example.org";
const HOST: &str = "signer.example.org";
struct Fixture {
    root: PathBuf,
    dispatch: Dispatch,
    ordinary: mpsc::Receiver<super::super::Work>,
    continued: mpsc::Receiver<super::super::Work>,
    recovered: mpsc::Receiver<super::super::Work>,
    mail: mpsc::Receiver<super::super::MailWork>,
    tls: Arc<ServerConfig>,
    client: Arc<rustls::ClientConfig>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../work")
            .join(format!(
                "browser-test-{}",
                hex::encode(zark_protocol::random32())
            ));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        let certificate =
            rcgen::generate_simple_self_signed(vec![HOST.into(), "localhost".into()])?;
        let cert = root.join("certificate.pem");
        fs::write(&cert, certificate.cert.pem())?;
        let key = root.join("private.key");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key)?
            .write_all(certificate.signing_key.serialize_pem().as_bytes())?;
        let path = root.join("hosted.json");
        let config = json!({"version":10,"listen":"127.0.0.1:1","certificate":cert,"private_key":key,
            "network_workers":1,"proof_workers":1,"queue_capacity":1,
            "browser":{"listen":"127.0.0.1:0","certificate":cert,"private_key":key,
                "allowed_origins":[ORIGIN],"allowed_hosts":[HOST]},
            "public_access":{"max_inflight":1,"requests_per_minute":30,"allocations_per_minute":10},
            "messaging":{"directory":root.join("mail"),"max_inflight":4,"requests_per_minute":60,
                "peer_max_inflight":4,"peer_requests_per_minute":60}});
        fs::write(&path, serde_json::to_vec(&config)?)?;
        HostedConfig::load(&path)?;
        let (ordinary_tx, ordinary) = mpsc::sync_channel(1);
        let (continued_tx, continued) = mpsc::sync_channel(1);
        let (recovered_tx, recovered) = mpsc::sync_channel(1);
        let (mail_tx, mail) = mpsc::sync_channel(1);
        let dispatch = Dispatch {
            path,
            ordinary: ordinary_tx,
            continued: continued_tx,
            recovered: recovered_tx,
            mail: mail_tx,
            usage: Arc::default(),
            continuation_usage: Arc::default(),
            recovery_usage: Arc::default(),
            mail_usage: Arc::default(),
        };
        let tls = Arc::new(tls_config(&cert, &key, vec![b"http/1.1".to_vec()])?);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.cert.der().clone())?;
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            root,
            dispatch,
            ordinary,
            continued,
            recovered,
            mail,
            tls,
            client: Arc::new(client),
        })
    }
    fn connect(&self, request: String) -> Result<std::thread::JoinHandle<Result<String>>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let dispatch = self.dispatch.clone();
        let tls = self.tls.clone();
        thread::spawn(move || -> Result<()> {
            let socket = listener.accept()?.0;
            let accepted = Instant::now();
            handle(
                StreamOwned::new(
                    ServerConnection::new(tls)?,
                    DeadlineStream {
                        stream: socket,
                        deadline: accepted + NETWORK_LIFETIME,
                    },
                ),
                accepted,
                &dispatch,
            );
            Ok(())
        });
        let client = self.client.clone();
        Ok(thread::spawn(move || -> Result<String> {
            let socket = TcpStream::connect(address)?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut stream = rustls::StreamOwned::new(
                rustls::ClientConnection::new(client, HOST.try_into()?)?,
                socket,
            );
            stream.write_all(request.as_bytes())?;
            stream.flush()?;
            let mut reply = String::new();
            // HTTP Content-Length is authoritative; rustls also reports an
            // unclean transport EOF after the complete connection-close reply.
            match stream.read_to_string(&mut reply) {
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => (),
                Err(e) => return Err(e.into()),
            }
            Ok(reply)
        }))
    }
    fn request(&self, path: &str, body: &str) -> Result<std::thread::JoinHandle<Result<String>>> {
        self.connect(format!("POST {path} HTTP/1.1\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn signed(command: Command) -> Result<Request> {
    let key = SigningKey::from_bytes(&[9; 32])?;
    Request::sign(
        TransferContext {
            start_revision: 0,
            scope: OperationScope::Single,
            deployment: [1; 32],
            coin: [2; 32],
            previous_state: [3; 32],
            operation: [4; 32],
            recipient_claim: [5; 32],
            session_auth: key.verifying_key().to_bytes().into(),
        },
        command,
        &key,
    )
}
fn outer(request: &Request) -> Result<String> {
    Ok(serde_json::to_string(
        &json!({"method":"zark_request","request":String::from_utf8(request.encode()?.to_vec())?}),
    )?)
}

/// Test-only bridge to the real shared worker and durable Engine. No production
/// verifier, authorization path or listener is replaced by this fixture.
pub(crate) fn signer_roundtrip(engine: &crate::engine::Engine, request: &Request) -> Result<Value> {
    let f = Fixture::new()?;
    let response = f.request("/v1/signer", &outer(request)?)?;
    let queue = if super::super::admission::recovery(&request.command) {
        &f.recovered
    } else if super::super::admission::continuation(&request.command)
        || matches!(request.command, Command::ExitPrepare { .. })
    {
        &f.continued
    } else {
        &f.ordinary
    };
    let job = queue.recv_timeout(Duration::from_secs(2))?;
    assert_eq!(&*job.request.encode()?, &*request.encode()?);
    let value = super::super::dispatch::execute(engine, &f.dispatch.path, &job);
    job.reply.reject(value.clone());
    let reply = response.join().unwrap()?;
    let received: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1)?;
    assert_eq!(received, value);
    Ok(received)
}

#[test]
fn strict_framing_rejects_ambiguous_or_unbounded_http() -> Result<()> {
    for head in [
        "POST /v1/signer HTTP/1.0\r\n\r\n",
        "POST /v1/signer HTTP/1.1\n\n",
        "POST /v1/signer HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 2\r\n\r\n",
        "POST /v1/signer HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST /v1/signer HTTP/1.1\r\nContent-Encoding: gzip\r\n\r\n",
        "POST /v1/signer HTTP/1.1\r\nExpect: 100-continue\r\n\r\n",
        "POST /v1/signer HTTP/1.1\r\nCookie: secret\r\n\r\n",
        "POST /v1/signer HTTP/1.1\r\n Origin: x\r\n\r\n",
    ] {
        assert!(read_head(&mut Cursor::new(head)).is_err(), "{head}");
    }
    let huge = format!(
        "POST /v1/signer HTTP/1.1\r\nX-Test: {}\r\n\r\n",
        "a".repeat(16_384)
    );
    assert!(read_head(&mut Cursor::new(huge)).is_err());
    for length in ["-1", "9999999999999999999999999", "0", "3", "2,2"] {
        let head = read_head(&mut Cursor::new(format!(
            "POST /v1/signer HTTP/1.1\r\nContent-Length: {length}\r\n\r\n"
        )))?;
        assert!(read_body(&mut Cursor::new("{}"), &head, 2).is_err());
    }
    Ok(())
}

#[test]
fn exact_origins_hosts_and_preflight_are_enforced_before_dispatch() -> Result<()> {
    let f = Fixture::new()?;
    for (host, origin) in [
        (HOST, "https://evil.example.org"),
        (HOST, "null"),
        ("evil.example.org", ORIGIN),
        (HOST, ""),
    ] {
        let request = format!(
            "POST /v1/signer HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        let reply = f.connect(request)?.join().unwrap()?;
        assert!(reply.starts_with("HTTP/1.1 403"));
        assert!(!reply.contains("Access-Control-Allow-Origin"));
    }
    let request = format!(
        "OPTIONS /v1/signer HTTP/1.1\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type\r\n\r\n"
    );
    let reply = f.connect(request.clone())?.join().unwrap()?;
    assert!(reply.starts_with("HTTP/1.1 204"));
    assert!(reply.contains(&format!("Access-Control-Allow-Origin: {ORIGIN}")));
    assert!(!reply.contains("Allow-Credentials"));
    assert!(
        f.connect(request.replace("content-type", "authorization"))?
            .join()
            .unwrap()?
            .starts_with("HTTP/1.1 400")
    );
    assert!(f.ordinary.try_recv().is_err() && f.mail.try_recv().is_err());
    // Revocation is read from disk for the next request, without restarting.
    let mut config: Value = serde_json::from_slice(&fs::read(&f.dispatch.path)?)?;
    config["browser"] = Value::Null;
    fs::write(&f.dispatch.path, serde_json::to_vec(&config)?)?;
    assert!(
        f.connect(request)?
            .join()
            .unwrap()?
            .starts_with("HTTP/1.1 403")
    );
    Ok(())
}

#[test]
fn signed_bytes_authentication_and_shared_reserved_lanes_survive_https() -> Result<()> {
    let f = Fixture::new()?;
    let request = signed(Command::BootstrapAllocate {})?;
    let body = outer(&request)?;
    let response = f.request("/v1/signer", &body)?;
    let job = f.ordinary.recv_timeout(Duration::from_secs(2))?;
    assert_eq!(&*job.request.encode()?, &*request.encode()?);
    // Holding the HTTPS job consumes the same native admission counter.
    assert!(
        f.dispatch
            .signing_permits(&request, None, "127.0.0.1".parse()?)
            .is_err()
    );
    let recovery = signed(Command::CancelTransfer {})?;
    let recovered = f.request("/v1/signer", &outer(&recovery)?)?;
    let recovery_job = f.recovered.recv_timeout(Duration::from_secs(2))?;
    recovery_job
        .reply
        .reject(json!({"ok":true,"result":{"recovered":true}}));
    assert!(recovered.join().unwrap()?.contains("\"recovered\":true"));
    let continued = f.request(
        "/v1/signer",
        &outer(&signed(Command::Prepare {
            recovery: [6; 32],
            blinding: [7; 32],
        })?)?,
    )?;
    let continued_job = f.continued.recv_timeout(Duration::from_secs(2))?;
    continued_job
        .reply
        .reject(failure("invalid_request", false));
    assert!(continued.join().unwrap()?.contains("invalid_request"));
    job.reply
        .reject(json!({"ok":true,"result":{"version":10,"response":{"allocated":true}}}));
    drop(job._permits);
    assert!(response.join().unwrap()?.contains("\"allocated\":true"));
    let mut tampered: Value = serde_json::from_slice(&request.encode()?)?;
    tampered["signature"] = json!("00".repeat(64));
    let malformed =
        serde_json::to_string(&json!({"method":"zark_request","request":tampered.to_string()}))?;
    assert!(
        f.request("/v1/signer", &malformed)?
            .join()
            .unwrap()?
            .contains("invalid_request")
    );
    assert!(f.ordinary.try_recv().is_err());
    let mut config: Value = serde_json::from_slice(&fs::read(&f.dispatch.path)?)?;
    config["public_access"] = Value::Null;
    fs::write(&f.dispatch.path, serde_json::to_vec(&config)?)?;
    assert!(
        f.request("/v1/signer", &body)?
            .join()
            .unwrap()?
            .contains("unauthorized")
    );
    Ok(())
}

#[test]
fn browser_configuration_refuses_wildcards_paths_and_nonlocal_http() -> Result<()> {
    let f = Fixture::new()?;
    let original: Value = serde_json::from_slice(&fs::read(&f.dispatch.path)?)?;
    for origin in [
        "*",
        "null",
        "https://wallet.example.org/",
        "https://wallet.example.org:443",
        "http://wallet.example.org",
        "https://user@wallet.example.org",
        "https://wallet.example.org\r\nX: yes",
    ] {
        let mut config = original.clone();
        config["browser"]["allowed_origins"] = json!([origin]);
        assert!(
            HostedConfig::parse(&serde_json::to_vec(&config)?).is_err(),
            "{origin}"
        );
    }
    Ok(())
}

#[test]
fn same_origin_health_requires_an_explicit_https_origin_and_matching_host() -> Result<()> {
    let f = Fixture::new()?;
    let request =
        format!("GET /health HTTP/1.1\r\nHost: {HOST}\r\nSec-Fetch-Site: same-origin\r\n\r\n");
    // An allowed cross-origin wallet does not implicitly authorize hosting an
    // app on the API domain itself.
    assert!(
        f.connect(request.clone())?
            .join()
            .unwrap()?
            .starts_with("HTTP/1.1 403")
    );
    let mut config: Value = serde_json::from_slice(&fs::read(&f.dispatch.path)?)?;
    config["browser"]["allowed_origins"] = json!([ORIGIN, format!("https://{HOST}")]);
    fs::write(&f.dispatch.path, serde_json::to_vec(&config)?)?;
    let reply = f.connect(request.clone())?.join().unwrap()?;
    assert!(reply.starts_with("HTTP/1.1 200"));
    assert!(reply.contains(&format!("Access-Control-Allow-Origin: https://{HOST}")));
    assert!(
        f.connect(request.replace("same-origin", "cross-site"))?
            .join()
            .unwrap()?
            .starts_with("HTTP/1.1 403")
    );
    Ok(())
}
