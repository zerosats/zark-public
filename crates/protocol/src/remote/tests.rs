//! Pinned TLS transport, framing and credential-isolation tests.
use super::*;
use crate::random32;
use rustls::{ServerConfig, ServerConnection, pki_types::PrivatePkcs8KeyDer};
use std::{fs, net::TcpListener, thread};

struct Fixture {
    root: PathBuf,
    endpoint: RemoteEndpoint,
    server: Arc<ServerConfig>,
    listener: TcpListener,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir().join(format!("statechain-tls-{}", hex::encode(random32())));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let provider = rustls::crypto::ring::default_provider();
        let mut server = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            )?;
        server.alpn_protocols = vec![ALPN.to_vec()];
        fs::write(root.join("ca.pem"), cert.cert.pem())?;
        let credential_file = root.join("credential");
        fs::write(
            &credential_file,
            "test-token-canary-0123456789abcdef0123456789abcdef",
        )?;
        fs::set_permissions(&credential_file, fs::Permissions::from_mode(0o600))?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = RemoteEndpoint {
            address: listener.local_addr()?,
            server_name: "localhost".into(),
            ca_certificate: root.join("ca.pem"),
            certificate_sha256: hex::encode(Sha256::digest(cert.cert.der().as_ref())),
            credential_file: Some(credential_file),
            timeout_secs: 3,
        };
        Ok(Self {
            root,
            endpoint,
            server: Arc::new(server),
            listener,
        })
    }
    fn serve_once(&self) -> Result<thread::JoinHandle<Option<Value>>> {
        self.serve_reply(
            serde_json::json!({"ok":true,"result":{"version":crate::handoff::PROTOCOL_VERSION,"response":{"accepted":true}}}),
        )
    }
    fn serve_reply(&self, reply: Value) -> Result<thread::JoinHandle<Option<Value>>> {
        let listener = self.listener.try_clone()?;
        let config = self.server.clone();
        Ok(thread::spawn(move || {
            let (socket, _) = listener.accept().ok()?;
            socket.set_read_timeout(Some(Duration::from_secs(4))).ok()?;
            socket
                .set_write_timeout(Some(Duration::from_secs(4)))
                .ok()?;
            let connection = ServerConnection::new(config).ok()?;
            let mut stream = StreamOwned::new(connection, socket);
            let request = read_message(&mut BufReader::new(&mut stream)).ok()?;
            write_message(&mut stream, &reply).ok()?;
            Some(request)
        }))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn read_message(reader: &mut impl BufRead) -> Result<Value> {
    let mut bytes = Vec::new();
    reader
        .take((crate::wire::MAX_WIRE * 2 + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    ensure!(
        bytes.last() == Some(&b'\n') && bytes.len() <= crate::wire::MAX_WIRE * 2,
        "bounded test request"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_message(writer: &mut impl Write, reply: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(reply)?;
    bytes.push(b'\n');
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

fn envelope() -> crate::wire::Request {
    let key = k256::schnorr::SigningKey::from_bytes(&[19; 32]).unwrap();
    let context = crate::handoff::TransferContext {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
        start_revision: 1,
        scope: crate::handoff::OperationScope::Single,
    };
    crate::wire::Request::sign(
        context,
        crate::wire::Command::Prepare {
            recovery: [6; 32],
            blinding: [7; 32],
        },
        &key,
    )
    .unwrap()
}

#[test]
fn tls_request_checks_ca_name_pin_and_keeps_context() -> Result<()> {
    let fixture = Fixture::new()?;
    let server = fixture.serve_once()?;
    let signed = envelope();
    assert_eq!(fixture.endpoint.request(&signed)?["accepted"], true);
    let received = server.join().unwrap().unwrap();
    assert_eq!(received["method"], "zark_request");
    let saved = received["request"].as_str().unwrap();
    assert_eq!(
        crate::wire::Request::decode(saved.as_bytes())?.digest()?,
        signed.digest()?
    );
    assert_eq!(
        received["credential"],
        "test-token-canary-0123456789abcdef0123456789abcdef"
    );
    Ok(())
}

#[test]
fn public_endpoint_omits_credentials_and_keeps_signed_request() -> Result<()> {
    let mut fixture = Fixture::new()?;
    fixture.endpoint.credential_file = None;
    let config = serde_json::to_value(&fixture.endpoint)?;
    assert!(config.get("credential_file").is_none());
    let endpoint: RemoteEndpoint = serde_json::from_value(config)?;
    let server = fixture.serve_once()?;
    let signed = envelope();
    assert_eq!(endpoint.request(&signed)?["accepted"], true);
    let received = server.join().unwrap().unwrap();
    assert!(received.get("credential").is_none());
    let request = crate::wire::Request::decode(received["request"].as_str().unwrap().as_bytes())?;
    request.authenticate()?;
    assert_eq!(request.digest()?, signed.digest()?);
    Ok(())
}

#[test]
fn tls_keeps_canonical_session_request_and_refuses_unsupported_alpn() -> Result<()> {
    let key = k256::schnorr::SigningKey::from_bytes(&[19; 32])?;
    let context = crate::handoff::TransferContext {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
        start_revision: 1,
        scope: crate::handoff::OperationScope::Single,
    };
    let request = crate::wire::Request::sign(
        context,
        crate::wire::Command::Prepare {
            recovery: [6; 32],
            blinding: [7; 32],
        },
        &key,
    )?;
    let mut fixture = Fixture::new()?;
    Arc::get_mut(&mut fixture.server).unwrap().alpn_protocols = vec![ALPN.to_vec()];
    let server = fixture.serve_reply(
        serde_json::json!({"ok":true,"result":{"version":crate::handoff::PROTOCOL_VERSION,"response":{"accepted":true}}}),
    )?;
    assert_eq!(fixture.endpoint.request(&request)?["accepted"], true);
    let received = server.join().unwrap().unwrap();
    assert_eq!(received["method"], "zark_request");
    let saved = received["request"].as_str().unwrap();
    assert_eq!(
        crate::wire::Request::decode(saved.as_bytes())?.digest()?,
        request.digest()?
    );
    let mut legacy = Fixture::new()?;
    Arc::get_mut(&mut legacy.server).unwrap().alpn_protocols = vec![ALPN.to_vec()];
    let server = legacy.serve_reply(
        serde_json::json!({"ok":true,"result":{"version":8,"response":{"accepted":true}}}),
    )?;
    assert!(legacy.endpoint.request(&request).is_err());
    assert!(server.join().unwrap().is_some());
    let mut unsupported = Fixture::new()?;
    Arc::get_mut(&mut unsupported.server)
        .unwrap()
        .alpn_protocols = vec![b"statechain/8".to_vec()];
    let server = unsupported.serve_once()?;
    assert!(unsupported.endpoint.request(&request).is_err());
    assert!(
        server.join().unwrap().is_none(),
        "incompatible peer received credentials or application data"
    );
    Ok(())
}

#[test]
fn untrusted_tls_peers_never_receive_credentials() -> Result<()> {
    for bad in ["pin", "hostname", "ca"] {
        let mut fixture = Fixture::new()?;
        match bad {
            "pin" => fixture.endpoint.certificate_sha256 = "00".repeat(32),
            "hostname" => fixture.endpoint.server_name = "wrong.example".into(),
            "ca" => {
                let other = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
                fs::write(&fixture.endpoint.ca_certificate, other.cert.pem())?;
            }
            _ => unreachable!(),
        }
        let server = fixture.serve_once()?;
        assert!(
            fixture.endpoint.request(&envelope()).is_err(),
            "accepted {bad}"
        );
        assert!(
            server.join().unwrap().is_none(),
            "sent application data for wrong {bad}"
        );
    }
    Ok(())
}

#[test]
fn credentials_require_private_regular_files() -> Result<()> {
    let fixture = Fixture::new()?;
    assert!(fixture.endpoint.credential().is_ok());
    let credential_file = fixture.endpoint.credential_file.as_ref().unwrap();
    fs::set_permissions(credential_file, fs::Permissions::from_mode(0o644))?;
    assert!(fixture.endpoint.credential().is_err());
    fs::remove_file(credential_file)?;
    std::os::unix::fs::symlink("ca.pem", credential_file)?;
    assert!(fixture.endpoint.credential().is_err());
    Ok(())
}

#[test]
fn untrusted_errors_do_not_echo_sensitive_details() {
    let error = decode_response(br#"{"ok":false,"error":{"code":"overloaded","message":"secret-canary","retryable":false}}"#).unwrap_err();
    let failure = error.downcast_ref::<RemoteFailure>().unwrap();
    assert!(failure.retryable);
    assert!(!format!("{error:#}").contains("secret-canary"));
    assert!(decode_response(br#"{"ok":true,"result":{},"error":{}}"#).is_err());
    assert!(decode_response(br#"{"ok":false,"result":{}}"#).is_err());
}
#[test]
fn malformed_remote_replies_do_not_echo_parser_values_or_field_names() {
    for bytes in [
        br#"{"ok":"credential-marker-do-not-print","error":{}}"#.as_slice(),
        br#"{"ok":false,"credential-marker-do-not-print":0,"error":{}}"#.as_slice(),
        br#"{"ok":false,"error":"credential-marker-do-not-print""#.as_slice(),
    ] {
        let error = decode_response(bytes).unwrap_err();
        assert_eq!(error.to_string(), "Invalid signer response");
        assert!(!format!("{error:#}").contains("credential-marker-do-not-print"));
    }
}

#[test]
fn negotiated_session_reuses_tls_but_reloads_credentials_for_each_request() -> Result<()> {
    let mut fixture = Fixture::new()?;
    Arc::get_mut(&mut fixture.server).unwrap().alpn_protocols = vec![SESSION_ALPN.to_vec()];
    let listener = fixture.listener.try_clone()?;
    let config = fixture.server.clone();
    let server = thread::spawn(move || -> Result<Vec<Value>> {
        let (socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(4)))?;
        let mut stream = BufReader::new(StreamOwned::new(ServerConnection::new(config)?, socket));
        let mut requests = Vec::new();
        for _ in 0..2 {
            requests.push(read_message(&mut stream)?);
            write_message(
                stream.get_mut(),
                &serde_json::json!({"ok":true,"result":{"version":10,"response":{"accepted":true}}}),
            )?;
        }
        Ok(requests)
    });
    let request = envelope();
    fixture.endpoint.request(&request)?;
    fs::write(
        fixture.endpoint.credential_file.as_ref().unwrap(),
        "rotated-token-0123456789abcdef0123456789abcdef",
    )?;
    fixture.endpoint.request(&request)?;
    let received = server.join().unwrap()?;
    assert_ne!(received[0]["credential"], received[1]["credential"]);
    assert_eq!(received[0]["request"], received[1]["request"]);
    Ok(())
}

fn accepted() -> Value {
    serde_json::json!({"ok":true,"result":{"version":10,"response":{"accepted":true}}})
}
fn handshake(
    socket: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<BufReader<StreamOwned<ServerConnection, TcpStream>>> {
    socket.set_read_timeout(Some(Duration::from_secs(4)))?;
    let mut stream = StreamOwned::new(ServerConnection::new(config)?, socket);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    Ok(BufReader::new(stream))
}

#[test]
fn early_connection_carries_the_next_requests_without_another_handshake() -> Result<()> {
    let mut fixture = Fixture::new()?;
    Arc::get_mut(&mut fixture.server).unwrap().alpn_protocols =
        vec![SESSION_ALPN.to_vec(), EARLY_SESSION_ALPN.to_vec()];
    let listener = fixture.listener.try_clone()?;
    let config = fixture.server.clone();
    let server = thread::spawn(move || -> Result<Vec<Value>> {
        let mut stream = handshake(listener.accept()?.0, config)?;
        ensure!(
            stream.get_ref().conn.alpn_protocol() == Some(EARLY_SESSION_ALPN),
            "early connection negotiated another protocol"
        );
        let mut requests = Vec::new();
        for _ in 0..2 {
            requests.push(read_message(&mut stream)?);
            write_message(stream.get_mut(), &accepted())?;
        }
        Ok(requests)
    });
    fixture.endpoint.preconnect();
    let request = envelope();
    fixture.endpoint.request(&request)?;
    fixture.endpoint.request(&request)?;
    let received = server.join().unwrap()?;
    assert_eq!(received[0]["request"], received[1]["request"]);
    assert_eq!(
        received[0]["credential"],
        "test-token-canary-0123456789abcdef0123456789abcdef"
    );
    fixture.listener.set_nonblocking(true)?;
    assert!(
        matches!(fixture.listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}

#[test]
fn signers_without_early_sessions_refuse_them_in_the_hello_once_per_process() -> Result<()> {
    let mut fixture = Fixture::new()?;
    Arc::get_mut(&mut fixture.server).unwrap().alpn_protocols =
        vec![SESSION_ALPN.to_vec(), ALPN.to_vec()];
    let listener = fixture.listener.try_clone()?;
    let config = fixture.server.clone();
    let server = thread::spawn(move || -> Result<Vec<bool>> {
        let mut handshakes = Vec::new();
        while handshakes.iter().filter(|accepted| **accepted).count() < 2 {
            let Ok(mut stream) = handshake(listener.accept()?.0, config.clone()) else {
                handshakes.push(false);
                continue;
            };
            handshakes.push(true);
            read_message(&mut stream)?;
            write_message(stream.get_mut(), &accepted())?;
        }
        Ok(handshakes)
    });
    fixture.endpoint.preconnect();
    fixture.endpoint.request(&envelope())?;
    // Another thread has no pooled session, but the refusal is process-wide.
    let endpoint = fixture.endpoint.clone();
    thread::spawn(move || {
        endpoint.preconnect();
        endpoint.request(&envelope())
    })
    .join()
    .unwrap()?;
    assert_eq!(server.join().unwrap()?, [false, true, true]);
    Ok(())
}

#[test]
fn closed_early_connection_is_replaced_before_any_request_bytes() -> Result<()> {
    let mut fixture = Fixture::new()?;
    Arc::get_mut(&mut fixture.server).unwrap().alpn_protocols =
        vec![SESSION_ALPN.to_vec(), EARLY_SESSION_ALPN.to_vec()];
    let listener = fixture.listener.try_clone()?;
    let config = fixture.server.clone();
    let (closed, closed_rx) = std::sync::mpsc::channel();
    let server = thread::spawn(move || -> Result<Value> {
        // Session tickets precede the close, as when a full signer drops it.
        drop(handshake(listener.accept()?.0, config.clone())?);
        closed.send(())?;
        let mut stream = handshake(listener.accept()?.0, config)?;
        let request = read_message(&mut stream)?;
        write_message(stream.get_mut(), &accepted())?;
        Ok(request)
    });
    fixture.endpoint.preconnect();
    closed_rx.recv_timeout(Duration::from_secs(4))?;
    thread::sleep(Duration::from_millis(50));
    fixture.endpoint.request(&envelope())?;
    assert_eq!(server.join().unwrap()?["method"], "zark_request");
    Ok(())
}

#[test]
fn lost_session_reply_is_not_replayed_on_a_new_connection() -> Result<()> {
    let mut fixture = Fixture::new()?;
    Arc::get_mut(&mut fixture.server).unwrap().alpn_protocols = vec![SESSION_ALPN.to_vec()];
    let listener = fixture.listener.try_clone()?;
    let config = fixture.server.clone();
    let server = thread::spawn(move || -> Result<()> {
        let (socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(4)))?;
        let mut stream = BufReader::new(StreamOwned::new(ServerConnection::new(config)?, socket));
        read_message(&mut stream)?;
        write_message(
            stream.get_mut(),
            &serde_json::json!({"ok":true,"result":{"version":10,"response":{"accepted":true}}}),
        )?;
        read_message(&mut stream)?;
        // Simulate a committed mutation whose response was lost.
        Ok(())
    });
    fixture.endpoint.request(&envelope())?;
    assert!(fixture.endpoint.request(&envelope()).is_err());
    server.join().unwrap()?;
    fixture.listener.set_nonblocking(true)?;
    assert!(
        matches!(fixture.listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}
