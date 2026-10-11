//! Real Zark TLS/process regression. Uses the externally qualified suite
//! supplied explicitly by the test operator. No proof oracle, Bitcoin node,
//! existing signer, or user wallet participates; no signature is released.
use anyhow::{Context, Result, ensure};
use k256::schnorr::SigningKey;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command as Process, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zark_protocol::{
    deployment::{Deployment, Manifest},
    handoff::{TransferContext, origin_previous_state},
    hash,
    network::{Network, REGTEST_GENESIS},
    random_scalar, random32,
    remote::{RemoteEndpoint, RemoteFailure},
    wire::{Command, Request},
};

struct Fixture {
    root: PathBuf,
    child: Option<Child>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root =
            std::env::temp_dir().join(format!("zark-private-tls-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        Ok(Self {
            root: root.canonicalize()?,
            child: None,
        })
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = self.root.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn digest_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}
fn expected_failure(endpoint: &RemoteEndpoint, request: &Request, code: &str) -> Result<()> {
    let error = endpoint
        .request(request)
        .err()
        .context("request unexpectedly succeeded")?;
    ensure!(
        error
            .downcast_ref::<RemoteFailure>()
            .is_some_and(|error| error.code == code),
        "wrong private TLS error: {error}"
    );
    Ok(())
}

/// Exercise protocol negotiation without retaining an alternate wire client.
/// No credential or application request is sent on this rejected connection.
fn reject_unsupported_alpn(endpoint: &RemoteEndpoint) -> Result<()> {
    let mut roots = rustls::RootCertStore::empty();
    let certificate = fs::read(&endpoint.ca_certificate)?;
    for certificate in rustls_pemfile::certs(&mut certificate.as_slice()) {
        roots.add(certificate?)?;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"unsupported-protocol/0".to_vec()];
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), endpoint.server_name.clone().try_into()?)?;
    let mut socket = TcpStream::connect_timeout(&endpoint.address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    ensure!(
        connection.complete_io(&mut socket).is_err(),
        "unsupported ALPN accepted"
    );
    Ok(())
}

type MailConnection = BufReader<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>;

fn mail_connect(endpoint: &RemoteEndpoint, alpn: &[u8]) -> Result<MailConnection> {
    let mut roots = rustls::RootCertStore::empty();
    let pem = fs::read(&endpoint.ca_certificate)?;
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(cert?)?;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    let conn =
        rustls::ClientConnection::new(Arc::new(config), endpoint.server_name.clone().try_into()?)?;
    let socket = TcpStream::connect_timeout(&endpoint.address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut tls = rustls::StreamOwned::new(conn, socket);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    ensure!(tls.conn.alpn_protocol() == Some(alpn), "mail ALPN");
    ensure!(
        hex::encode(hash(&[tls.conn.peer_certificates().unwrap()[0].as_ref()]))
            == endpoint.certificate_sha256,
        "mail pin"
    );
    Ok(BufReader::new(tls))
}

fn mail_exchange(tls: &mut MailConnection, value: serde_json::Value) -> Result<serde_json::Value> {
    tls.get_mut().write_all(format!("{value}\n").as_bytes())?;
    tls.get_mut().flush()?;
    let mut result = Vec::new();
    tls.take(zark_protocol::mail::MAX_WIRE as u64)
        .read_until(b'\n', &mut result)?;
    ensure!(result.last() == Some(&b'\n'), "mail reply framing");
    Ok(serde_json::from_slice(&result)?)
}

fn mail_request(endpoint: &RemoteEndpoint, value: serde_json::Value) -> Result<serde_json::Value> {
    mail_exchange(
        &mut mail_connect(endpoint, zark_protocol::mail::ALPN)?,
        value,
    )
}

#[test]
#[ignore = "requires qualified ZARK_TEST_SUITE, ZARK_TEST_BB, ZARK_TEST_CRS and local TCP permission"]
fn listener_pins_tls_scopes_replays_and_rejects_unsupported_protocol() -> Result<()> {
    let suite = PathBuf::from(std::env::var("ZARK_TEST_SUITE")?).canonicalize()?;
    let bb = PathBuf::from(std::env::var("ZARK_TEST_BB")?).canonicalize()?;
    let crs = PathBuf::from(std::env::var("ZARK_TEST_CRS")?).canonicalize()?;
    let manifest_path = suite.join("suite-manifest.json");
    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest.validate()?;
    let mut fixture = Fixture::new()?;
    for directory in ["db", "independent"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(fixture.root.join(directory))?;
    }
    let control = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let origin = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let control_file = fixture.write("control.key", &control.to_bytes())?;
    let origin_file = fixture.write("origin.key", &origin.to_bytes())?;
    let deployment = Deployment {
        protocol_version: 10,
        signer_protocol_version: zark_protocol::deployment::SIGNER_PROTOCOL_VERSION,
        network: Network::Regtest,
        genesis_hash: REGTEST_GENESIS.into(),
        signet_challenge: String::new(),
        initial_delay: 480,
        gap: 60,
        margin: 6,
        control_key: hex::encode(control.verifying_key().to_bytes()),
        origin_key: hex::encode(origin.verifying_key().to_bytes()),
        suite: hex::encode(manifest.id()?),
    };
    let deployment_file = fixture.write("deployment.json", &serde_json::to_vec(&deployment)?)?;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = fixture.write("certificate.pem", cert.cert.pem().as_bytes())?;
    let tls_key = fixture.write("tls.key", cert.signing_key.serialize_pem().as_bytes())?;
    let reservation = TcpListener::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?;
    drop(reservation);
    let coin = random32();
    let token = hex::encode(random32());
    let token_file = fixture.write("token", token.as_bytes())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut hosted = json!({"version":10,"listen":address,"certificate":certificate,"private_key":tls_key,
        "credentials":[{"sha256":hex::encode(hash(&[token.as_bytes()])),"coins":[hex::encode(coin)],
            "expires_at":now+3600,"max_inflight":2,"requests_per_minute":60}],
        "network_workers":2,"proof_workers":1,"queue_capacity":4});
    hosted["messaging"] =
        json!({"directory":fixture.root.join("messaging"),"requests_per_minute":1200});
    let hosted_file = fixture.write("hosted.json", &serde_json::to_vec(&hosted)?)?;
    let config = json!({"version":10,
        "deployment":{"path":deployment_file,"sha256":digest_file(&deployment_file)?},
        "manifest":{"path":manifest_path,"sha256":digest_file(&manifest_path)?},
        "suite_directory":suite,"bb":{"path":bb,"sha256":digest_file(&bb)?},
        "crs":{"directory":crs,"bn254_g1_sha256":digest_file(&crs.join("bn254_g1.dat"))?,
            "bn254_g1_compressed_sha256":digest_file(&crs.join("bn254_g1_compressed.dat"))?},
        "database":fixture.root.join("db/signer-v9.sqlite"),"checkpoint":fixture.root.join("independent/checkpoint.json"),
        "control_key":control_file,"origin_key":origin_file,"hosted":hosted_file});
    let config_file = fixture.write("signer.json", &serde_json::to_vec(&config)?)?;
    let binary = env!("CARGO_BIN_EXE_zark-signer");
    ensure!(
        Process::new(binary)
            .args(["--config", config_file.to_str().unwrap(), "--check-config"])
            .stdout(Stdio::null())
            .status()?
            .success(),
        "configuration preflight failed"
    );
    ensure!(
        !fixture.root.join("db/signer-v9.sqlite").exists(),
        "preflight created signer state"
    );
    let stderr = fixture.write("stderr.log", b"")?;
    fixture.child = Some(
        Process::new(binary)
            .arg("--config")
            .arg(&config_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::OpenOptions::new().append(true).open(&stderr)?)
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if TcpStream::connect(address).is_ok() {
            break;
        }
        ensure!(
            fixture.child.as_mut().unwrap().try_wait()?.is_none(),
            "private listener failed: {}",
            fs::read_to_string(&stderr)?
        );
        ensure!(
            Instant::now() < deadline,
            "private listener startup timeout"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let endpoint = RemoteEndpoint {
        address,
        server_name: "localhost".into(),
        ca_certificate: certificate,
        certificate_sha256: hex::encode(hash(&[cert.cert.der().as_ref()])),
        credential_file: Some(token_file.clone()),
        timeout_secs: 5,
    };
    let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let context = TransferContext {
        start_revision: 0,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: deployment.id()?,
        coin,
        previous_state: origin_previous_state(&deployment.id()?, &coin)?,
        operation: random32(),
        recipient_claim: random32(),
        session_auth: session.verifying_key().to_bytes().into(),
    };
    let request = Request::sign(context.clone(), Command::BootstrapAllocate {}, &session)?;
    let checkpoint = fixture.root.join("independent/checkpoint.json");
    let before = fs::read(&checkpoint)?;
    // Both protocols use the same listener. Mail writes never advance coin state.
    let mail = |method: &str, path: &str, body: serde_json::Value, bearer: Option<&str>| {
        mail_request(
            &endpoint,
            json!({"version":1,"method":method,"path":path,"body":body,"bearer":bearer}),
        )
    };
    ensure!(
        mail("GET", "/health", serde_json::Value::Null, None)?["ok"] == true,
        "mail service unavailable"
    );
    // More idle sessions than ingress workers must not monopolize those workers.
    let health = json!({"version":1,"method":"GET","path":"/health","body":null});
    let mut idle = Vec::new();
    for _ in 0..3 {
        let mut connection = mail_connect(&endpoint, zark_protocol::mail::SESSION_ALPN)?;
        ensure!(
            mail_exchange(&mut connection, health.clone())?["ok"] == true,
            "session health"
        );
        idle.push(connection);
    }
    ensure!(
        mail("GET", "/health", serde_json::Value::Null, None)?["ok"] == true,
        "idle mail occupied ingress"
    );
    for connection in &mut idle {
        ensure!(
            mail_exchange(connection, health.clone())?["ok"] == true,
            "mail session reuse"
        );
    }
    // Every reused frame reloads hosting policy; live TLS retains no permission.
    let mut disabled = hosted.clone();
    disabled.as_object_mut().unwrap().remove("messaging");
    fs::write(&hosted_file, serde_json::to_vec(&disabled)?)?;
    ensure!(
        mail_exchange(&mut idle[0], health)?["ok"] == false,
        "reused mail bypassed hosting policy"
    );
    fs::write(&hosted_file, serde_json::to_vec(&hosted)?)?;
    drop(idle);
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let key = SigningKey::from_bytes(&[17; 32])?;
    let envelope = k256::SecretKey::from_slice(&[18; 32])?
        .public_key()
        .to_encoded_point(true);
    let mut claim = [0; 33];
    claim[0] = 2;
    claim[1..].copy_from_slice(&key.verifying_key().to_bytes());
    let receive = zark_protocol::address::ReceivingAddress::new(
        zark_protocol::address::AddressNetwork::Test,
        deployment.id()?,
        envelope.as_bytes().try_into()?,
        claim,
    )?;
    let mail_token = hex::encode(random32());
    let token_hash = hex::encode(hash(&[mail_token.as_bytes()]));
    let signature = key.sign_raw(
        &zark_protocol::mail::registration_digest(&receive, &token_hash, 60000)?,
        &random32(),
    )?;
    let register = json!({"receiveAddress":receive.encode(),"readTokenHash":token_hash,"ttlMs":60000,"signature":hex::encode(signature.to_bytes())});
    let registered = mail("POST", "/v1/mailboxes", register, None)?;
    ensure!(registered["ok"] == true, "mail registration failed");
    let path = format!(
        "/v1/mailboxes/{}/messages",
        registered["result"]["addressHash"].as_str().unwrap()
    );
    let message = json!({"id":"01".repeat(32),"ciphertext":"ab".repeat(80_000)});
    ensure!(
        mail("POST", &path, message.clone(), None)?["ok"] == true,
        "mail delivery failed"
    );
    ensure!(
        mail("GET", &path, serde_json::Value::Null, None)?["error"]["code"] == "unauthorized",
        "unauthorized mail read"
    );
    ensure!(
        mail("GET", &path, serde_json::Value::Null, Some(&mail_token))?["result"]["messages"]
            .as_array()
            .unwrap()
            .len()
            == 1,
        "mail read failed"
    );
    let mut connection = mail_connect(&endpoint, zark_protocol::mail::SESSION_ALPN)?;
    let response = mail_exchange(
        &mut connection,
        json!({"version":1,"method":"GET","path":path,"body":null,"bearer":mail_token}),
    )?;
    ensure!(
        response["result"]["messages"]
            .as_array()
            .is_some_and(|messages| messages.len() == 1),
        "session used signing response size limit"
    );
    drop(connection);
    ensure!(
        mail("POST", &path, message, None)?["error"]["code"] == "message_replayed",
        "mail replay accepted"
    );
    ensure!(
        fs::read(&checkpoint)? == before,
        "mail mutated coin checkpoint"
    );
    if let Ok(node) = std::env::var("ZARK_TEST_NODE") {
        let endpoint_file = fixture.write("node-endpoint.json", &serde_json::to_vec(&endpoint)?)?;
        let client = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../apps/desktop/relay/signer-client.mjs")
            .canonicalize()?;
        let script = "import {readFile} from 'node:fs/promises'; import {pathToFileURL} from 'node:url'; const {SignerRelayClient}=await import(pathToFileURL(process.argv[1])); const endpoint=JSON.parse(await readFile(process.argv[2])); const result=await new SignerRelayClient(endpoint,{}).health(); if(result.service!=='zark-mail') process.exit(1);";
        ensure!(
            Process::new(&node)
                .args(["--input-type=module", "-e", script])
                .arg(client)
                .arg(endpoint_file)
                .status()?
                .success(),
            "desktop TLS client interoperability"
        );
        if let Ok(wallet) = std::env::var("ZARK_TEST_WALLET") {
            // Local crypto does not load proof tools or contact Bitcoin. Deliberately
            // nonexistent paths prove these commands do not start either service.
            let unused = fixture.root.join("unused");
            let wallet_config = json!({"version":10,"deployment":deployment,
                "manifest":manifest_path,"manifest_sha256":digest_file(&manifest_path)?,
                "programs":unused,"nargo":{"path":unused,"sha256":"00".repeat(32)},
                "bb":{"path":unused,"sha256":"00".repeat(32)},"crs":unused,
                "crs_sha256":{},"bitcoin_cli_sha256":"00".repeat(32),"endpoint":endpoint,
                "chain":{"deployment":deployment,"bitcoin_cli":unused,"datadir":unused,
                    "rpc_cookie":null,"rpc_port":1,"minimum_confirmations":1}});
            let config = fixture.write("wallet.json", &serde_json::to_vec(&wallet_config)?)?;
            let smoke = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../apps/desktop/relay/host-smoke.mjs");
            ensure!(
                Process::new(&node)
                    .arg(smoke)
                    .arg(config)
                    .arg(wallet)
                    .arg(&fixture.root)
                    .status()?
                    .success(),
                "native wallet mail interoperability"
            );
            ensure!(
                fs::read(&checkpoint)? == before,
                "desktop mail mutated coin checkpoint"
            );
        }
    }
    let mut wrong_pin = endpoint.clone();
    wrong_pin.certificate_sha256 = hex::encode([8; 32]);
    wrong_pin.credential_file = Some(fixture.root.join("not-loaded-before-TLS-pin"));
    let error = wrong_pin
        .request(&request)
        .err()
        .context("wrong pin accepted")?;
    ensure!(
        error.to_string().contains("fingerprint"),
        "credential was loaded before TLS pin: {error}"
    );
    reject_unsupported_alpn(&endpoint)?;
    fs::write(&token_file, hex::encode(random32()))?;
    expected_failure(&endpoint, &request, "unauthorized")?;
    ensure!(
        before == fs::read(&checkpoint)?,
        "rejected requests changed checkpoint"
    );
    fs::write(&token_file, &token)?;
    let allocated = endpoint.request(&request)?;
    ensure!(
        allocated["parent_server"]
            .as_array()
            .is_some_and(|v| v.len() == 64)
            && allocated["active_server"]
                .as_array()
                .is_some_and(|v| v.len() == 64)
            && allocated.get("partial").is_none(),
        "unexpected bootstrap allocation response"
    );
    ensure!(
        allocated == endpoint.request(&request)?,
        "exact allocation retry changed frozen shares"
    );
    // Early connections wait outside the network workers until their request
    // arrives, so more of them than workers cannot stall other peers.
    let started = Instant::now();
    let mut early = Vec::new();
    for _ in 0..3 {
        early.push(mail_connect(
            &endpoint,
            zark_protocol::remote::EARLY_SESSION_ALPN,
        )?);
    }
    ensure!(
        mail("GET", "/health", serde_json::Value::Null, None)?["ok"] == true
            && started.elapsed() < Duration::from_secs(4),
        "idle early connections occupied ingress"
    );
    let retry = json!({"method":"zark_request","credential":token,
        "request":String::from_utf8(request.encode()?.to_vec())?});
    for connection in &mut early {
        ensure!(
            mail_exchange(connection, retry.clone())?["result"]["response"] == allocated,
            "early connection changed the exact allocation retry"
        );
    }
    drop(early);
    // A thread without a pooled session uses the wallet's own early connection.
    let (early_endpoint, early_request) = (endpoint.clone(), request.clone());
    let preconnected = thread::spawn(move || {
        early_endpoint.preconnect();
        early_endpoint.request(&early_request)
    })
    .join()
    .unwrap()?;
    ensure!(
        allocated == preconnected,
        "preconnected exact retry changed frozen shares"
    );
    let after = fs::read(&checkpoint)?;
    let mut foreign = context.clone();
    foreign.coin = random32();
    foreign.previous_state = origin_previous_state(&foreign.deployment, &foreign.coin)?;
    expected_failure(
        &endpoint,
        &Request::sign(foreign, Command::BootstrapAllocate {}, &session)?,
        "unauthorized",
    )?;
    hosted["credentials"] = json!([]);
    fs::write(&hosted_file, serde_json::to_vec(&hosted)?)?;
    expected_failure(&endpoint, &request, "unauthorized")?;
    // Cancellation crosses hosted admission after revocation, but the engine
    // rejects this bootstrap operation: no ordinary reservation was admitted.
    let cancellation = Request::sign(context.clone(), Command::CancelTransfer {}, &session)?;
    expected_failure(&endpoint, &cancellation, "invalid_request")?;
    let retrieval = Request::sign(
        context,
        Command::RetrieveBootstrap {
            binding_digest: [9; 32],
        },
        &session,
    )?;
    expected_failure(&endpoint, &retrieval, "invalid_request")?; // Not released, despite retrieval credential exception.
    ensure!(
        after == fs::read(&checkpoint)?,
        "scope/revocation/retrieval failures changed checkpoint"
    );

    // Enabling public access must admit a new wallet and new coin without any
    // registered token, while the same Engine enforces ownership and phases.
    hosted["public_access"] =
        json!({"max_inflight":2,"requests_per_minute":60,"allocations_per_minute":10});
    fs::write(&hosted_file, serde_json::to_vec(&hosted)?)?;
    let mut public_endpoint = endpoint.clone();
    public_endpoint.credential_file = None;
    let newcomer = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let new_coin = random32();
    let mut public_context = TransferContext {
        start_revision: 0,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: deployment.id()?,
        coin: new_coin,
        previous_state: origin_previous_state(&deployment.id()?, &new_coin)?,
        operation: random32(),
        recipient_claim: random32(),
        session_auth: newcomer.verifying_key().to_bytes().into(),
    };
    let public_allocate = Request::sign(
        public_context.clone(),
        Command::BootstrapAllocate {},
        &newcomer,
    )?;
    let allocation = public_endpoint.request(&public_allocate)?;
    ensure!(
        allocation["parent_server"]
            .as_array()
            .is_some_and(|v| v.len() == 64)
            && allocation.get("partial").is_none(),
        "public allocation released signing material"
    );
    ensure!(
        allocation == public_endpoint.request(&public_allocate)?,
        "public allocation retry changed shares"
    );
    let public_floor = fs::read(&checkpoint)?;

    let mut takeover = request.context.clone();
    takeover.session_auth = newcomer.verifying_key().to_bytes().into();
    expected_failure(
        &public_endpoint,
        &Request::sign(takeover, Command::BootstrapAllocate {}, &newcomer)?,
        "invalid_request",
    )?;
    public_context.deployment = random32();
    expected_failure(
        &public_endpoint,
        &Request::sign(public_context, Command::BootstrapAllocate {}, &newcomer)?,
        "invalid_request",
    )?;
    // Public access cannot retrieve unreleased material or skip proof/phase checks.
    expected_failure(
        &public_endpoint,
        &Request::sign(
            public_allocate.context.clone(),
            Command::RetrieveBootstrap {
                binding_digest: [8; 32],
            },
            &newcomer,
        )?,
        "invalid_request",
    )?;
    expected_failure(
        &public_endpoint,
        &Request::sign(
            public_allocate.context.clone(),
            Command::Reserve {
                owner_authorization: zark_protocol::owner_auth::OwnerAuthorization {
                    public_key: newcomer.verifying_key().to_bytes().into(),
                    signature: vec![0; 64],
                },
            },
            &newcomer,
        )?,
        "invalid_request",
    )?;
    ensure!(
        public_floor == fs::read(&checkpoint)?,
        "public rejected requests changed signer state"
    );

    hosted.as_object_mut().unwrap().remove("public_access");
    fs::write(&hosted_file, serde_json::to_vec(&hosted)?)?;
    expected_failure(&public_endpoint, &public_allocate, "unauthorized")?;
    expected_failure(&public_endpoint, &retrieval, "invalid_request")?;
    ensure!(
        !Process::new(binary)
            .arg("--config")
            .arg(&config_file)
            .arg("--repair-interrupted-checkpoint")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success(),
        "repair bypassed service process lock"
    );
    ensure!(
        !fs::read_to_string(&stderr)?.contains(&token),
        "host logged bearer credential"
    );
    Ok(())
}
