use super::*;

#[test]
fn lock_contention_is_retryable_but_persistence_failures_are_not() {
    for message in [
        "checkpoint busy: admission capacity",
        "checkpoint busy: admission deadline",
        "checkpoint busy: lock deadline",
        "proof verification busy: lock deadline",
        "private coin capacity reached",
        "batch capacity reached",
    ] {
        assert_eq!(
            classify(&anyhow::anyhow!(message)),
            failure("overloaded", true)
        );
    }
    assert_eq!(
        classify(&anyhow::anyhow!("private request deadline exceeded")),
        failure("timeout", true)
    );
    assert_eq!(
        classify(&anyhow::anyhow!("stale private checkpoint floor")),
        failure("invalid_request", false)
    );
}
use k256::schnorr::SigningKey;
use zark_protocol::handoff::TransferContext;

type Client = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;
fn early_tls() -> Result<(Arc<ServerConfig>, Arc<rustls::ClientConfig>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;
    server.alpn_protocols = vec![zark_protocol::remote::EARLY_SESSION_ALPN.to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone())?;
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = server.alpn_protocols.clone();
    Ok((Arc::new(server), Arc::new(client)))
}
fn early_pair(
    listener: &TcpListener,
    (server, client): &(Arc<ServerConfig>, Arc<rustls::ClientConfig>),
    deadline: Instant,
) -> Result<(Tls, Client)> {
    let address = listener.local_addr()?;
    let client = client.clone();
    let connecting = thread::spawn(move || -> Result<Client> {
        let socket = TcpStream::connect(address)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        let name = rustls::pki_types::ServerName::try_from("localhost")?;
        let mut stream =
            rustls::StreamOwned::new(rustls::ClientConnection::new(client, name)?, socket);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        Ok(stream)
    });
    let mut stream = StreamOwned::new(
        ServerConnection::new(server.clone())?,
        DeadlineStream {
            stream: listener.accept()?.0,
            deadline,
        },
    );
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    Ok((stream, connecting.join().unwrap()?))
}

#[test]
fn early_connections_wait_for_requests_outside_network_workers() -> Result<()> {
    let tls = early_tls()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let (ingress, arrivals) = mpsc::sync_channel::<(Ingress, Instant)>(4);
    let pool = keepalive::start(ingress.clone(), 1, Held::FirstRequests);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut held, mut client) = early_pair(&listener, &tls, deadline)?;
    assert!(!keepalive::request_started(&mut held)?);
    keepalive::hold(&pool, &ingress, held);
    // A full pool returns the next one to a worker, which waits as before.
    let (overflow, _overflow_client) = early_pair(&listener, &tls, deadline)?;
    thread::sleep(Duration::from_millis(50));
    keepalive::hold(&pool, &ingress, overflow);
    let Ok((Ingress::Handshaken(returned), _)) = arrivals.recv_timeout(Duration::from_secs(2))
    else {
        panic!("full pool dropped an early connection");
    };
    assert_eq!(returned.sock.deadline, deadline);
    assert!(
        arrivals.recv_timeout(Duration::from_millis(100)).is_err(),
        "idle early connection reached a worker"
    );
    client.write_all(b"request\n")?;
    client.flush()?;
    let Ok((Ingress::Handshaken(mut arrived), _)) = arrivals.recv_timeout(Duration::from_secs(2))
    else {
        panic!("request did not resume its early connection");
    };
    assert_eq!(arrived.sock.deadline, deadline);
    assert!(keepalive::request_started(&mut arrived)?);
    let mut line = String::new();
    BufReader::new(&mut *arrived).read_line(&mut line)?;
    assert_eq!(line, "request\n");

    // Holding never extends the network deadline set at accept.
    let (expiring, mut late) =
        early_pair(&listener, &tls, Instant::now() + Duration::from_millis(300))?;
    keepalive::hold(&pool, &ingress, expiring);
    thread::sleep(Duration::from_millis(600));
    let _ = late.write_all(b"late\n").and_then(|_| late.flush());
    assert!(
        arrivals.recv_timeout(Duration::from_millis(200)).is_err(),
        "expired early connection reached a worker"
    );
    Ok(())
}

#[test]
fn public_starts_are_bounded_and_cannot_consume_reserved_lanes() -> Result<()> {
    let config = HostedConfig::parse(&serde_json::to_vec(&json!({
        "version":10,"listen":"127.0.0.1:1","certificate":"unused","private_key":"unused",
        "network_workers":1,"proof_workers":1,"queue_capacity":1,
        "public_access":{"max_inflight":2,"requests_per_minute":10,"allocations_per_minute":1}
    }))?)?;
    let key = SigningKey::from_bytes(&[9; 32])?;
    let context = TransferContext {
        start_revision: 0,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
    };
    let request = Request::sign(context.clone(), Command::BootstrapAllocate {}, &key)?;
    let usage: UsageMap = Arc::default();
    let continued: UsageMap = Arc::default();
    let recovered: UsageMap = Arc::default();
    let peer = "127.0.0.1".parse()?;
    drop(admit_start(&config, &usage, &request, None, peer)?);
    assert!(admit_start(&config, &usage, &request, None, peer).is_err());
    // A fresh session and peer cannot evade the allocation-wide rate cap.
    let other = SigningKey::from_bytes(&[10; 32])?;
    let mut rotated = context.clone();
    rotated.session_auth = other.verifying_key().to_bytes().into();
    let rotated = Request::sign(rotated, Command::BootstrapAllocate {}, &other)?;
    assert!(admit_start(&config, &usage, &rotated, None, "127.0.0.2".parse()?).is_err());
    let exit = Request::sign(
        context,
        Command::ExitPrepare {
            funding: [1; 32],
            server_share: [2; 32],
            capability: [3; 32],
            exit: [4; 32],
            blinding: [5; 32],
            owner_authorization: placeholder_owner_authorization(),
        },
        &key,
    )?;
    let _exit_permits = admit_start(&config, &continued, &exit, None, peer)?;
    let _recovery_permit = admit(&recovered, "session:owner".into(), 2, 60)?;
    // Hosting permission does not authorize the placeholder ownership signature.
    // The engine's native-owner and proof tests cover that boundary separately.
    let mut private = config.clone();
    private.public_access = None;
    assert!(
        private
            .authorize(None, &hex::encode(request.context.coin))
            .is_err()
    );
    assert!(!private.admits_coin(&hex::encode(request.context.coin))?);
    Ok(())
}

#[test]
fn public_configuration_limits_are_validated() -> Result<()> {
    let original = json!({"version":10,"listen":"127.0.0.1:1","certificate":"unused","private_key":"unused",
        "network_workers":1,"proof_workers":1,"queue_capacity":1,
        "public_access":{"max_inflight":2,"requests_per_minute":10,"allocations_per_minute":1}});
    for (field, value) in [
        ("max_inflight", 0),
        ("max_inflight", 9),
        ("requests_per_minute", 601),
        ("allocations_per_minute", 11),
        ("peer_max_inflight", 0),
        ("peer_max_inflight", 9),
        ("peer_requests_per_minute", 0),
        ("peer_requests_per_minute", 601),
        ("peer_allocations_per_minute", 0),
        ("peer_allocations_per_minute", 61),
    ] {
        let mut changed = original.clone();
        changed["public_access"][field] = json!(value);
        assert!(HostedConfig::parse(&serde_json::to_vec(&changed)?).is_err());
    }
    let defaults = HostedConfig::parse(&serde_json::to_vec(&original)?)?;
    assert_eq!(defaults.storage_limits.coins, 10_000);
    assert_eq!(defaults.storage_limits.batches, 10_000);
    assert_eq!(
        defaults.public_access.unwrap().peer_allocations_per_minute,
        12
    );
    for (field, value) in [
        ("coins", 0),
        ("coins", 10_001),
        ("batches", 0),
        ("batches", 10_001),
    ] {
        let mut changed = original.clone();
        changed["storage_limits"] = json!({"coins":10000,"batches":10000});
        changed["storage_limits"][field] = json!(value);
        assert!(HostedConfig::parse(&serde_json::to_vec(&changed)?).is_err());
    }
    let mut changed = original.clone();
    changed["storage_limits"] = json!({"coins":2,"batches":1});
    let config = HostedConfig::parse(&serde_json::to_vec(&changed)?)?;
    assert_eq!(config.storage_limits.coins, 2);
    assert_eq!(config.storage_limits.batches, 1);
    Ok(())
}

#[test]
fn allocation_peer_limit_cannot_be_rotated_or_spend_another_peers_budget() -> Result<()> {
    let config = HostedConfig::parse(&serde_json::to_vec(&json!({
        "version":10,"listen":"127.0.0.1:1","certificate":"unused","private_key":"unused",
        "network_workers":1,"proof_workers":1,"queue_capacity":1,
        "public_access":{"max_inflight":8,"requests_per_minute":60,"allocations_per_minute":3,
            "peer_allocations_per_minute":1,"peer_requests_per_minute":60}
    }))?)?;
    let key = SigningKey::from_bytes(&[9; 32])?;
    let mut context = TransferContext {
        start_revision: 0,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
    };
    let request = Request::sign(context.clone(), Command::BootstrapAllocate {}, &key)?;
    let usage: UsageMap = Arc::default();
    drop(admit_start(
        &config,
        &usage,
        &request,
        None,
        "127.0.0.1".parse()?,
    )?);
    let other = SigningKey::from_bytes(&[10; 32])?;
    context.session_auth = other.verifying_key().to_bytes().into();
    context.coin = [8; 32];
    let rotated = Request::sign(context.clone(), Command::BootstrapAllocate {}, &other)?;
    for peer in ["127.0.0.1", "::ffff:127.0.0.1"] {
        assert!(admit_start(&config, &usage, &rotated, None, peer.parse()?).is_err());
    }
    drop(admit_start(
        &config,
        &usage,
        &rotated,
        None,
        "127.0.0.2".parse()?,
    )?);
    drop(admit_start(
        &config,
        &usage,
        &rotated,
        None,
        "127.0.0.3".parse()?,
    )?);
    assert!(admit_start(&config, &usage, &rotated, None, "127.0.0.4".parse()?).is_err());
    // Hitting the allocation-only budget does not consume a transfer-start slot.
    let transfer = Request::sign(
        context,
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &other,
    )?;
    drop(admit_start(
        &config,
        &usage,
        &transfer,
        None,
        "127.0.0.1".parse()?,
    )?);
    Ok(())
}

#[test]
fn globally_rejected_allocations_do_not_fill_peer_bookkeeping() -> Result<()> {
    let config = HostedConfig::parse(&serde_json::to_vec(&json!({
        "version":10,"listen":"127.0.0.1:1","certificate":"unused","private_key":"unused",
        "network_workers":1,"proof_workers":1,"queue_capacity":1,
        "public_access":{"max_inflight":1,"requests_per_minute":60,"allocations_per_minute":3}
    }))?)?;
    let key = SigningKey::from_bytes(&[9; 32])?;
    let request = Request::sign(
        TransferContext {
            start_revision: 0,
            scope: zark_protocol::handoff::OperationScope::Single,
            deployment: [1; 32],
            coin: [2; 32],
            previous_state: [3; 32],
            operation: [4; 32],
            recipient_claim: [5; 32],
            session_auth: key.verifying_key().to_bytes().into(),
        },
        Command::BootstrapAllocate {},
        &key,
    )?;
    let usage: UsageMap = Arc::default();
    let held = admit_start(&config, &usage, &request, None, "127.0.0.1".parse()?)?;
    let before = usage.lock().unwrap().len();
    for suffix in 1..=1024u128 {
        let peer = std::net::Ipv6Addr::from((0x2001_0db8u128 << 96) | suffix).into();
        assert!(admit_start(&config, &usage, &request, None, peer).is_err());
    }
    assert_eq!(usage.lock().unwrap().len(), before);
    drop(held);
    drop(admit_start(
        &config,
        &usage,
        &request,
        None,
        "127.0.0.2".parse()?,
    )?);
    Ok(())
}

fn placeholder_owner_authorization() -> zark_protocol::owner_auth::OwnerAuthorization {
    let key = SigningKey::from_bytes(&[17; 32]).unwrap();
    zark_protocol::owner_auth::OwnerAuthorization {
        public_key: key.verifying_key().to_bytes().into(),
        signature: vec![0; 64],
    }
}

#[test]
fn proof_free_commands_use_their_role_lane_not_their_proof_shape() {
    let (starts, _) = mpsc::sync_channel::<()>(1);
    let (continued, _) = mpsc::sync_channel::<()>(1);
    let (recovered, _) = mpsc::sync_channel::<()>(1);
    let reserve = Command::Reserve {
        owner_authorization: placeholder_owner_authorization(),
    };
    let proposed = Command::ProposeRecipient {
        statement: vec![],
        token: [1; 32],
        delta: [2; 32],
        delta_salt: [3; 32],
    };
    let ack = Command::AcknowledgeTransfer {
        state: [4; 32],
        issuance_identity: [5; 32],
    };
    for command in [&reserve, &proposed, &ack] {
        assert!(command.proof().is_none());
    }
    assert!(!continuation(&reserve));
    assert!(continuation(&proposed) && !recovery(&proposed));
    assert!(recovery(&ack));
    assert!(std::ptr::eq(
        queue_for(&reserve, &starts, &continued, &recovered),
        &starts
    ));
    assert!(std::ptr::eq(
        queue_for(&proposed, &starts, &continued, &recovered),
        &continued
    ));
    assert!(std::ptr::eq(
        queue_for(&ack, &starts, &continued, &recovered),
        &recovered
    ));
}

#[test]
fn proof_saturation_preserves_bounded_recovery_queue_and_worker() -> Result<()> {
    let (ordinary, rx) = mpsc::sync_channel(1);
    let (protected, protected_rx) = mpsc::sync_channel(1);
    let (reserved, reserved_rx) = mpsc::sync_channel(1);
    let (started, start_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    workers(rx, 1, move |job| {
        if job == 0 {
            started.send(()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
    });
    ordinary.try_send(0)?;
    start_rx.recv_timeout(Duration::from_secs(2))?;
    ordinary.try_send(1)?;
    assert!(matches!(
        ordinary.try_send(2),
        Err(mpsc::TrySendError::Full(2))
    ));

    // Even before its worker starts, the reserved queue has its own bound.
    let cancel = Command::CancelTransfer {};
    queue_for(&cancel, &ordinary, &protected, &reserved).try_send(3)?;
    assert!(matches!(
        queue_for(&cancel, &ordinary, &protected, &reserved).try_send(4),
        Err(mpsc::TrySendError::Full(4))
    ));
    let (finished, finish_rx) = mpsc::channel();
    workers(reserved_rx, RECOVERY_WORKERS, move |job| {
        finished.send(job).unwrap();
    });
    assert_eq!(finish_rx.recv_timeout(Duration::from_secs(2))?, 3);
    let retrieve = Command::RetrieveIssued {
        binding_digest: [1; 32],
    };
    queue_for(&retrieve, &ordinary, &protected, &reserved).try_send(5)?;
    assert_eq!(finish_rx.recv_timeout(Duration::from_secs(2))?, 5);
    let key = SigningKey::from_bytes(&[9; 32])?;
    let head = Command::Head {
        query: zark_protocol::head::HeadQuery::fresh(
            [1; 32],
            [2; 32],
            key.verifying_key().to_bytes().into(),
        )?,
    };
    for (job, command) in [(7, head), (8, Command::CompleteSender {})] {
        assert!(command.proof().is_none());
        queue_for(&command, &ordinary, &protected, &reserved).try_send(job)?;
        assert_eq!(finish_rx.recv_timeout(Duration::from_secs(2))?, job);
    }
    // Completion and new cooperative exit have their own bounded queue,
    // even while ordinary admission is still saturated.
    let completion = Command::AcceptOrigin {
        state: [1; 32],
        issuance_identity: [2; 32],
    };
    queue_for(&completion, &ordinary, &protected, &reserved).try_send(9)?;
    assert!(matches!(
        queue_for(&completion, &ordinary, &protected, &reserved).try_send(10),
        Err(mpsc::TrySendError::Full(10))
    ));
    queue_for(&cancel, &ordinary, &protected, &reserved).try_send(12)?;
    assert_eq!(finish_rx.recv_timeout(Duration::from_secs(2))?, 12);
    let (completed, completed_rx) = mpsc::channel();
    workers(protected_rx, CONTINUATION_WORKERS, move |job| {
        completed.send(job).unwrap();
    });
    assert_eq!(completed_rx.recv_timeout(Duration::from_secs(2))?, 9);
    let exit = Command::ExitPrepare {
        funding: [1; 32],
        server_share: [2; 32],
        capability: [3; 32],
        exit: [4; 32],
        blinding: [5; 32],
        owner_authorization: placeholder_owner_authorization(),
    };
    assert!(
        !continuation(&exit),
        "new exit must still require a credential"
    );
    queue_for(&exit, &ordinary, &protected, &reserved).try_send(11)?;
    assert_eq!(completed_rx.recv_timeout(Duration::from_secs(2))?, 11);
    // The expensive lane remains full until explicitly released.
    assert!(matches!(
        ordinary.try_send(6),
        Err(mpsc::TrySendError::Full(6))
    ));
    release.send(())?;
    Ok(())
}

#[test]
fn session_admission_remains_bounded_and_independent_of_ordinary_load() -> Result<()> {
    let ordinary: UsageMap = Arc::default();
    let recovery_usage: UsageMap = Arc::default();
    let mut permits = Vec::new();
    for i in 0..1024 {
        permits.push(admit(&ordinary, format!("credential:{i}"), 1, 1)?);
    }
    assert!(admit(&ordinary, "overflow".into(), 1, 1).is_err());
    let first = admit(&recovery_usage, "session:owner".into(), 2, 3)?;
    let second = admit(&recovery_usage, "session:owner".into(), 2, 3)?;
    assert!(admit(&recovery_usage, "session:owner".into(), 2, 3).is_err());
    drop(first);
    let third = admit(&recovery_usage, "session:owner".into(), 2, 3)?;
    drop(second);
    drop(third);
    assert!(admit(&recovery_usage, "session:owner".into(), 2, 3).is_err());
    Ok(())
}

#[test]
fn expiry_and_revocation_do_not_block_signed_continuations_or_admit_new_starts() -> Result<()> {
    let key = SigningKey::from_bytes(&[9; 32])?;
    let context = TransferContext {
        start_revision: 0,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
    };
    let directory = std::env::temp_dir().join(format!(
        "zark-host-guard-{}",
        hex::encode(zark_protocol::random32())
    ));
    fs::create_dir(&directory)?;
    let path = directory.join("hosted.json");
    let digest = hex::encode([7; 32]);
    let mut config = json!({"version":10,"listen":"127.0.0.1:0","certificate":"unused", "private_key":"unused",
        "network_workers":1,"proof_workers":1,"queue_capacity":1,
        "credentials":[{"sha256":digest,"coins":[hex::encode(context.coin)],"expires_at":0,"max_inflight":1,"requests_per_minute":1}]});
    let result = (|| -> Result<()> {
        for revoked in [false, true] {
            if revoked {
                config["credentials"] = json!([]);
            }
            fs::write(&path, serde_json::to_vec(&config)?)?;
            for command in [
                Command::CancelTransfer {},
                Command::RetrieveIssued {
                    binding_digest: [6; 32],
                },
                Command::Prepare {
                    recovery: [6; 32],
                    blinding: [7; 32],
                },
                Command::AcceptOrigin {
                    state: [1; 32],
                    issuance_identity: [2; 32],
                },
            ] {
                let request = Request::sign(context.clone(), command, &key)?;
                request.authenticate()?;
                guard(
                    &path,
                    &request,
                    Some(&digest),
                    Instant::now() + Duration::from_secs(2),
                )?;
                assert!(guard(&path, &request, Some(&digest), Instant::now()).is_err());
            }
            for command in [
                Command::BootstrapAllocate {},
                Command::Reserve {
                    owner_authorization: placeholder_owner_authorization(),
                },
            ] {
                let request = Request::sign(context.clone(), command, &key)?;
                assert_eq!(
                    guard(
                        &path,
                        &request,
                        Some(&digest),
                        Instant::now() + Duration::from_secs(2)
                    )
                    .unwrap_err()
                    .to_string(),
                    "private credential rejected"
                );
            }
        }
        Ok(())
    })();
    fs::remove_dir_all(directory)?;
    result
}
#[test]
fn only_canonical_signed_v10_requests_enter_the_queue() -> Result<()> {
    let key = SigningKey::from_bytes(&[9; 32])?;
    let context = TransferContext {
        start_revision: 0,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
    };
    let request = Request::sign(
        context,
        Command::RetrieveIssued {
            binding_digest: [6; 32],
        },
        &key,
    )?;
    let envelope = String::from_utf8(request.encode()?.to_vec())?;
    let token = "C".repeat(64);
    let mut value = json!({"method":"zark_request","credential":token,"request":envelope});
    assert!(recovery(&decode(&serde_json::to_vec(&value)?)?.0.command));
    value["method"] = "request".into();
    assert!(decode(&serde_json::to_vec(&value)?).is_err());
    value["method"] = "zark_request".into();
    value["history"] = "private-canary".into();
    assert!(decode(&serde_json::to_vec(&value)?).is_err());
    value.as_object_mut().unwrap().remove("history");
    value["request"] = format!("{envelope} ").into();
    assert!(decode(&serde_json::to_vec(&value)?).is_err());
    assert!(
        !serde_json::to_string(&classify(&anyhow::anyhow!("private-secret-canary")))?
            .contains("canary")
    );
    Ok(())
}

#[test]
fn shared_peer_limit_can_be_raised_without_disabling_admission() -> Result<()> {
    let config = HostedConfig::parse(&serde_json::to_vec(&json!({
        "version":10,"listen":"127.0.0.1:1","certificate":"unused","private_key":"unused",
        "network_workers":8,"proof_workers":2,"queue_capacity":16,
        "public_access":{"max_inflight":8,"requests_per_minute":120,"allocations_per_minute":60,
            "peer_max_inflight":4,"peer_requests_per_minute":120},
        "messaging":{"directory":"/unused","requests_per_minute":6000,"max_inflight":8,
            "peer_max_inflight":8,"peer_requests_per_minute":3000}
    }))?)?;
    let usage: UsageMap = Arc::default();
    let mut held = Vec::new();
    for n in 1..=5 {
        let key = SigningKey::from_bytes(&[n; 32])?;
        let context = TransferContext {
            start_revision: 0,
            scope: zark_protocol::handoff::OperationScope::Single,
            deployment: [1; 32],
            coin: [2; 32],
            previous_state: [3; 32],
            operation: [4; 32],
            recipient_claim: [5; 32],
            session_auth: key.verifying_key().to_bytes().into(),
        };
        let request = Request::sign(context, Command::BootstrapAllocate {}, &key)?;
        let result = admit_start(&config, &usage, &request, None, "198.51.100.1".parse()?);
        if n <= 4 {
            held.push(result?);
        } else {
            assert!(result.is_err());
        }
    }
    Ok(())
}
