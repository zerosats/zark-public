//! End-to-end CLI/TLS deposit, transfer and exit orchestration.
use super::*;

pub(super) fn run_inner(batch: Option<BatchSenderMode>, public: bool, worker: bool) -> Result<()> {
    run_with_transfers(batch, public, worker, 2)
}

pub(super) fn run_with_transfers(
    batch: Option<BatchSenderMode>,
    public: bool,
    worker: bool,
    transfer_count: usize,
) -> Result<()> {
    ensure!(
        transfer_count == 0 || transfer_count == 2,
        "unsupported exit slot"
    );
    ensure!(
        batch.is_none() || transfer_count == 2,
        "batch requires transfer flow"
    );
    let config = Config::read()?;
    let wallet_pin = config
        .zark_wallet
        .as_ref()
        .context("CLI qualification requires zark_wallet BinaryPin")?
        .clone();
    let signer_pin = config
        .zark_signer
        .as_ref()
        .context("CLI qualification requires zark_signer BinaryPin")?
        .clone();
    pin(&wallet_pin)?;
    pin(&signer_pin)?;
    let run = config
        .run_parent
        .join(format!("zark-cli-flow-{}", hex::encode(random32())));
    private_dir(&run)?;
    eprintln!("cli-flow: private artifacts {}", run.display());
    for directory in ["server", "checkpoint", "logs", "alice", "bob", "carol"] {
        private_dir(&run.join(directory))?;
    }
    let node = Regtest::start(&config, &run)?;
    let manifest: Manifest = serde_json::from_slice(&fs::read(&config.manifest)?)?;
    let origin_key = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let control_key = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let deployment = Deployment {
        protocol_version: 10,
        signer_protocol_version: zark_protocol::deployment::SIGNER_PROTOCOL_VERSION,
        network: network::Network::Regtest,
        genesis_hash: network::REGTEST_GENESIS.into(),
        signet_challenge: String::new(),
        initial_delay: 480,
        gap: 60,
        margin: 6,
        origin_key: hex::encode(origin_key.verifying_key().to_bytes()),
        control_key: hex::encode(control_key.verifying_key().to_bytes()),
        suite: hex::encode(manifest.id()?),
    };
    deployment.lineage_policy(&manifest)?;
    let deployment_bytes = serde_json::to_vec_pretty(&deployment)?;
    let deployment_path = run.join("deployment.json");
    write_private(&deployment_path, &deployment_bytes)?;
    write_private(&run.join("server/origin.raw"), &origin_key.to_bytes())?;
    write_private(&run.join("server/control.raw"), &control_key.to_bytes())?;
    drop(origin_key);
    drop(control_key);
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate_path = run.join("server/tls.pem");
    let tls_key_path = run.join("server/tls.key");
    write_private(&certificate_path, certificate.cert.pem().as_bytes())?;
    write_private(
        &tls_key_path,
        certificate.signing_key.serialize_pem().as_bytes(),
    )?;
    let certificate_sha256 = hex::encode(hash(&[certificate.cert.der().as_ref()]));
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let listen = listener.local_addr()?;
    drop(listener);
    let emulation = config
        .network
        .as_ref()
        .map(|settings| latency::Emulation::start(settings, &run, listen, &node))
        .transpose()?;
    let wallet_endpoint = emulation.as_ref().map_or(listen, |e| e.signer);
    let mut crs_pins = BTreeMap::new();
    for entry in fs::read_dir(&config.crs)? {
        let entry = entry?;
        if is_crs_runtime_lock(&entry.path())? {
            continue;
        }
        if entry.file_type()?.is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            ensure!(
                name.ends_with(".dat") && !name.starts_with('.'),
                "unexpected CRS file"
            );
            crs_pins.insert(
                name,
                hex::encode(sha256_bounded(&entry.path(), MAX_CRS_BYTES)?),
            );
        }
    }
    let hosted_path = run.join("server/hosted.json");
    let mut hosted = json!({"version":10,"listen":listen,
        "certificate":certificate_path,"private_key":tls_key_path,"credentials":[],
        "network_workers":4,"proof_workers":1,"queue_capacity":8});
    if public {
        hosted["public_access"] =
            json!({"max_inflight":4,"requests_per_minute":600,"allocations_per_minute":60});
        hosted["messaging"] =
            json!({"directory":run.join("server/messaging"),"requests_per_minute":1200});
    }
    write_private(&hosted_path, &serde_json::to_vec_pretty(&hosted)?)?;
    let server_config = run.join("server/config.json");
    write_private(
        &server_config,
        &serde_json::to_vec_pretty(&json!({
            "version":10,"deployment":{"path":deployment_path,"sha256":hex::encode(hash(&[&deployment_bytes]))},
            "manifest":{"path":config.manifest,"sha256":config.manifest_sha256},
            "suite_directory":config.manifest.parent().context("suite directory")?,
            "bb":config.bb,
            "crs":{"directory":config.crs,
                "bn254_g1_sha256":crs_pins.get("bn254_g1.dat").context("G1 CRS pin")?,
                "bn254_g1_compressed_sha256":crs_pins.get("bn254_g1_compressed.dat").context("compressed G1 CRS pin")?},
            "batch_bitcoin":{"bitcoin_cli":config.bitcoin_cli,
                "datadir":node.datadir,"rpc_cookie":null,"rpc_port":node.port},
            "database":run.join("server/signer.sqlite"),"checkpoint":run.join("checkpoint/floor.json"),
            "control_key":run.join("server/control.raw"),"origin_key":run.join("server/origin.raw"),
            "hosted":hosted_path
        }))?,
    )?;
    let mut credentials = Vec::new();
    let mut clients = Vec::new();
    for actor in ["alice", "bob", "carol"] {
        let actor_directory = run.join(actor);
        let token = Zeroizing::new(hex::encode(random32()));
        let token_path = actor_directory.join("token");
        write_private(&token_path, token.as_bytes())?;
        credentials.push(json!({"sha256":hex::encode(hash(&[token.as_bytes()])),
            "coins":[],"expires_at":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()+48*60*60,
            "max_inflight":1,"requests_per_minute":600}));
        let actor_config = actor_directory.join("config.json");
        write_private(
            &actor_config,
            &serde_json::to_vec_pretty(&json!({
                "version":10,"deployment":deployment,"manifest":config.manifest,
                "manifest_sha256":config.manifest_sha256,"programs":config.programs,
                "nargo":config.nargo,"bb":config.bb,"crs":config.crs,"crs_sha256":crs_pins,
                "fast_runtime":config.fast_runtime,
                "bitcoin_cli_sha256":config.bitcoin_cli.sha256,
                "endpoint":{"address":wallet_endpoint,"server_name":"localhost","ca_certificate":certificate_path,
                    "certificate_sha256":certificate_sha256,"credential_file":if public { None } else { Some(&token_path) },"timeout_secs":180},
                "chain":emulation.as_ref().map_or_else(|| node.chain(deployment.clone()), |e| e.chain(&node, deployment.clone()))
            }))?,
        )?;
        clients.push(WalletCli {
            worker_enabled: worker,
            worker: None,
            network: emulation.as_ref().map(|e| e.stats.clone()),
            binary: wallet_pin.clone(),
            config: actor_config,
            logs: run.join("logs"),
            actor,
            count: 0,
            commands: Vec::new(),
            last_process_window: None,
        });
    }
    let [mut alice, mut bob, mut carol]: [WalletCli; 3] = clients
        .try_into()
        .map_err(|_| anyhow::anyhow!("three CLI actors"))?;
    let mut signer = SignerProcess {
        binary: signer_pin.clone(),
        config: server_config,
        listen,
        log_directory: run.join("logs"),
        generation: 0,
        process: None,
    };
    signer.start()?;
    for client in [&mut alice, &mut bob, &mut carol] {
        let assets = client.ok("verify-assets", &args(&[word("verify-assets")]))?;
        ensure!(
            assets["verified"] == true && assets["proof_roles"] == 6,
            "CLI proof suite not verified"
        );
    }

    let alice_owner = run.join("alice/origin");
    let create = args(&[
        word("origin-create"),
        word("--operation"),
        alice_owner.as_os_str(),
        word("--amount"),
        word("100000"),
        word("--activation-fee"),
        word("1000"),
        word("--recovery-fee"),
        word("1000"),
    ]);
    if public {
        alice.ok("token-free-origin", &create)?;
    } else {
        let denied = alice.execute("unadmitted-origin", &create, false)?;
        ensure!(
            text_field(&denied, "message")?.contains("unauthorized"),
            "initial CLI operation did not fail specifically at credential admission"
        );
    }
    let status_args = args(&[word("status"), word("--operation"), alice_owner.as_os_str()]);
    let pending = alice.ok("pending-origin-status", &status_args)?;
    let coin = text_field(&pending, "coin")?.to_owned();
    hex32(&coin)?;
    ensure!(
        pending["metadata_only"] == true,
        "local status overstated ownership"
    );
    if !public {
        for credential in &mut credentials {
            credential["coins"] = json!([coin]);
        }
        hosted["credentials"] = json!(credentials);
        atomic_write(&hosted_path, &serde_json::to_vec_pretty(&hosted)?)?;
    }
    let allocated = alice.ok("retry-admitted-origin", &create)?;
    let allocation_retry = alice.ok("retry-allocation-exact", &create)?;
    ensure!(
        allocated == allocation_retry,
        "allocation retry changed CLI response"
    );
    ensure!(
        alice.ok("allocated-status", &status_args)?["coin"] == coin,
        "admission retry changed coin"
    );
    let parent = Address::from_str(text_field(&allocated, "funding_address")?)?
        .require_network(Network::Regtest)?;
    let (deposit, vout) = node.signed_funding(&parent.script_pubkey(), 100_000)?;
    let deposit_path = run.join("alice/deposit-signed.hex");
    write_private(
        &deposit_path,
        hex::encode(bitcoin::consensus::serialize(&deposit)).as_bytes(),
    )?;
    alice.ok(
        "bind-funding",
        &args(&[
            word("origin-bind"),
            word("--operation"),
            alice_owner.as_os_str(),
            word("--transaction"),
            deposit_path.as_os_str(),
            word("--vout"),
            word(&vout.to_string()),
        ]),
    )?;
    let advance_origin = args(&[
        word("advance"),
        word("--operation"),
        alice_owner.as_os_str(),
    ]);
    let ready = alice.ok("origin-proofs", &advance_origin)?;
    ensure!(
        ready["recovery_and_activation_saved"] == true,
        "origin CLI did not save recovery"
    );
    require_proof_jobs(&alice_owner, &["deposit_authorization"])?;
    ensure!(
        node.rpc(None, "getrawmempool", &[])? == json!([]),
        "funding published before explicit broadcast"
    );
    let deposit_proof = deposit_receipt(&alice_owner)?;
    // This scenario intentionally restarts both peers. Transport loss without
    // replay is covered separately; do not silently retry a stale TLS session.
    alice.worker.take();
    signer.restart()?;
    ensure!(
        alice.ok("resume-origin-after-restart", &advance_origin)? == ready,
        "ready origin retry changed"
    );
    ensure!(
        deposit_receipt(&alice_owner)? == deposit_proof,
        "origin resume generated another proof attempt"
    );
    let broadcast_origin = args(&[
        word("advance"),
        word("--operation"),
        alice_owner.as_os_str(),
        word("--broadcast"),
    ]);
    let published = alice.ok("publish-deposit", &broadcast_origin)?;
    ensure!(
        published["transaction_id"] == deposit.compute_txid().to_string(),
        "wrong published deposit"
    );
    node.mine(1)?;

    if let Some(sender_mode) = batch {
        if let BatchSenderMode::Multi(left, right, wrong_amount) = sender_mode {
            return multi::run(
                &run,
                &node,
                &mut signer,
                &mut alice,
                &mut bob,
                &alice_owner,
                &coin,
                left,
                right,
                wrong_amount,
            );
        }
        return run_batch_after_first_origin(
            sender_mode,
            &run,
            &node,
            &mut signer,
            &mut alice,
            &mut bob,
            &hosted_path,
            &mut hosted,
            &mut credentials,
            &alice_owner,
            &coin,
            &deployment,
            &config,
            &wallet_pin,
            &signer_pin,
        );
    }

    let mut owner = alice_owner;
    let mut transfers = Vec::new();
    for index in 0..transfer_count {
        let (sender, recipient, label) = if index == 0 {
            (&mut alice, &mut bob, "alice-bob")
        } else {
            (&mut bob, &mut carol, "bob-carol")
        };
        let invitation = run.join(recipient.actor).join("invitation");
        let invite_args = args(&[
            word("new-address"),
            word("--directory"),
            invitation.as_os_str(),
        ]);
        let invite = recipient.ok("new-invitation", &invite_args)?;
        ensure!(
            recipient.ok("retry-invitation", &invite_args)? == invite,
            "invitation retry regenerated keys"
        );
        ensure!(
            text_field(&invite, "address")?.starts_with("tzark"),
            "test invitation prefix"
        );
        let send_operation = run.join(sender.actor).join("outgoing");
        let offer = run.join(format!("{label}.offer"));
        let send_args = args(&[
            word("send"),
            word("--owner"),
            owner.as_os_str(),
            word("--operation"),
            send_operation.as_os_str(),
            word("--to"),
            word(text_field(&invite, "address")?),
            word("--output"),
            offer.as_os_str(),
        ]);
        if let Some(emulation) = &emulation {
            thread::sleep(emulation.idle_before_transfer);
        }
        let sent = sender.ok("send-whole-coin", &send_args)?;
        let offer_hash = sha256_bounded(&offer, 4_000_000)?;
        let other_invitation = run.join(recipient.actor).join("unused-invitation");
        let other = recipient.ok(
            "unused-invitation-for-metadata-check",
            &args(&[
                word("new-address"),
                word("--directory"),
                other_invitation.as_os_str(),
            ]),
        )?;
        reject_metadata_change(
            sender,
            &send_operation,
            &run.join("checkpoint/floor.json"),
            "recipient",
            other["address"].clone(),
            "reject-changed-sender-recipient",
        )?;
        if index == 1 {
            // Alice's valid existing origin is a different source owner from
            // Bob's accepted receiver, even though both concern this coin.
            reject_metadata_change(
                sender,
                &send_operation,
                &run.join("checkpoint/floor.json"),
                "owner",
                json!(run.join("alice/origin")),
                "reject-changed-sender-owner",
            )?;
        }
        ensure!(
            sender.ok("retry-send-exact", &send_args)? == sent
                && sha256_bounded(&offer, 4_000_000)? == offer_hash,
            "send retry changed encrypted offer"
        );
        let recipient_owner = run.join(recipient.actor).join("incoming");
        let receive = args(&[
            word("receive"),
            word("--invitation"),
            invitation.as_os_str(),
            word("--operation"),
            recipient_owner.as_os_str(),
            word("--offer"),
            offer.as_os_str(),
            word("--coin"),
            word(&coin),
            word("--transfer-operation"),
            word(text_field(&sent, "transfer_operation")?),
            word("--recovery-fee"),
            word("1000"),
        ]);
        if let Some(emulation) = &emulation {
            thread::sleep(emulation.idle_before_transfer);
        }
        let accepted = recipient.ok("receive-and-accept", &receive)?;
        ensure!(
            accepted["accepted"] == true
                && accepted["coin"] == coin
                && accepted["recovery_saved"] == true,
            "CLI recipient did not accept exact coin"
        );
        require_proof_jobs(
            &send_operation,
            &[if index == 0 {
                "sender_from_origin"
            } else {
                "sender_from_transfer"
            }],
        )?;
        require_proof_jobs(&recipient_owner, &["receiver_authorization"])?;
        sender.worker.take();
        recipient.worker.take();
        signer.restart()?;
        let resumed = recipient.ok(
            "resume-accepted-after-restart",
            &args(&[
                word("resume"),
                word("--operation"),
                recipient_owner.as_os_str(),
            ]),
        )?;
        ensure!(
            resumed == accepted,
            "recipient resume changed accepted state"
        );
        let complete = args(&[
            word("complete"),
            word("--operation"),
            send_operation.as_os_str(),
        ]);
        ensure!(
            sender.ok("complete-sender", &complete)?["completed"] == true,
            "sender not retired"
        );
        ensure!(
            sender.ok("retry-complete", &complete)?["completed"] == true,
            "sender completion not idempotent"
        );
        ensure!(
            node.rpc(None, "getrawmempool", &[])? == json!([]),
            "transfer unexpectedly published an ancestor"
        );
        transfers.push(json!({"path":label,"state":accepted["state"],"coin":coin,
            "offer_sha256":hex::encode(offer_hash),"accepted_after_signer_restart":true}));
        owner = recipient_owner;
    }
    let (exit_actor, exiting) = if transfer_count == 0 {
        ("alice", &mut alice)
    } else {
        ("carol", &mut carol)
    };
    let archive = run.join(format!("{exit_actor}/recovery.json"));
    exiting.ok(
        "export-recovery",
        &args(&[
            word("export-recovery"),
            word("--operation"),
            owner.as_os_str(),
            word("--output"),
            archive.as_os_str(),
        ]),
    )?;
    let destination = node.rpc(
        Some("flow-funding"),
        "getnewaddress",
        &["exiting-cli-exit".into(), "bech32m".into()],
    )?;
    let destination = destination
        .as_str()
        .context("fresh CLI exit address")?
        .to_owned();
    let exit_operation = run.join(format!("{exit_actor}/exit"));
    let exited = exiting.ok(
        "cooperative-exit-sign",
        &args(&[
            word("exit"),
            word("--owner"),
            owner.as_os_str(),
            word("--operation"),
            exit_operation.as_os_str(),
            word("--to"),
            word(&destination),
            word("--fee"),
            word("1000"),
        ]),
    )?;
    ensure!(
        exited["signature_status"] == "released_terminal" && exited["broadcast"] == false,
        "CLI exit was not saved before broadcast"
    );
    let other_destination = node.rpc(
        Some("flow-funding"),
        "getnewaddress",
        &["unused-cli-metadata-destination".into(), "bech32m".into()],
    )?;
    reject_metadata_change(
        exiting,
        &exit_operation,
        &run.join("checkpoint/floor.json"),
        "destination",
        other_destination,
        "reject-changed-exit-destination",
    )?;
    reject_metadata_change(
        exiting,
        &exit_operation,
        &run.join("checkpoint/floor.json"),
        "fee",
        json!(1001),
        "reject-changed-exit-fee",
    )?;
    ensure!(
        node.rpc(None, "getrawmempool", &[])? == json!([]),
        "exit published without explicit broadcast"
    );
    exiting.worker.take();
    signer.restart()?;
    let retry_exit = exiting.ok(
        "resume-terminal-exit",
        &args(&[
            word("resume"),
            word("--operation"),
            exit_operation.as_os_str(),
        ]),
    )?;
    ensure!(retry_exit == exited, "terminal exit retry changed result");
    let publish_exit = args(&[
        word("advance"),
        word("--operation"),
        exit_operation.as_os_str(),
        word("--broadcast"),
    ]);
    let mempool = exiting.ok("publish-exit", &publish_exit)?;
    ensure!(
        mempool["amount_received_sat"] == 99_000 && mempool["waiting"] == true,
        "CLI exit mempool result"
    );
    ensure!(
        node.rpc(None, "getrawmempool", &[])? == json!([mempool["transaction_id"]]),
        "CLI direct exit must broadcast exactly one transaction"
    );
    node.mine(1)?;
    let confirmed = exiting.ok("confirm-exit", &publish_exit)?;
    ensure!(
        confirmed["waiting"] == false
            && confirmed["confirmations"].as_u64().unwrap_or(0) >= 1
            && confirmed["amount_received_sat"] == 99_000
            && confirmed["transaction_id"] == mempool["transaction_id"],
        "CLI withdrawal did not confirm exact 99,000 sats"
    );
    let exit_id = text_field(&confirmed, "transaction_id")?;
    let transaction = node.rpc(None, "getrawtransaction", &[exit_id.into(), "true".into()])?;
    let outputs = transaction["vout"]
        .as_array()
        .context("exit transaction outputs")?;
    ensure!(
        outputs.len() == 1 && outputs[0]["scriptPubKey"]["address"] == destination,
        "CLI withdrawal destination mismatch"
    );
    let utxo = node.rpc(
        None,
        "gettxout",
        &[exit_id.into(), "0".into(), "true".into()],
    )?;
    ensure!(
        utxo["confirmations"].as_u64().unwrap_or(0) >= 1
            && Amount::from_btc(utxo["value"].as_f64().context("withdrawal amount")?)?.to_sat()
                == 99_000,
        "confirmed CLI withdrawal UTXO missing"
    );
    ensure!(
        transaction["vin"][0]["txid"] == deposit.compute_txid().to_string()
            && transaction["vin"][0]["vout"] == vout,
        "CLI exit must spend the original deposit"
    );
    require_proof_jobs(
        &exit_operation,
        &[if transfer_count == 0 {
            "exit_from_origin"
        } else {
            "exit_from_transfer"
        }],
    )?;
    if let Some(worker) = &mut exiting.worker {
        worker.reject_changed_config(&exiting.config, &run.join("must-not-create-invitation"))?;
    }
    let report = json!({"version":10,"qualification":"actual-cli-tls-fresh-flow","persistent_worker":worker,
        "deployment":hex::encode(deployment.id()?),"coin":coin,
        "wallet_binary":wallet_pin,"signer_binary":signer_pin,
        "manifest_sha256":config.manifest_sha256,"tls_certificate_sha256":certificate_sha256,
        "admission":if public {"token-free public starts; no coins registered; exact allocation retried"} else {"empty initial credential scope; saved coin explicitly admitted; exact allocation retried"},
        "signer_starts":signer.generation,"deposit":deposit.compute_txid().to_string(),
        "activation_published_during_exit":false,"exit":confirmed,"destination":destination,"transfers":transfers,
        "commands":[alice.commands,bob.commands,carol.commands],
        "metadata_tampering_rejected_without_journal_or_checkpoint_changes":if transfer_count == 0 { 2 } else { 5 },
        "proof_oracle":false,"existing_wallet_or_node":false,"fresh_transfer_proof_jobs":transfer_count,"deposit_proof_jobs":1,"exit_proof_jobs":1,
        "scope":"actual binaries and pinned TLS, fresh generated proofs and Bitcoin; not a fault-injection or privacy noninterference proof"});
    write_private(
        &run.join("cli-flow-report.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    eprintln!(
        "cli-flow: confirmed 99,000 sats; report {}",
        run.join("cli-flow-report.json").display()
    );
    Ok(())
}
