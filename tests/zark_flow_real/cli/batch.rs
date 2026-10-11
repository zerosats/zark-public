//! Two-coin batch scenarios and exact restart/retrieval checks.
use super::*;

#[allow(
    clippy::too_many_arguments,
    reason = "real-flow harness passes authenticated fixtures explicitly"
)]
pub(super) fn run_batch_after_first_origin(
    sender_mode: BatchSenderMode,
    run: &Path,
    node: &Regtest,
    signer: &mut SignerProcess,
    alice: &mut WalletCli,
    bob: &mut WalletCli,
    hosted_path: &Path,
    hosted: &mut Value,
    credentials: &mut [Value],
    alice_owner: &Path,
    alice_coin: &str,
    deployment: &Deployment,
    config: &Config,
    wallet_pin: &BinaryPin,
    signer_pin: &BinaryPin,
) -> Result<()> {
    let bob_owner = run.join("bob/origin");
    let bob_create = args(&[
        word("origin-create"),
        word("--operation"),
        bob_owner.as_os_str(),
        word("--amount"),
        word("120000"),
        word("--activation-fee"),
        word("1000"),
        word("--recovery-fee"),
        word("1000"),
    ]);
    let public = hosted.get("public_access").is_some();
    bob.execute("batch-second-origin-first-attempt", &bob_create, public)?;
    let bob_status = bob.ok(
        "batch-second-origin-status",
        &args(&[word("status"), word("--operation"), bob_owner.as_os_str()]),
    )?;
    let bob_coin = text_field(&bob_status, "coin")?.to_owned();
    ensure!(bob_coin != alice_coin, "batch origins duplicated a coin ID");
    if !public {
        for credential in credentials.iter_mut() {
            credential["coins"] = json!([alice_coin, bob_coin]);
        }
        hosted["credentials"] = json!(credentials);
        atomic_write(hosted_path, &serde_json::to_vec_pretty(hosted)?)?;
    }
    let allocated = bob.ok("batch-second-origin-allocate", &bob_create)?;
    let parent = Address::from_str(text_field(&allocated, "funding_address")?)?
        .require_network(Network::Regtest)?;
    let (deposit, vout) = node.signed_funding(&parent.script_pubkey(), 120_000)?;
    let deposit_path = run.join("bob/deposit-signed.hex");
    write_private(
        &deposit_path,
        hex::encode(bitcoin::consensus::serialize(&deposit)).as_bytes(),
    )?;
    bob.ok(
        "batch-second-origin-bind",
        &args(&[
            word("origin-bind"),
            word("--operation"),
            bob_owner.as_os_str(),
            word("--transaction"),
            deposit_path.as_os_str(),
            word("--vout"),
            word(&vout.to_string()),
        ]),
    )?;
    let bob_advance = args(&[word("advance"), word("--operation"), bob_owner.as_os_str()]);
    ensure!(
        bob.ok("batch-second-origin-proofs", &bob_advance)?["recovery_and_activation_saved"]
            == true,
        "second origin recovery was not saved"
    );
    let bob_receipt = deposit_receipt(&bob_owner)?;
    bob.ok("batch-second-origin-resume", &bob_advance)?;
    ensure!(
        deposit_receipt(&bob_owner)? == bob_receipt,
        "second deposit resume generated another proof attempt"
    );
    bob.ok(
        "batch-second-origin-publish",
        &args(&[
            word("advance"),
            word("--operation"),
            bob_owner.as_os_str(),
            word("--broadcast"),
        ]),
    )?;
    node.mine(1)?;

    let alice_invitation = run.join("alice/batch-invitation");
    let bob_invitation = run.join("bob/batch-invitation");
    let alice_address = alice.ok(
        "batch-alice-invitation",
        &args(&[
            word("new-address"),
            word("--directory"),
            alice_invitation.as_os_str(),
        ]),
    )?;
    let bob_address = bob.ok(
        "batch-bob-invitation",
        &args(&[
            word("new-address"),
            word("--directory"),
            bob_invitation.as_os_str(),
        ]),
    )?;
    let alice_send = run.join("alice/batch-send");
    let bob_send = run.join("bob/batch-send");
    let alice_offer = run.join("alice-bob-batch.offer");
    let bob_offer = run.join("bob-alice-batch.offer");
    let a = alice.ok(
        "batch-alice-draft",
        &args(&[
            word("batch-draft"),
            word("--owner"),
            alice_owner.as_os_str(),
            word("--operation"),
            alice_send.as_os_str(),
            word("--to"),
            word(text_field(&bob_address, "address")?),
            word("--output"),
            alice_offer.as_os_str(),
        ]),
    )?;
    let b = bob.ok(
        "batch-bob-draft",
        &args(&[
            word("batch-draft"),
            word("--owner"),
            bob_owner.as_os_str(),
            word("--operation"),
            bob_send.as_os_str(),
            word("--to"),
            word(text_field(&alice_address, "address")?),
            word("--output"),
            bob_offer.as_os_str(),
        ]),
    )?;
    ensure!(
        a["coin"] == alice_coin && b["coin"] == bob_coin,
        "batch drafts changed owner coins"
    );
    let manifest_path = run.join("batch-manifest.json");
    let expiry =
        (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 4 * 60 * 60).to_string();
    let peer_path = run.join("bob-public-draft.json");
    if public {
        write_private(
            &peer_path,
            &serde_json::to_vec(
                &json!({"coin":b["coin"],"context":b["context"],"revision":b["revision"]}),
            )?,
        )?;
    }
    let manifest_args = args(&[
        word("batch-manifest"),
        word("--first"),
        alice_send.as_os_str(),
        word(if public { "--peer" } else { "--second" }),
        if public {
            peer_path.as_os_str()
        } else {
            bob_send.as_os_str()
        },
        word("--expires-at"),
        word(&expiry),
        word("--output"),
        manifest_path.as_os_str(),
    ]);
    let manifest = alice.ok("batch-frozen-manifest", &manifest_args)?;
    ensure!(
        alice.ok("batch-manifest-retry", &manifest_args)? == manifest,
        "batch manifest retry changed identity"
    );
    for (client, operation) in [(&mut *alice, &alice_send), (&mut *bob, &bob_send)] {
        let joined = client.ok(
            "batch-join",
            &args(&[
                word("batch-send"),
                word("--operation"),
                operation.as_os_str(),
                word("--manifest"),
                manifest_path.as_os_str(),
            ]),
        )?;
        ensure!(joined["phase"] == "joined", "batch sender was not joined");
    }
    let alice_advance = args(&[word("advance"), word("--operation"), alice_send.as_os_str()]);
    let bob_advance = args(&[word("advance"), word("--operation"), bob_send.as_os_str()]);
    let sender_pair_started = Instant::now();
    let (sent_a, sent_b) = match sender_mode {
        BatchSenderMode::Sequential => (
            alice.ok("batch-alice-offer", &alice_advance)?,
            bob.ok("batch-bob-offer", &bob_advance)?,
        ),
        BatchSenderMode::Concurrent => {
            // Each thread owns one actor's mutable command/log state. No third
            // wallet is launched, and both children are joined before returning
            // either error or starting a recipient. OwnedProcess retains the
            // existing process-group cleanup and command deadline behavior.
            let ready = std::sync::Barrier::new(2);
            thread::scope(|scope| -> Result<(Value, Value)> {
                let a = scope.spawn(|| {
                    ready.wait();
                    alice.ok("batch-alice-offer", &alice_advance)
                });
                let b = scope.spawn(|| {
                    ready.wait();
                    bob.ok("batch-bob-offer", &bob_advance)
                });
                let a = a.join();
                let b = b.join();
                Ok((
                    a.map_err(|_| anyhow::anyhow!("Alice sender worker panicked"))??,
                    b.map_err(|_| anyhow::anyhow!("Bob sender worker panicked"))??,
                ))
            })?
        }
        BatchSenderMode::Multi(_, _, _) => unreachable!("multi-group harness is separate"),
    };
    let sender_pair_elapsed = sender_pair_started.elapsed();
    let (a_start, a_end) = alice
        .last_process_window
        .context("Alice sender process interval")?;
    let (b_start, b_end) = bob
        .last_process_window
        .context("Bob sender process interval")?;
    let sender_processes_overlap = a_start < b_end && b_start < a_end;
    ensure!(
        sender_processes_overlap == (sender_mode == BatchSenderMode::Concurrent),
        "sender process scheduling did not match the qualification mode"
    );
    ensure!(
        sent_a["coin"] == alice_coin && sent_b["coin"] == bob_coin,
        "batch handover returned wrong coin"
    );
    let bob_receive = run.join("bob/batch-receive");
    let alice_receive = run.join("alice/batch-receive");
    let bob_pending = bob.ok(
        "batch-first-ready",
        &args(&[
            word("receive"),
            word("--invitation"),
            bob_invitation.as_os_str(),
            word("--operation"),
            bob_receive.as_os_str(),
            word("--offer"),
            alice_offer.as_os_str(),
            word("--coin"),
            word(alice_coin),
            word("--transfer-operation"),
            word(text_field(&sent_a, "transfer_operation")?),
            word("--batch"),
            manifest_path.as_os_str(),
        ]),
    )?;
    ensure!(
        bob_pending["phase"] == "batch_ready",
        "first recipient released before pair was ready"
    );
    let alice_accepted = alice.ok(
        "batch-second-ready-and-accept",
        &args(&[
            word("receive"),
            word("--invitation"),
            alice_invitation.as_os_str(),
            word("--operation"),
            alice_receive.as_os_str(),
            word("--offer"),
            bob_offer.as_os_str(),
            word("--coin"),
            word(&bob_coin),
            word("--transfer-operation"),
            word(text_field(&sent_b, "transfer_operation")?),
            word("--batch"),
            manifest_path.as_os_str(),
        ]),
    )?;
    ensure!(
        alice_accepted["accepted"] == true && alice_accepted["coin"] == bob_coin,
        "second batch recipient did not accept"
    );
    signer.restart()?;
    let bob_accepted = bob.ok(
        "batch-first-recipient-retrieve",
        &args(&[
            word("advance"),
            word("--operation"),
            bob_receive.as_os_str(),
        ]),
    )?;
    ensure!(
        bob_accepted["accepted"] == true && bob_accepted["coin"] == alice_coin,
        "first recipient did not retrieve after restart"
    );
    for (client, operation) in [(&mut *alice, &alice_send), (&mut *bob, &bob_send)] {
        ensure!(
            client.ok(
                "batch-complete-sender",
                &args(&[word("complete"), word("--operation"), operation.as_os_str()])
            )?["completed"]
                == true,
            "batch sender did not retire"
        );
    }
    ensure!(
        node.rpc(None, "getrawmempool", &[])? == json!([]),
        "batch transfer published an activation"
    );
    for operation in [&alice_send, &bob_send] {
        require_proof_jobs(operation, &["sender_from_origin"])?;
    }
    for operation in [&alice_receive, &bob_receive] {
        require_proof_jobs(operation, &["receiver_authorization"])?;
    }
    let report = json!({"qualification":"real-two-coin-batch-cli-tls-regtest","deployment":hex::encode(deployment.id()?),
        "coins":[alice_coin,bob_coin],"batch":manifest["batch"],"accepted":[alice_accepted,bob_accepted],
        "signer_restarted_before_first_recipient_retrieval":true,"proof_oracle":false,"fresh_transfer_proof_jobs":4,
        "public_admission":public,"portable_peer_draft":public,
        "sender_scheduling":if sender_mode == BatchSenderMode::Concurrent {"concurrent"} else {"sequential"},
        "sender_wallet_process_limit":if sender_mode == BatchSenderMode::Concurrent {2} else {1},
        "sender_process_overlap_observed":sender_processes_overlap,
        "sender_pair_elapsed_seconds":sender_pair_elapsed.as_secs_f64(),
        "recipient_scheduling":"sequential_first_readiness_then_atomic_commit",
        "wallet_binary":wallet_pin,"signer_binary":signer_pin,"manifest_sha256":config.manifest_sha256,
        "commands":[alice.commands,bob.commands]});
    write_private(
        &run.join("batch-flow-report.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    eprintln!(
        "cli-flow: two-coin batch accepted; report {}",
        run.join("batch-flow-report.json").display()
    );
    Ok(())
}
