//! Fresh origin and subsequent-owner cooperative exit qualification.
use super::*;

pub(super) fn run_owner_exit(exit_slot: usize) -> Result<()> {
    let owners = [
        "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    ];
    ensure!(exit_slot < owners.len(), "unsupported owner slot");
    let exit_owner = owners[exit_slot];
    let config = Config::read()?;
    let run = config
        .run_parent
        .join(format!("zark-real-flow-{}", hex::encode(random32())));
    private_dir(&run)?;
    eprintln!("real-flow: private artifacts {}", run.display());
    for name in ["server", "checkpoint", "proofs", "verify"] {
        private_dir(&run.join(name))?;
    }
    for owner in owners {
        private_dir(&run.join("proofs").join(owner))?;
    }
    let node = Regtest::start(&config, &run)?;
    let manifest: Manifest = serde_json::from_slice(&fs::read(&config.manifest)?)?;
    let origin_key = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let control_key = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let control: Digest = control_key.verifying_key().to_bytes().into();
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
        control_key: hex::encode(control),
        suite: hex::encode(manifest.id()?),
    };
    let policy = deployment.lineage_policy(&manifest)?;
    write_private(
        &run.join("deployment.json"),
        &serde_json::to_vec_pretty(&deployment)?,
    )?;
    // The test server's own signing keys are guarded separately, never passed to
    // any client journal, witness writer or proof command.
    let server_keys = Zeroizing::new(serde_json::to_vec(&json!({"test_only":true,
        "origin":hex::encode(origin_key.to_bytes()),"control":hex::encode(control_key.to_bytes())}))?);
    write_private(&run.join("server/control-keys.json"), &server_keys)?;
    let client = DurableSigner {
        run: run.clone(),
        config: &config,
        manifest: &manifest,
        deployment: deployment.clone(),
        policy: policy.clone(),
        control: control_key,
        origin: origin_key,
        calls: RefCell::new(BTreeMap::new()),
    };
    let verifier = verifier(&config, &manifest, &deployment)?;
    let proofs = Proofs {
        prover: Prover::new(
            &config.manifest,
            &hex32(&config.manifest_sha256)?,
            config.nargo.clone(),
            config.bb.clone(),
            config.crs.clone(),
            serde_json::from_slice::<Vec<Program>>(&fs::read(&config.programs)?)?,
        )?
        .with_fast_runtime(
            config
                .fast_runtime
                .clone()
                .context("v10 real flow requires fast runtime")?,
        )?,
        root: run.join("proofs"),
        counts: RefCell::new(BTreeMap::new()),
        privacy_checks: RefCell::new(Vec::new()),
        transfer_timings: RefCell::new(Vec::new()),
    };
    let scratch = run.join("verify");
    let chain = node.chain(deployment);
    let alice_directory = run.join("alice");
    let deposit_jobs_before: usize = proofs.counts.borrow().values().sum();
    let mut alice = OriginJournal::create(&alice_directory, &policy, 100_000, 1_000, 1_000)?;
    let parent = alice.allocate(&client)?;
    let (deposit, vout) = node.signed_funding(&parent, 100_000)?;
    chain.test_accept(&deposit)?;
    alice.bind_funding(&deposit, vout)?;
    drop(alice);
    let mut alice = OriginJournal::open(&alice_directory, &policy)?;
    alice.prepare_parent(&client)?;
    alice.freeze_parent(&client)?;
    alice.prepare_recovery(&client)?;
    alice.write_deposit_witness(&proofs.input("alice-deposit"))?;
    let authorization = proofs.prove("deposit_authorization", "alice-deposit")?;
    let initial_recovery = alice.issue_recovery(&authorization, &verifier, &scratch, &client)?;
    drop(alice);
    let mut alice = OriginJournal::open(&alice_directory, &policy)?;
    ensure!(
        alice.retrieve_issued(&verifier, &scratch, &client)? == initial_recovery,
        "origin recovery retry changed"
    );
    let activation = alice.accept_initial_recovery(&verifier, &scratch, &client)?;
    drop(alice);
    let mut alice = OriginJournal::open(&alice_directory, &policy)?;
    ensure!(
        alice.accept_initial_recovery(&verifier, &scratch, &client)? == activation,
        "activation retry changed"
    );
    alice.freeze_certificate(&verifier, &scratch)?;
    ensure!(
        proofs.counts.borrow().values().sum::<usize>() == deposit_jobs_before + 1
            && proofs.counts.borrow().get("deposit_authorization") == Some(&1),
        "deposit or resume generated more than one proof"
    );
    alice.export_recovery(&alice_directory.join("portable-recovery.json"))?;
    ensure!(
        node.rpc(None, "getrawmempool", &[])? == json!([]),
        "deposit published before durable recovery/certificate"
    );
    ensure!(
        alice.broadcast_funding(&verifier, &scratch, &client, &chain, &control)?
            == deposit.compute_txid(),
        "deposit id changed"
    );
    node.mine(1)?;
    ensure!(chain.confirmations(&deposit)? >= 1, "deposit not confirmed");
    let mut receivers: Vec<ReceiverJournal> = Vec::new();
    for slot in 1..=exit_slot {
        let owner = owners[slot];
        let step = format!("{}-{owner}", owners[slot - 1]);
        let mut invitation = LocalInvitation::create(
            &run.join(format!("{owner}-invitation")),
            AddressNetwork::Test,
            policy.deployment,
        )?;
        let address = invitation.public_address()?;
        let sender_directory = run.join(format!("{}-to-{owner}", owners[slot - 1]));
        let mut sender = if slot == 1 {
            alice.create_sender(
                &sender_directory,
                &address,
                &verifier,
                &scratch,
                &client,
                &chain,
                &control,
            )?
        } else {
            receivers
                .last_mut()
                .context("missing predecessor")?
                .create_sender(
                    &sender_directory,
                    &address,
                    &verifier,
                    &scratch,
                    &client,
                    &chain,
                    &control,
                )?
        };
        let receiver = transfer(
            &mut sender,
            &mut invitation,
            &run.join(owner),
            &step,
            &proofs,
            &verifier,
            &scratch,
            &client,
            &chain,
            &control,
            &policy,
        )?;
        ensure!(
            receiver.context().coin == alice.context().coin,
            "whole-coin identity changed"
        );
        ensure!(
            receiver.recovery_delays()?.1 == policy.schedule.delay_after(slot as u32)?,
            "whole-coin transfer did not apply the exact fixed recovery schedule"
        );
        receivers.push(receiver);
    }
    if exit_slot == owners.len() - 1 {
        let extra = LocalInvitation::create(
            &run.join("extra-invitation"),
            AddressNetwork::Test,
            policy.deployment,
        )?;
        ensure!(
            receivers
                .last_mut()
                .context("missing final owner")?
                .create_sender(
                    &run.join("prohibited-eighth-transfer"),
                    &extra.public_address()?,
                    &verifier,
                    &scratch,
                    &client,
                    &chain,
                    &control,
                )
                .is_err(),
            "eighth transfer exceeded the ownership budget"
        );
    }
    ensure!(
        node.rpc(None, "getrawmempool", &[])? == json!([]),
        "transfer published an on-chain transaction"
    );
    let destination_wallet = format!("{exit_owner}-withdrawal");
    node.rpc(
        None,
        "createwallet",
        std::slice::from_ref(&destination_wallet),
    )?;
    let destination_address = node
        .rpc(
            Some(&destination_wallet),
            "getnewaddress",
            &["".into(), "bech32m".into()],
        )?
        .as_str()
        .context("withdrawal address")?
        .to_owned();
    let destination_info = node.rpc(
        Some(&destination_wallet),
        "getaddressinfo",
        std::slice::from_ref(&destination_address),
    )?;
    let destination_script = hex::decode(
        destination_info["scriptPubKey"]
            .as_str()
            .context("withdrawal script")?,
    )?;
    ensure!(
        destination_script.len() == 34 && destination_script[..2] == [0x51, 0x20],
        "withdrawal destination must be Taproot"
    );
    let destination: Digest = destination_script[2..].try_into()?;
    let exit_step = format!("{exit_owner}-exit");
    let exit_directory = run.join(&exit_step);
    let mut exit = if exit_slot == 0 {
        alice.create_exit(
            &exit_directory,
            destination,
            1_000,
            &verifier,
            &scratch,
            &client,
            &chain,
            &control,
        )?
    } else {
        let receiver = receivers.last_mut().context("missing exit owner")?;
        receiver.create_exit(
            &exit_directory,
            destination,
            1_000,
            &verifier,
            &scratch,
            &client,
            &chain,
            &control,
        )?
    };
    let exit_jobs_before: usize = proofs.counts.borrow().values().sum();
    exit.prepare(&verifier, &scratch, &client, &chain)?;
    exit.write_authorization_witness(
        &proofs.input(&exit_step),
        &proofs.prover,
        &verifier,
        &scratch,
    )?;
    let exit_role = if exit_slot == 0 {
        "exit_from_origin"
    } else {
        "exit_from_transfer"
    };
    let exit_proof = proofs.prove(exit_role, &exit_step)?;
    let withdrawal = exit.issue(&exit_proof, &verifier, &scratch, &client, &chain)?;
    ensure!(
        proofs.counts.borrow().values().sum::<usize>() == exit_jobs_before + 1,
        "cooperative exit must generate exactly one fresh proof"
    );
    ensure!(
        withdrawal.output.len() == 1
            && withdrawal.output[0].value.to_sat() == 99_000
            && withdrawal.input.len() == 1
            && withdrawal.input[0].previous_output.txid == deposit.compute_txid()
            && withdrawal.input[0].previous_output.vout == vout
            && withdrawal.output[0].script_pubkey.as_bytes() == destination_script,
        "cooperative withdrawal destination or amount changed"
    );
    drop(exit);
    let mut exit = ExitOperation::open(&exit_directory, &policy)?;
    ensure!(
        exit.retrieve(&client)? == withdrawal,
        "terminal exit retry changed its transaction"
    );
    let pending = exit.publish(&chain)?;
    ensure!(
        node.rpc(None, "getrawmempool", &[])? == json!([withdrawal.compute_txid().to_string()]),
        "direct withdrawal must be the only transaction broadcast"
    );
    ensure!(
        pending["signature_status"] == "released_terminal",
        "exit did not record terminal signature release"
    );
    node.mine(1)?;
    let confirmed = exit.publish(&chain)?;
    ensure!(
        confirmed["waiting"] == false && confirmed["amount_received_sat"] == 99_000,
        "cooperative withdrawal not confirmed"
    );
    ensure!(
        chain.confirmations(&activation).is_err() && chain.confirmations(&withdrawal)? >= 1,
        "withdrawal must confirm without publishing activation"
    );
    let received = node.rpc(
        None,
        "gettxout",
        &[
            withdrawal.compute_txid().to_string(),
            "0".into(),
            "true".into(),
        ],
    )?;
    ensure!(
        received["scriptPubKey"]["address"] == destination_address,
        "withdrawal UTXO is not at the requested owner address"
    );
    let exercised: Vec<String> = proofs.counts.borrow().keys().cloned().collect();
    ensure!(
        ROLE_NAMES
            .iter()
            .filter(|role| matches!(**role, "deposit_authorization")
                || **role == exit_role
                || (exit_slot >= 1
                    && matches!(**role, "sender_from_origin" | "receiver_authorization"))
                || (exit_slot >= 2 && **role == "sender_from_transfer"))
            .all(|role| exercised.iter().any(|actual| actual == role)),
        "not all roles used by this transfer/final-exit flow were exercised"
    );
    // This last scenario intentionally makes server/prover/origin directories
    // unavailable. Nothing below may invoke an Engine, verifier or prover.
    let portable_recovery = if exit_slot == 2 {
        portable::run(
            &run, &node, &client, &proofs, &verifier, &scratch, &chain, &policy, &control,
        )?
    } else {
        Value::Null
    };
    write_private(
        &run.join("flow-report.json"),
        &serde_json::to_vec_pretty(&json!({
            "version":10,"deployment":hex::encode(policy.deployment),"fresh_signer_allocation":true,
            "deposit":deposit.compute_txid().to_string(),"activation":activation.compute_txid().to_string(),
            "activation_published_during_transfers":false,"owners":&owners[..=exit_slot],
            "proof_counts":*proofs.counts.borrow(),"wire_calls":*client.calls.borrow(),
            "recipient_privacy_boundaries":*proofs.privacy_checks.borrow(),
            "transfer_native_timings":*proofs.transfer_timings.borrow(),
            "archive_only_unilateral_recovery":portable_recovery,
            "engine_reopened_and_exact_retries_checked":true,"transport":"in-process shared wire",
            "cooperative_exit":confirmed,"withdrawal":withdrawal.compute_txid().to_string(),
            "destination":destination_address,"received_sat":99_000,"activation_published_during_exit":false,
            "all_flow_roles_proved_and_externally_verified":true,
            "fresh_transfer_proof_jobs":2,"exit_owner":exit_owner,"fresh_exit_proof_jobs":1
        }))?,
    )?;
    Ok(())
}
