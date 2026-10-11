//! A second fresh Engine-origin coin exits with only its native recovery archive.
//! The archive phase receives no Engine, prover, verifier or owner journal.
use super::*;
use bitcoin::consensus::serialize;

#[allow(clippy::too_many_arguments)] // Explicit isolated test actors and trust inputs.
pub(super) fn run(
    run: &Path,
    node: &Regtest,
    client: &DurableSigner<'_>,
    proofs: &Proofs,
    verifier: &PinnedVerifier,
    scratch: &Path,
    chain: &ChainConfig,
    policy: &LineagePolicy,
    control: &Digest,
) -> Result<Value> {
    let owner_directory = run.join("portable-origin");
    let archive_directory = run.join("standalone-recovery");
    private_dir(&archive_directory)?;
    let jobs_before: usize = proofs.counts.borrow().values().sum();
    let mut owner = OriginJournal::create(&owner_directory, policy, 100_000, 1_000, 1_000)?;
    let script = owner.allocate(client)?;
    let (deposit, vout) = node.signed_funding(&script, 100_000)?;
    chain.test_accept(&deposit)?;
    owner.bind_funding(&deposit, vout)?;
    owner.prepare_parent(client)?;
    owner.freeze_parent(client)?;
    owner.prepare_recovery(client)?;
    owner.write_deposit_witness(&proofs.input("portable-deposit"))?;
    let proof = proofs.prove("deposit_authorization", "portable-deposit")?;
    let signed_recovery = owner.issue_recovery(&proof, verifier, scratch, client)?;
    let signed_activation = owner.accept_initial_recovery(verifier, scratch, client)?;
    owner.freeze_certificate(verifier, scratch)?;
    ensure!(
        proofs.counts.borrow().values().sum::<usize>() == jobs_before + 1,
        "portable deposit generated more than one proof"
    );
    let coin = owner.context().coin;
    let archive = archive_directory.join("recovery.json");
    owner.export_recovery(&archive)?;
    ensure!(
        owner.broadcast_funding(verifier, scratch, client, chain, control)?
            == deposit.compute_txid(),
        "portable source deposit changed"
    );
    node.mine(1)?;
    ensure!(
        chain.confirmations(&deposit)? >= 1,
        "portable source deposit unconfirmed"
    );
    drop(owner);
    // These are reversible renames inside this test's fresh private run only.
    // Do not restore them: the rest of this scenario must be archive-only.
    for (source, destination) in [
        ("portable-origin", "portable-origin-unavailable"),
        ("server", "server-unavailable"),
        ("checkpoint", "checkpoint-unavailable"),
        ("proofs", "proofs-unavailable"),
    ] {
        ensure!(
            !run.join(destination).try_exists()?,
            "unavailable destination already exists"
        );
        fs::rename(run.join(source), run.join(destination))?;
    }
    ensure!(
        !owner_directory.exists()
            && !run.join("server").exists()
            && !run.join("checkpoint").exists()
            && !proofs.root.exists(),
        "original owner, signer and private proof paths must be unavailable"
    );
    let before = client.calls.borrow().clone();
    let result = archive_only(
        node,
        &archive,
        &policy.deployment,
        &coin,
        &signed_activation,
        &signed_recovery,
    )?;
    ensure!(
        *client.calls.borrow() == before,
        "portable recovery contacted the signer"
    );
    write_private(
        &archive_directory.join("report.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}

/// Its only secret input is the native portable archive. Expected transaction
/// bytes and authenticated deployment/coin are comparison data, not witnesses.
fn archive_only(
    node: &Regtest,
    archive: &Path,
    deployment: &Digest,
    coin: &Digest,
    expected_activation: &Transaction,
    expected_recovery: &Transaction,
) -> Result<Value> {
    ensure!(
        node.rpc(None, "getblockhash", &["0".into()])? == network::REGTEST_GENESIS,
        "portable recovery node changed chains"
    );
    let portable = PortableRecovery::read(archive, deployment, coin)?;
    let [activation, recovery] = portable.transactions()?;
    ensure!(
        activation == *expected_activation && recovery == *expected_recovery,
        "portable archive changed the actual Engine-issued transactions"
    );
    let delay = portable.relative_blocks();
    ensure!(
        delay >= 2 && recovery.input[0].sequence.to_consensus_u32() == delay,
        "portable recovery schedule mismatch"
    );
    let activation_test = test_accept(node, &activation)?;
    ensure!(
        activation_test["allowed"] == true,
        "portable activation is not Bitcoin-valid"
    );
    publish(node, &activation)?;
    node.mine(1)?;
    let activation_height = node
        .rpc(None, "getblockcount", &[])?
        .as_u64()
        .context("activation height")?;
    let first = test_accept(node, &recovery)?;
    ensure!(
        first["allowed"] == false && first["reject-reason"] == "non-BIP68-final",
        "fresh portable recovery did not enforce its relative timelock"
    );
    node.mine(delay - 2)?;
    let boundary = test_accept(node, &recovery)?;
    ensure!(
        boundary["allowed"] == false && boundary["reject-reason"] == "non-BIP68-final",
        "portable recovery was accepted one block before BIP68 maturity"
    );
    node.mine(1)?;
    let mature = test_accept(node, &recovery)?;
    ensure!(
        mature["allowed"] == true,
        "portable recovery rejected at exact next-block maturity"
    );
    publish(node, &recovery)?;
    node.mine(1)?;
    ensure!(
        node.rpc(None, "getblockcount", &[])?.as_u64()
            == Some(activation_height + u64::from(delay)),
        "portable recovery did not confirm at the intended maturity height"
    );
    let confirmed = node.rpc(
        None,
        "getrawtransaction",
        &[recovery.compute_txid().to_string(), "true".into()],
    )?;
    ensure!(
        confirmed["confirmations"].as_u64().is_some_and(|n| n >= 1),
        "portable recovery not confirmed"
    );

    node.rpc(
        None,
        "createwallet",
        &["standalone-recovery-destination".into()],
    )?;
    let destination = node
        .rpc(
            Some("standalone-recovery-destination"),
            "getnewaddress",
            &["".into(), "bech32m".into()],
        )?
        .as_str()
        .context("portable sweep address")?
        .to_owned();
    let info = node.rpc(
        Some("standalone-recovery-destination"),
        "getaddressinfo",
        std::slice::from_ref(&destination),
    )?;
    let script = hex::decode(
        info["scriptPubKey"]
            .as_str()
            .context("portable sweep script")?,
    )?;
    ensure!(
        script.len() == 34 && script[..2] == [0x51, 0x20],
        "portable sweep destination is not Taproot"
    );
    let sweep = portable.sign_payout_spend(script[2..].try_into()?, 1_000)?;
    ensure!(
        sweep.output.len() == 1
            && sweep.output[0].value.to_sat() == 97_000
            && sweep.output[0].script_pubkey.as_bytes() == script,
        "portable payout sweep destination or fee changed"
    );
    ensure!(
        test_accept(node, &sweep)?["allowed"] == true,
        "archive payout key cannot spend its recovery output"
    );
    publish(node, &sweep)?;
    node.mine(1)?;
    let utxo = node.rpc(
        None,
        "gettxout",
        &[sweep.compute_txid().to_string(), "0".into(), "true".into()],
    )?;
    ensure!(
        utxo["confirmations"].as_u64().is_some_and(|n| n >= 1)
            && utxo["scriptPubKey"]["address"] == destination,
        "portable payout sweep did not reach the destination wallet"
    );
    Ok(json!({
        "fresh_engine_bootstrap":true,"deployment":hex::encode(deployment),"coin":hex::encode(coin),
        "activation":activation.compute_txid().to_string(),"recovery":recovery.compute_txid().to_string(),
        "sweep":sweep.compute_txid().to_string(),"destination":destination,"received_sat":97_000,
        "relative_blocks":delay,"activation_height":activation_height,
        "immature_rejection":first["reject-reason"],"one_block_early_rejection":boundary["reject-reason"],
        "exact_maturity_accepted":true,"source_owner_signer_and_proof_paths_unavailable":true,
        "signer_calls_after_export":0,"private_proof_generation_after_export":false
    }))
}

fn test_accept(node: &Regtest, transaction: &Transaction) -> Result<Value> {
    let answer = node.rpc(
        None,
        "testmempoolaccept",
        &[serde_json::to_string(&[hex::encode(serialize(
            transaction,
        ))])?],
    )?;
    let entries = answer
        .as_array()
        .filter(|entries| entries.len() == 1)
        .context("portable mempool response")?;
    ensure!(
        entries[0]["txid"] == transaction.compute_txid().to_string(),
        "mempool tested another transaction"
    );
    Ok(entries[0].clone())
}

fn publish(node: &Regtest, transaction: &Transaction) -> Result<()> {
    let txid = node.rpc(
        None,
        "sendrawtransaction",
        &[hex::encode(serialize(transaction))],
    )?;
    ensure!(
        txid == transaction.compute_txid().to_string(),
        "portable published transaction changed"
    );
    Ok(())
}
