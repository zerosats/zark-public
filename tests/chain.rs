use anyhow::Result;
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use zark_protocol::{
    deployment::Deployment,
    handoff::RecoveryDelay,
    network::{Network, REGTEST_GENESIS},
    point_bytes, random32,
};
use zark_wallet::{chain::ChainConfig, signing::FundingKey, types::Input};
struct Home(PathBuf);
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn write(path: &Path, name: &str, value: &Value) -> Result<()> {
    fs::write(path.join(name), serde_json::to_vec(value)?)?;
    Ok(())
}
fn output(input: &Input, confirmations: u64) -> Result<Value> {
    Ok(
        json!({"bestblock":"44".repeat(32),"confirmations":confirmations,"value":bitcoin::Amount::from_sat(input.amount).to_btc(),
        "n":input.vout,"scriptPubKey":{"hex":hex::encode(zark_wallet::bitcoin::p2tr(&input.key()?).as_bytes())}}),
    )
}

#[test]
fn fresh_chain_checks_spends_exact_network_and_relative_window() -> Result<()> {
    let home = Home(std::env::temp_dir().join(format!("zark-chain-{}", hex::encode(random32()))));
    fs::create_dir(&home.0)?;
    let deployment = Deployment {
        protocol_version: 10,
        signer_protocol_version: zark_protocol::deployment::SIGNER_PROTOCOL_VERSION,
        network: Network::Regtest,
        genesis_hash: REGTEST_GENESIS.into(),
        signet_challenge: String::new(),
        initial_delay: 480,
        gap: 60,
        margin: 6,
        origin_key: hex::encode(SigningKey::from_bytes(&[1; 32])?.verifying_key().to_bytes()),
        control_key: hex::encode(SigningKey::from_bytes(&[2; 32])?.verifying_key().to_bytes()),
        suite: "55".repeat(32),
    };
    let key = FundingKey::new(
        ProjectivePoint::GENERATOR * Scalar::from(11u64),
        Scalar::from(13u64),
    )?;
    let input = |txid: String, amount| -> Result<Input> {
        Ok(Input {
            deployment: hex::encode(deployment.id()?),
            id: "33".repeat(32),
            funding_salt: "22".repeat(32),
            internal_point: hex::encode(point_bytes(key.internal)?),
            txid,
            vout: 0,
            amount,
        })
    };
    let backing = input("66".repeat(32), 99_000)?;
    let deposit = input("77".repeat(32), 100_000)?;
    let cli = home.0.join("cli");
    fs::write(
        &cli,
        format!(
            r#"#!/bin/sh
while [ "${{1#-}}" != "$1" ]; do shift; done
case "$1" in
getblockchaininfo)
  if [ -f '{dir}/unstable.json' ]; then
    if [ -f '{dir}/flip' ]; then rm '{dir}/flip'; cat '{dir}/info.json';
    else touch '{dir}/flip'; cat '{dir}/unstable.json'; fi
  else cat '{dir}/info.json'; fi;;
getblockhash) case "$2" in
  0) cat '{dir}/genesis.json';;
  101) cat '{dir}/block.json';;
  *) cat '{dir}/wrong-block.json';; esac;;
getrawtransaction)
  if [ -f '{dir}/next-info.json' ]; then
    mv '{dir}/next-info.json' '{dir}/info.json'
    mv '{dir}/next-deposit.json' '{dir}/deposit.json'
    mv '{dir}/next-parent.json' '{dir}/parent.json'
  fi
  cat '{dir}/deposit.json';;
gettxout) if [ "$2" = '{backing}' ]; then cat '{dir}/active.json'; else cat '{dir}/parent.json'; fi;;
*) exit 1;;
esac
"#,
            dir = home.0.display(),
            backing = backing.txid
        ),
    )?;
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o700))?;
    let config = ChainConfig {
        deployment,
        bitcoin_cli: cli,
        datadir: home.0.clone(),
        rpc_cookie: None,
        rpc_port: 12345,
        rpc_transport: Default::default(),
        minimum_confirmations: 1,
    };
    let info = json!({"chain":"regtest","initialblockdownload":false,"blocks":200,"bestblockhash":"44".repeat(32)});
    write(&home.0, "info.json", &info)?;
    // Match bitcoin-cli's actual raw-string and empty-null output conventions.
    fs::write(home.0.join("genesis.json"), format!("{REGTEST_GENESIS}\n"))?;
    write(&home.0, "block.json", &json!("aa".repeat(32)))?;
    write(&home.0, "wrong-block.json", &json!("cc".repeat(32)))?;
    write(
        &home.0,
        "deposit.json",
        &json!({"txid":deposit.txid,"confirmations":100,"blockhash":"aa".repeat(32),"vout":[output(&deposit,100)?]}),
    )?;
    fs::write(home.0.join("active.json"), b"")?;
    write(&home.0, "parent.json", &output(&deposit, 100)?)?;
    // Exercise the two late lifetime slots while keeping the short mock chain.
    let previous = RecoveryDelay::from_sequence(180)?;
    let next = RecoveryDelay::from_sequence(120)?;
    let observation = config.observe(&backing, &deposit)?;
    assert!(observation.activation_height.is_none());
    assert!(
        config
            .check_transfer_window(&observation, previous, next)?
            .is_none()
    );
    write(&home.0, "parent.json", &Value::Null)?;
    assert!(
        config.observe(&backing, &deposit).is_err(),
        "mempool-spent parent cannot serve as live backing"
    );
    write(&home.0, "active.json", &output(&backing, 20)?)?;
    let observation = config.observe(&backing, &deposit)?;
    assert_eq!(observation.activation_height, Some(181));
    assert_eq!(
        config
            .check_transfer_window(&observation, previous, next)?
            .unwrap()
            .previous_maturity,
        361
    );
    write(&home.0, "active.json", &output(&backing, 177)?)?;
    let late = config.observe(&backing, &deposit)?;
    assert!(config.check_transfer_window(&late, previous, next).is_err());
    let mut wrong = output(&backing, 20)?;
    wrong["value"] = json!(0.001);
    write(&home.0, "active.json", &wrong)?;
    assert!(config.observe(&backing, &deposit).is_err());
    write(&home.0, "active.json", &output(&backing, 20)?)?;
    let mut stale_deposit: Value = serde_json::from_slice(&fs::read(home.0.join("deposit.json"))?)?;
    stale_deposit["in_active_chain"] = false.into();
    write(&home.0, "deposit.json", &stale_deposit)?;
    assert!(config.observe(&backing, &deposit).is_err());
    stale_deposit
        .as_object_mut()
        .unwrap()
        .remove("in_active_chain");
    stale_deposit["blockhash"] = json!("bb".repeat(32));
    write(&home.0, "deposit.json", &stale_deposit)?;
    assert!(config.observe(&backing, &deposit).is_err());
    stale_deposit["blockhash"] = json!("aa".repeat(32));
    write(&home.0, "deposit.json", &stale_deposit)?;
    let mut wrong = info.clone();
    wrong["initialblockdownload"] = true.into();
    write(&home.0, "info.json", &wrong)?;
    assert!(config.observe(&backing, &deposit).is_err());
    write(&home.0, "info.json", &info)?;
    write(&home.0, "genesis.json", &json!("88".repeat(32)))?;
    assert!(config.observe(&backing, &deposit).is_err());

    // Mine a block after the tip RPC but before the transaction RPC. The first
    // confirmation calculation points at block 100 instead of 101 and fails;
    // a fresh complete observation must succeed without ignoring that check.
    write(&home.0, "genesis.json", &json!(REGTEST_GENESIS))?;
    fs::write(home.0.join("active.json"), b"")?;
    let mut next_info = info.clone();
    next_info["blocks"] = 201.into();
    next_info["bestblockhash"] = json!("55".repeat(32));
    write(&home.0, "next-info.json", &next_info)?;
    stale_deposit["confirmations"] = 101.into();
    write(&home.0, "next-deposit.json", &stale_deposit)?;
    let mut parent = output(&deposit, 101)?;
    parent["bestblock"] = next_info["bestblockhash"].clone();
    write(&home.0, "next-parent.json", &parent)?;
    let fresh = config.observe(&backing, &deposit)?;
    assert_eq!(fresh.tip_height, 201);
    assert_eq!(fresh.tip_hash, "55".repeat(32));
    assert!(fresh.activation_height.is_none());

    // A stable orphan is still rejected after the retry path has been used.
    stale_deposit["blockhash"] = json!("bb".repeat(32));
    write(&home.0, "deposit.json", &stale_deposit)?;
    assert!(config.observe(&backing, &deposit).is_err());
    stale_deposit["blockhash"] = json!("aa".repeat(32));
    write(&home.0, "deposit.json", &stale_deposit)?;

    // Even a same-height reorg invalidates an observation; persistent churn
    // must stop after the bounded retry budget rather than accept mixed data.
    next_info["bestblockhash"] = json!("99".repeat(32));
    write(&home.0, "unstable.json", &next_info)?;
    assert!(
        config
            .observe(&backing, &deposit)
            .err()
            .unwrap()
            .to_string()
            .contains("kept changing")
    );
    Ok(())
}

#[test]
fn rejected_broadcast_requires_exact_mempool_or_active_block_evidence_for_retry() -> Result<()> {
    use bitcoin::{OutPoint, Txid, hashes::Hash};
    let home =
        Home(std::env::temp_dir().join(format!("zark-publication-{}", hex::encode(random32()))));
    fs::create_dir(&home.0)?;
    let destination: [u8; 32] = SigningKey::from_bytes(&[7; 32])?
        .verifying_key()
        .to_bytes()
        .into();
    // Unsigned synthetic transaction: this test checks RPC admission evidence,
    // not actual Bitcoin consensus. Real regtest coverage is separate.
    let transaction = zark_wallet::bitcoin::cooperative_exit(
        OutPoint::new(Txid::from_byte_array([3; 32]), 0),
        99_000,
        1000,
        destination,
    )?;
    let raw = hex::encode(bitcoin::consensus::serialize(&transaction));
    let id = transaction.compute_txid().to_string();
    let cli = home.0.join("cli");
    fs::write(
        &cli,
        format!(
            r#"#!/bin/sh
while [ "${{1#-}}" != "$1" ]; do shift; done
case "$1" in
getblockchaininfo) cat '{dir}/info.json';;
getblockhash) case "$2" in
  0) cat '{dir}/genesis.json';;
  199) cat '{dir}/block.json';;
  *) cat '{dir}/wrong-block.json';; esac;;
getrawtransaction)
  if [ -f '{dir}/next-info.json' ]; then
    mv '{dir}/next-info.json' '{dir}/info.json'
    mv '{dir}/next-transaction.json' '{dir}/transaction.json'
  fi
  cat '{dir}/transaction.json';;
getmempoolentry) test -f '{dir}/mempool.json' || exit 1; cat '{dir}/mempool.json';;
sendrawtransaction) exit 1;;
*) exit 1;;
esac
"#,
            dir = home.0.display()
        ),
    )?;
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o700))?;
    let config = ChainConfig {
        deployment: Deployment {
            protocol_version: 10,
            signer_protocol_version: zark_protocol::deployment::SIGNER_PROTOCOL_VERSION,
            network: Network::Regtest,
            genesis_hash: REGTEST_GENESIS.into(),
            signet_challenge: String::new(),
            initial_delay: 480,
            gap: 60,
            margin: 6,
            origin_key: hex::encode(SigningKey::from_bytes(&[1; 32])?.verifying_key().to_bytes()),
            control_key: hex::encode(SigningKey::from_bytes(&[2; 32])?.verifying_key().to_bytes()),
            suite: "55".repeat(32),
        },
        bitcoin_cli: cli,
        datadir: home.0.clone(),
        rpc_cookie: None,
        rpc_port: 12345,
        rpc_transport: Default::default(),
        minimum_confirmations: 1,
    };
    write(
        &home.0,
        "info.json",
        &json!({"chain":"regtest","initialblockdownload":false,"blocks":200,"bestblockhash":"44".repeat(32)}),
    )?;
    fs::write(home.0.join("genesis.json"), format!("{REGTEST_GENESIS}\n"))?;
    write(&home.0, "block.json", &json!("aa".repeat(32)))?;
    write(&home.0, "wrong-block.json", &json!("cc".repeat(32)))?;
    let mut response = json!({"txid":id,"hex":raw});
    write(&home.0, "transaction.json", &response)?;
    assert!(
        config.confirmations(&transaction).is_err(),
        "cached bytes alone are not mempool acceptance"
    );
    assert!(
        config.publish(&transaction).is_err(),
        "rejected broadcast must not become false success"
    );
    write(&home.0, "mempool.json", &json!({"vsize":111}))?;
    assert_eq!(config.confirmations(&transaction)?, 0);
    assert_eq!(config.publish(&transaction)?, transaction.compute_txid());
    response["confirmations"] = 2.into();
    response["blockhash"] = json!("bb".repeat(32));
    write(&home.0, "transaction.json", &response)?;
    assert!(
        config.publish(&transaction).is_err(),
        "inactive confirmation block cannot authorize idempotent success"
    );
    response["blockhash"] = json!("aa".repeat(32));
    write(&home.0, "transaction.json", &response)?;
    assert_eq!(config.confirmations(&transaction)?, 2);
    assert_eq!(config.publish(&transaction)?, transaction.compute_txid());
    response["in_active_chain"] = false.into();
    write(&home.0, "transaction.json", &response)?;
    assert!(config.confirmations(&transaction).is_err());
    response.as_object_mut().unwrap().remove("in_active_chain");
    response["confirmations"] = 202.into();
    write(&home.0, "transaction.json", &response)?;
    assert!(
        config.confirmations(&transaction).is_err(),
        "confirmation count must fit observed tip"
    );
    write(
        &home.0,
        "next-info.json",
        &json!({"chain":"regtest","initialblockdownload":false,"blocks":201,"bestblockhash":"55".repeat(32)}),
    )?;
    response["confirmations"] = 3.into();
    write(&home.0, "next-transaction.json", &response)?;
    assert_eq!(config.confirmations(&transaction)?, 3);
    Ok(())
}
