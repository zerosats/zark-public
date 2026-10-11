use super::*;
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde_json::json;
use zark_protocol::{
    deployment::Deployment,
    network::{Network, REGTEST_GENESIS},
    point_bytes,
};

fn fixture() -> Result<(ChainConfig, Input, Input, Vec<String>, Value)> {
    let deployment = Deployment {
        protocol_version: 10,
        signer_protocol_version: 5,
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
    let input = |txid: &str, amount| -> Result<Input> {
        Ok(Input {
            deployment: hex::encode(deployment.id()?),
            id: "33".repeat(32),
            funding_salt: "22".repeat(32),
            internal_point: hex::encode(point_bytes(
                zark_protocol::even(ProjectivePoint::GENERATOR * Scalar::from(11u64))?.0,
            )?),
            txid: txid.repeat(32),
            vout: 0,
            amount,
        })
    };
    let backing = input("66", 99_000)?;
    let deposit = input("77", 100_000)?;
    let config = ChainConfig {
        deployment,
        bitcoin_cli: "/unused".into(),
        datadir: "/unused".into(),
        rpc_cookie: None,
        rpc_port: 1234,
        rpc_transport: Default::default(),
        minimum_confirmations: 1,
    };
    let request = vec![
        "1".into(),
        backing.txid.clone(),
        "0".into(),
        deposit.txid.clone(),
        "0".into(),
    ];
    let tip = json!({"chain":"regtest", "initialblockdownload":false, "blocks":200, "bestblockhash":"44".repeat(32)});
    let output = json!({"n":0, "value":0.001, "scriptPubKey":{"hex":hex::encode(crate::bitcoin::p2tr(&deposit.key()?).as_bytes())}});
    let read = |method, args: Value, result| json!({"method":method, "args":args, "result":result, "failed":false});
    let value = json!({"version":1, "request":request, "reads":[
        read("getblockchaininfo", json!([]), tip.clone()),
        read("getblockhash", json!(["0"]), json!(REGTEST_GENESIS)),
        read("getrawtransaction", json!([deposit.txid,"true"]), json!({"txid":deposit.txid,"confirmations":100,"blockhash":"aa".repeat(32),"vout":[output.clone()]})),
        read("getblockhash", json!(["101"]), json!("aa".repeat(32))),
        read("gettxout", json!([backing.txid,"0","true"]), Value::Null),
        read("gettxout", json!([deposit.txid,"0","true"]), {
            let mut output = output; output["bestblock"] = json!("44".repeat(32)); output
        }),
        read("getblockchaininfo", json!([]), tip)
    ]});
    Ok((config, backing, deposit, request, value))
}

#[test]
fn aggregated_evidence_keeps_all_local_backing_and_network_checks() -> Result<()> {
    let (config, backing, deposit, request, value) = fixture()?;
    let check = |v| config.validate_evidence(v, &request, &backing, &deposit);
    assert!(check(value.clone())?.unwrap().activation_height.is_none());
    for (pointer, replacement) in [
        ("/request/1", json!("88".repeat(32))),
        ("/reads/0/result/initialblockdownload", json!(true)),
        ("/reads/0/result/chain", json!("main")),
        ("/reads/1/result", json!("88".repeat(32))),
        ("/reads/2/result/txid", json!("88".repeat(32))),
        ("/reads/2/result/confirmations", json!(0)),
        ("/reads/2/result/vout/0/value", json!(0.002)),
        ("/reads/2/result/vout/0/scriptPubKey/hex", json!("00")),
        ("/reads/3/result", json!("88".repeat(32))),
        ("/reads/4/args/2", json!("false")),
        ("/reads/4/failed", json!(true)),
        ("/reads/5/result", Value::Null),
        ("/reads/5/result/value", json!(0.002)),
        ("/reads/5/result/bestblock", json!("88".repeat(32))),
        ("/reads/6/failed", json!(true)),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(check(changed).is_err(), "accepted {pointer}");
    }
    let mut changed = value.clone();
    changed["reads"][2]["result"]["in_active_chain"] = json!(false);
    assert!(check(changed).is_err());
    // A same-height reorg invalidates even an early failed read, for retry.
    let mut changed = value;
    changed["reads"][6]["result"]["bestblockhash"] = json!("88".repeat(32));
    changed["reads"][2]["failed"] = json!(true);
    assert!(check(changed)?.is_none());
    Ok(())
}

#[test]
fn aggregated_active_backing_validates_amount_script_and_confirmation_height() -> Result<()> {
    let (config, backing, deposit, request, mut value) = fixture()?;
    value["reads"].as_array_mut().unwrap().remove(5);
    value["reads"][4]["result"] = json!({"value":0.00099, "confirmations":20, "bestblock":"44".repeat(32),
        "scriptPubKey":{"hex":hex::encode(crate::bitcoin::p2tr(&backing.key()?).as_bytes())}});
    let check = |v| config.validate_evidence(v, &request, &backing, &deposit);
    assert_eq!(check(value.clone())?.unwrap().activation_height, Some(181));
    value["reads"][4]["result"]["confirmations"] = json!(0);
    assert!(check(value.clone())?.unwrap().activation_in_mempool);
    value["reads"][4]["result"]["confirmations"] = json!(202);
    assert!(check(value).is_err());
    Ok(())
}

struct FakeCli(std::path::PathBuf);
impl Drop for FakeCli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Points `config` at a logging bitcoin-cli in its own directory, which also
/// gives it a distinct process-wide capability key.
fn fake_cli(config: &mut ChainConfig, info: &Value, evidence: &Value) -> Result<FakeCli> {
    use std::{fs, os::unix::fs::PermissionsExt};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("work")
        .join(format!(
            "observation-test-{}",
            hex::encode(zark_protocol::random32())
        ));
    fs::create_dir_all(&root)?;
    let cleanup = FakeCli(root.clone());
    config.bitcoin_cli = root.join("cli");
    config.datadir = root.clone();
    fs::write(root.join("info"), serde_json::to_vec(info)?)?;
    fs::write(root.join("evidence"), serde_json::to_vec(evidence)?)?;
    fs::write(
        &config.bitcoin_cli,
        format!(
            r#"#!/bin/sh
while [ "${{1#-}}" != "$1" ]; do shift; done
echo "$1" >> '{dir}/calls'
case "$1" in
getblockchaininfo) cat '{dir}/info';;
zark_observe) cat '{dir}/evidence';;
zark_prepare) sleep 1; exit 9;;
*) exit 9;;
esac
"#,
            dir = root.display()
        ),
    )?;
    fs::set_permissions(&config.bitcoin_cli, fs::Permissions::from_mode(0o700))?;
    Ok(cleanup)
}

fn calls(config: &ChainConfig) -> String {
    std::fs::read_to_string(config.datadir.join("calls")).unwrap_or_default()
}

#[test]
fn connections_are_prepared_only_for_bridges_that_advertised_it_and_never_awaited() -> Result<()> {
    let (mut config, _, _, _, evidence) = fixture()?;
    let mut info = evidence["reads"][0]["result"].clone();
    let _old = fake_cli(&mut config, &info, &evidence)?;
    config.discover_observation()?;
    config.prepare_connection();
    let (mut prepared, _, _, _, _) = fixture()?;
    info["zark_prepare_version"] = json!(1);
    let _new = fake_cli(&mut prepared, &info, &evidence)?;
    // Undiscovered bridges are never sent an unknown method.
    prepared.prepare_connection();
    prepared.discover_observation()?;
    let started = std::time::Instant::now();
    prepared.prepare_connection();
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    let deadline = started + std::time::Duration::from_secs(10);
    while !calls(&prepared).contains("zark_prepare") {
        assert!(std::time::Instant::now() < deadline, "prepare never ran");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::thread::sleep(std::time::Duration::from_millis(1_500));
    assert_eq!(calls(&prepared), "getblockchaininfo\nzark_prepare\n");
    assert_eq!(calls(&config), "getblockchaininfo\n");
    Ok(())
}

#[test]
fn negotiated_observations_use_one_rpc_each_and_never_downgrade_on_failure() -> Result<()> {
    use std::fs;
    let (mut config, backing, deposit, _, mut evidence) = fixture()?;
    let mut info = evidence["reads"][0]["result"].clone();
    info["zark_observation_version"] = json!(1);
    let _cleanup = fake_cli(&mut config, &info, &evidence)?;
    let root = config.datadir.clone();
    // Early discovery reads only the capability, once.
    config.discover_observation()?;
    config.discover_observation()?;
    assert_eq!(
        fs::read_to_string(root.join("calls"))?,
        "getblockchaininfo\n"
    );
    for _ in 0..3 {
        config.observe(&backing, &deposit)?;
    }
    // Helper threads that read alongside a signer request share discovery.
    std::thread::scope(|scope| {
        scope
            .spawn(|| config.observe(&backing, &deposit))
            .join()
            .unwrap()
    })?;
    assert_eq!(
        fs::read_to_string(root.join("calls"))?,
        "getblockchaininfo\nzark_observe\nzark_observe\nzark_observe\nzark_observe\n"
    );
    // A failure on a negotiated gateway is an error, never a fallback that
    // could turn an unavailable/spent output into a different successful read.
    evidence["reads"][5]["result"] = Value::Null;
    fs::write(root.join("evidence"), serde_json::to_vec(&evidence)?)?;
    assert!(config.observe(&backing, &deposit).is_err());
    assert_eq!(fs::read_to_string(root.join("calls"))?.lines().count(), 6);
    evidence["reads"][6]["result"]["bestblockhash"] = json!("88".repeat(32));
    fs::write(root.join("evidence"), serde_json::to_vec(&evidence)?)?;
    assert!(config.observe(&backing, &deposit).is_err());
    assert_eq!(
        fs::read_to_string(root.join("calls"))?.lines().count(),
        9,
        "tip churn is bounded to three attempts"
    );
    Ok(())
}
