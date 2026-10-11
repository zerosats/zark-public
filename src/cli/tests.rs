use super::address::validate_address;
use super::arguments::*;
use super::batch::*;
use super::mail::verify_mail_peer;
use super::proofs::{parse_private_witness, toml_bytes};
use super::storage::*;
use super::*;
use crate::{invitation::LocalInvitation, origin::OriginJournal};
use anyhow::Result;
use bitcoin::{Address, Network};
use clap::Parser;
use serde_json::json;
use std::{fs, path::PathBuf};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    batch::Manifest as BatchManifest,
    handoff::TransferContext,
    lineage::LineagePolicy,
};

#[test]
fn peer_verification_returns_false_for_invalid_remote_input() {
    let home = TestHome::new();
    let deployment = [23; 32];
    let sender =
        LocalInvitation::create(&home.0.join("sender"), AddressNetwork::Test, deployment).unwrap();
    let receiver =
        LocalInvitation::create(&home.0.join("receiver"), AddressNetwork::Test, deployment)
            .unwrap();
    let source = sender.public_address().unwrap().encode();
    let destination = receiver.public_address().unwrap().encode();
    let message = json!({"kind":"swap2-terms","payload":{"version":2}});
    let signature = sender.sign_peer_message(&destination, &message).unwrap();
    assert!(verify_mail_peer(
        &deployment,
        &source,
        &destination,
        &message,
        &signature
    ));
    for bad in ["not hex", "", &"00".repeat(64)] {
        assert!(!verify_mail_peer(
            &deployment,
            &source,
            &destination,
            &message,
            bad
        ));
    }
    assert!(!verify_mail_peer(
        &deployment,
        "bad address",
        &destination,
        &message,
        &signature
    ));
    assert!(!verify_mail_peer(
        &[24; 32],
        &source,
        &destination,
        &message,
        &signature
    ));
    assert!(!verify_mail_peer(
        &deployment,
        &source,
        &destination,
        &json!({"changed":true}),
        &signature
    ));
}
struct TestHome(PathBuf);
impl TestHome {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zark-cli-init-{}",
            hex::encode(zark_protocol::random32())
        ));
        new_directory(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn origin_metadata() -> Metadata {
    Metadata {
        version: 10,
        deployment: "a".repeat(64),
        manifest_sha256: "b".repeat(64),
        kind: Kind::Origin {
            amount: 100_000,
            activation_fee: 1000,
            recovery_fee: 1000,
        },
    }
}

fn public_context(coin: u8) -> Result<TransferContext> {
    Ok(TransferContext {
        start_revision: 17,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: [19; 32],
        coin: [coin; 32],
        previous_state: [7; 32],
        operation: [coin + 80; 32],
        recipient_claim: [9; 32],
        session_auth: k256::schnorr::SigningKey::from_bytes(&[23; 32])?
            .verifying_key()
            .to_bytes()
            .into(),
    })
}

#[test]
fn receiving_address_preflight_checks_checksum_network_deployment_and_type() -> Result<()> {
    let home = TestHome::new();
    let deployment = [19; 32];
    let invitation =
        LocalInvitation::create(&home.0.join("address"), AddressNetwork::Test, deployment)?;
    let public = invitation.public_address()?;
    let zark = public.encode();
    assert_eq!(
        validate_address(&zark, &deployment, Network::Signet)?,
        "zark"
    );
    assert!(validate_address(&zark, &[20; 32], Network::Signet).is_err());
    let mainnet_zark = ReceivingAddress::new(
        AddressNetwork::MainnetReserved,
        deployment,
        *public.envelope_key(),
        *public.claim_key(),
    )?
    .encode();
    assert!(validate_address(&mainnet_zark, &deployment, Network::Signet).is_err());
    let output = crate::bitcoin::p2tr(&public_context(2)?.session_auth);
    let bitcoin = Address::from_script(&output, Network::Signet)?.to_string();
    assert_eq!(
        validate_address(&bitcoin, &deployment, Network::Signet)?,
        "bitcoin"
    );
    let regtest = Address::from_script(&output, Network::Regtest)?.to_string();
    assert_eq!(
        validate_address(&regtest, &deployment, Network::Regtest)?,
        "bitcoin"
    );
    assert!(validate_address(&regtest, &deployment, Network::Signet).is_err());
    let mainnet = Address::from_script(&output, Network::Bitcoin)?.to_string();
    assert!(validate_address(&mainnet, &deployment, Network::Signet).is_err());
    let mut segwit_script = vec![0, 32];
    segwit_script.extend([4; 32]);
    let segwit = Address::from_script(
        &bitcoin::ScriptBuf::from_bytes(segwit_script),
        Network::Signet,
    )?
    .to_string();
    assert!(validate_address(&segwit, &deployment, Network::Signet).is_err());
    for original in [zark, bitcoin] {
        let mut changed = original.clone();
        let last = changed.pop().unwrap();
        changed.push(if last == 'q' { 'p' } else { 'q' });
        assert!(validate_address(&changed, &deployment, Network::Signet).is_err());
        assert!(validate_address(&format!(" {original}"), &deployment, Network::Signet).is_err());
    }
    for invalid in [
        "",
        "invalid",
        "bitcoin:tb1pnot-a-payment-uri",
        "tzark1invalid",
    ] {
        assert!(validate_address(invalid, &deployment, Network::Signet).is_err());
    }
    let cli = Cli::try_parse_from([
        "zark-wallet",
        "--config",
        "config.json",
        "validate-address",
        "--address",
        &regtest,
    ])?;
    assert!(matches!(cli.command, Action::ValidateAddress { .. }));
    Ok(())
}

#[test]
fn public_peer_draft_binds_context_coin_deployment_and_revision() -> Result<()> {
    let home = TestHome::new();
    let context = public_context(3)?;
    let original = json!({"context": hex::encode(context.encode()?), "coin": hex::encode(context.coin), "revision": 17});
    let path = home.0.join("peer.json");
    write_new(&path, &serde_json::to_vec(&original)?)?;
    let peer = read_peer_batch_member(&path, &context.deployment)?;
    assert_eq!(peer, member_from_context(&context, 17));
    assert!(read_peer_batch_member(&path, &[20; 32]).is_err());
    for case in 0..5 {
        let mut changed = original.clone();
        match case {
            0 => changed["coin"] = json!("04".repeat(32)),
            1 => changed["revision"] = json!(0),
            2 => changed["context"] = json!(format!("{}00", hex::encode(context.encode()?))),
            3 => changed["operation"] = json!("/private/peer/journal"),
            _ => changed["context"] = json!("invalid"),
        }
        let path = home.0.join(format!("changed-{case}.json"));
        write_new(&path, &serde_json::to_vec(&changed)?)?;
        assert!(read_peer_batch_member(&path, &context.deployment).is_err());
    }
    Ok(())
}

#[test]
fn portable_manifest_retry_requires_same_peer_and_local_sender() -> Result<()> {
    let local = public_context(2)?;
    let peer = member_from_context(&public_context(3)?, 17);
    let manifest = BatchManifest {
        id: [11; 32],
        deployment: local.deployment,
        expires_at: 1000,
        members: vec![member_from_context(&local, 17), peer.clone()],
    };
    require_saved_peer(&manifest, &local, &peer)?;
    for case in 0..6 {
        let mut changed = peer.clone();
        match case {
            0 => changed.revision += 1,
            1 => changed.coin = [4; 32],
            2 => changed.previous_state = [4; 32],
            3 => changed.operation = [4; 32],
            4 => changed.recipient_claim = [4; 32],
            _ => changed.sender_session = [4; 32],
        }
        assert!(require_saved_peer(&manifest, &local, &changed).is_err());
    }
    assert!(require_saved_peer(&manifest, &local, &manifest.members[0]).is_err());
    let mut changed = local.clone();
    changed.operation = [4; 32];
    assert!(require_saved_peer(&manifest, &changed, &peer).is_err());
    changed = local.clone();
    changed.deployment = [4; 32];
    assert!(require_saved_peer(&manifest, &changed, &peer).is_err());
    Ok(())
}

#[test]
fn receiver_amount_expectation_is_frozen_in_metadata_and_optional_for_legacy() -> Result<()> {
    let home = TestHome::new();
    let destination = home.0.join("receiver");
    let mut expected = origin_metadata();
    expected.kind = Kind::Receiver {
        invitation: home.0.join("invitation"),
        coin: "01".repeat(32),
        transfer_operation: "02".repeat(32),
        offer_sha256: "03".repeat(32),
        recovery_fee: 1000,
        batch: None,
        expected_amount: Some(100_000),
        group: None,
    };
    initialize_metadata(&destination, &expected)?;
    assert!(initialize_metadata(&destination, &expected)? == expected);
    let before = fs::read(destination.join("operation.json"))?;
    for amount in [Some(99_000), None] {
        let mut changed = expected.clone();
        if let Kind::Receiver {
            expected_amount, ..
        } = &mut changed.kind
        {
            *expected_amount = amount;
        }
        assert!(initialize_metadata(&destination, &changed).is_err());
    }
    assert_eq!(fs::read(destination.join("operation.json"))?, before);
    let mut legacy = serde_json::to_value(&expected)?;
    legacy["kind"]
        .as_object_mut()
        .unwrap()
        .remove("expected_amount");
    let legacy: Metadata = serde_json::from_value(legacy)?;
    assert!(matches!(
        legacy.kind,
        Kind::Receiver {
            expected_amount: None,
            ..
        }
    ));
    assert!(!serde_json::to_string(&legacy)?.contains("expected_amount"));
    Ok(())
}

#[test]
fn cli_peer_draft_is_an_exclusive_alternative_and_expected_amount_is_positive() {
    let base = [
        "zark-wallet",
        "--config",
        "config.json",
        "batch-manifest",
        "--first",
        "local",
        "--expires-at",
        "1000",
        "--output",
        "manifest.json",
    ];
    assert!(Cli::try_parse_from(base).is_err());
    for alternative in ["--second", "--peer"] {
        assert!(Cli::try_parse_from(base.into_iter().chain([alternative, "peer"])).is_ok());
    }
    assert!(
        Cli::try_parse_from(base.into_iter().chain([
            "--second",
            "local-two",
            "--peer",
            "peer.json"
        ]))
        .is_err()
    );
    let receive = [
        "zark-wallet",
        "--config",
        "config.json",
        "receive",
        "--invitation",
        "invitation",
        "--operation",
        "operation",
        "--offer",
        "offer",
        "--coin",
        "coin",
        "--transfer-operation",
        "transfer",
    ];
    assert!(Cli::try_parse_from(receive).is_ok());
    assert!(
        Cli::try_parse_from(receive.into_iter().chain(["--expected-amount", "100000"])).is_ok()
    );
    assert!(Cli::try_parse_from(receive.into_iter().chain(["--expected-amount", "0"])).is_err());
}
#[test]
fn interrupted_metadata_creation_is_unpublished_and_retries_same_intent() -> Result<()> {
    let home = TestHome::new();
    let destination = home.0.join("operation");
    let metadata = origin_metadata();
    let intent = serde_json::to_vec(&metadata)?;
    let failed: Result<Metadata> = initialize_cli_local(
        &destination,
        &intent,
        |attempt| {
            new_directory(attempt)?;
            write_new(&attempt.join("operation.json"), b"{\"version\":")?;
            anyhow::bail!("simulated interrupted metadata write")
        },
        read_metadata,
    );
    assert!(failed.is_err());
    assert!(!destination.exists());
    let mut changed = metadata.clone();
    changed.kind = Kind::Origin {
        amount: 200_000,
        activation_fee: 1000,
        recovery_fee: 1000,
    };
    assert!(initialize_metadata(&destination, &changed).is_err());
    assert!(initialize_metadata(&destination, &metadata)? == metadata);
    let original = fs::read(destination.join("operation.json"))?;
    assert!(initialize_metadata(&destination, &metadata)? == metadata);
    assert!(initialize_metadata(&destination, &changed).is_err());
    assert_eq!(fs::read(destination.join("operation.json"))?, original);
    let stage = initialization_path(&destination)?;
    assert!(
        fs::read_dir(stage)?
            .filter_map(Result::ok)
            .any(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
    );
    Ok(())
}
#[test]
fn interrupted_native_origin_creation_recovers_without_replacing_complete_keys() -> Result<()> {
    let home = TestHome::new();
    let destination = home.0.join("journal");
    let mut hashes = [[0; 32]; zark_protocol::lineage::ROLE_COUNT];
    for (i, hash) in hashes.iter_mut().enumerate() {
        hash[31] = (i + 1) as u8;
    }
    let policy = LineagePolicy {
        deployment: [19; 32],
        schedule: zark_protocol::handoff::RecoverySchedule {
            initial: 480,
            gap: 60,
            margin: 6,
        },
        origin_key: k256::schnorr::SigningKey::from_bytes(&[23; 32])?
            .verifying_key()
            .to_bytes()
            .into(),
        role_hashes: hashes,
    };
    let intent = serde_json::to_vec(&origin_metadata())?;
    let failed: Result<OriginJournal> = initialize_cli_local(
        &destination,
        &intent,
        |attempt| {
            new_directory(attempt)?;
            anyhow::bail!("simulated interrupted origin record")
        },
        |path| OriginJournal::open(path, &policy),
    );
    assert!(failed.is_err());
    assert!(!destination.exists());
    let origin = initialize_cli_local(
        &destination,
        &intent,
        |path| OriginJournal::create(path, &policy, 100_000, 1000, 1000),
        |path| OriginJournal::open(path, &policy),
    )?;
    let context = origin.context().clone();
    origin.require_parameters(100_000, 1000, 1000)?;
    for (amount, activation, recovery) in [
        (200_000, 1000, 1000),
        (100_000, 999, 1000),
        (100_000, 1000, 999),
    ] {
        assert!(
            origin
                .require_parameters(amount, activation, recovery)
                .is_err()
        );
    }
    drop(origin);
    let reopened = initialize_cli_local(
        &destination,
        &intent,
        |_| -> Result<OriginJournal> { panic!("completed native journal must not be regenerated") },
        |path| OriginJournal::open(path, &policy),
    )?;
    assert!(reopened.context() == &context);
    Ok(())
}
#[test]
fn cli_requires_explicit_configuration_and_operation() {
    assert!(Cli::try_parse_from(["zark-wallet", "status"]).is_err());
    assert!(
        Cli::try_parse_from([
            "zark-wallet",
            "--config",
            "config.json",
            "resume",
            "--operation",
            "op"
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "zark-wallet",
            "--config",
            "config.json",
            "exit",
            "--owner",
            "alice",
            "--operation",
            "exit",
            "--to",
            "address"
        ])
        .is_ok()
    );
}
#[test]
fn public_witness_parser_rejects_out_of_range_and_non_arrays() {
    let value: toml::Value = toml::from_str("statement = [0, 255, '0x00ff']").unwrap();
    assert_eq!(toml_bytes(&value, "statement").unwrap(), vec![0, 255, 255]);
    for text in [
        "statement = [256]",
        "statement = [-1]",
        "statement = '00'",
        "statement = ['secret']",
    ] {
        assert!(toml_bytes(&toml::from_str::<toml::Value>(text).unwrap(), "statement").is_err());
    }
}
#[test]
fn malformed_private_witness_errors_do_not_echo_source() {
    const MARKER: &str = "private-scalar-marker-do-not-print";
    let malformed = format!("user = '{MARKER}\nstatement = [0]");
    let error = parse_private_witness(malformed.as_bytes()).unwrap_err();
    assert_eq!(error.to_string(), "invalid private witness TOML");
    assert!(!format!("{error:#}").contains(MARKER));
    let invalid_utf8 = [MARKER.as_bytes(), &[0xff]].concat();
    let error = parse_private_witness(&invalid_utf8).unwrap_err();
    assert_eq!(error.to_string(), "invalid private witness encoding");
    assert!(!format!("{error:#}").contains(MARKER));
    let value = parse_private_witness(format!("statement = ['{MARKER}']").as_bytes()).unwrap();
    let error = toml_bytes(&value, "statement").unwrap_err();
    assert!(!format!("{error:#}").contains(MARKER));
}
#[test]
fn operation_metadata_rejects_unknown_or_retargeted_fields() {
    let m = Metadata {
        version: 10,
        deployment: "a".into(),
        manifest_sha256: "b".into(),
        kind: Kind::Origin {
            amount: 100000,
            activation_fee: 1000,
            recovery_fee: 1000,
        },
    };
    let mut changed = m.clone();
    changed.kind = Kind::Origin {
        amount: 200000,
        activation_fee: 1000,
        recovery_fee: 1000,
    };
    assert!(changed != m);
    let mut value = serde_json::to_value(m).unwrap();
    value["arbitrary_import"] = json!(true);
    assert!(serde_json::from_value::<Metadata>(value).is_err());
}
#[test]
fn private_inputs_reject_links_permissions_and_output_replacement() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = std::env::temp_dir().join(format!(
        "zark-cli-test-{}",
        hex::encode(zark_protocol::random32())
    ));
    new_directory(&root).unwrap();
    let path = root.join("secret");
    write_new(&path, b"first").unwrap();
    assert_eq!(&*read_private(&path, 10).unwrap(), b"first");
    assert!(write_exact(&path, b"different").is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_private(&path, 10).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&path, root.join("symlink")).unwrap();
    assert!(read_private(&root.join("symlink"), 10).is_err());
    fs::hard_link(&path, root.join("hardlink")).unwrap();
    assert!(read_private(&path, 10).is_err());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn wallet_configuration_pinning_the_retired_python_helper_fails_explicitly() {
    let root = std::env::temp_dir().join(format!(
        "zark-cli-test-{}",
        hex::encode(zark_protocol::random32())
    ));
    new_directory(&root).unwrap();
    let path = root.join("wallet.json");
    let legacy = json!({"version": 10, "fast_runtime": {
        "python": {"path": "/retired/python3", "sha256": "00"},
        "python_assets": {}, "helper_directory": "/retired/helper", "helper_sha256": {}}});
    write_new(&path, &serde_json::to_vec(&legacy).unwrap()).unwrap();
    let error = App::load(&path, true).err().unwrap().to_string();
    assert!(
        error.contains("retired Python fast-prover helper"),
        "{error}"
    );
    fs::remove_dir_all(root).unwrap();
}
