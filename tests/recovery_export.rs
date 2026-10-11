//! All keys and transactions here are synthetic and unfunded. No live wallet,
//! signer, node, proof files, or predecessor owner records are read.
use bitcoin::{
    OutPoint, Transaction, Txid,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde_json::{Value, json};
use std::{
    ffi::CString,
    fs,
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
};
use zark_protocol::{
    handoff::{RecoveryDelay, RecoverySchedule, TransferContext},
    point_bytes, random32, scalar,
};
use zark_wallet::{
    bitcoin::{attach_signature, p2tr, sighash},
    recovery::{RecoveryDraft, RecoveryParameters},
    recovery_export::{MAX_EXPORT_BYTES, PortableRecovery},
    signing::{Blinding, FundingKey},
    types::Input,
};
use zeroize::Zeroizing;

const DEPLOYMENT: [u8; 32] = [101; 32];
const COIN: [u8; 32] = [102; 32];

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("zark-export-test-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn export(&self) -> PathBuf {
        self.0.join("recovery.json")
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    parameters: RecoveryParameters,
    user: [u8; 32],
    payout: [u8; 32],
    server: Scalar,
}

// The server contribution is deliberately a separate synthetic test helper.
// No production receiver/export API receives either server secret or nonce.
fn sign_funding(tx: &mut Transaction, amount: u64, user: Scalar, server: Scalar) {
    let server_point = ProjectivePoint::GENERATOR * server;
    let key = FundingKey::new(server_point, user).unwrap();
    let nonce = Scalar::from(17u64);
    let rs = ProjectivePoint::GENERATOR * nonce;
    let blind = Blinding::default();
    let session = blind
        .bind(
            &key,
            server_point,
            rs,
            sighash(tx, amount, key.xonly().unwrap()).unwrap(),
        )
        .unwrap();
    let signature = blind
        .finish(
            &key,
            &session,
            server_point,
            rs,
            nonce + session.challenge * server,
        )
        .unwrap();
    attach_signature(tx, amount, key.xonly().unwrap(), &signature).unwrap();
}

fn fixture() -> Fixture {
    let server = Scalar::from(7u64);
    let user = Scalar::from(23u64);
    let key = FundingKey::new(ProjectivePoint::GENERATOR * server, user).unwrap();
    let deposit_key = FundingKey::new(
        ProjectivePoint::GENERATOR * Scalar::from(21u64),
        Scalar::from(31u64),
    )
    .unwrap();
    let deposit = OutPoint::new(Txid::from_byte_array([103; 32]), 2);
    let activation_parent = Input {
        deployment: hex::encode(DEPLOYMENT),
        id: hex::encode([104; 32]),
        funding_salt: hex::encode([105; 32]),
        internal_point: hex::encode(point_bytes(deposit_key.internal).unwrap()),
        txid: deposit.txid.to_string(),
        vout: deposit.vout,
        amount: 100_000,
    };
    let mut activation =
        zark_wallet::bitcoin::activation(deposit, 100_000, &[(99_000, key.xonly().unwrap())], 0)
            .unwrap();
    sign_funding(
        &mut activation,
        100_000,
        Scalar::from(31u64),
        Scalar::from(21u64),
    );
    let backing = Input {
        deployment: hex::encode(DEPLOYMENT),
        id: hex::encode(COIN),
        funding_salt: hex::encode([106; 32]),
        internal_point: hex::encode(point_bytes(key.internal).unwrap()),
        txid: activation.compute_txid().to_string(),
        vout: 0,
        amount: 99_000,
    };
    Fixture {
        parameters: RecoveryParameters {
            context: TransferContext {
                start_revision: 1,
                scope: zark_protocol::handoff::OperationScope::Single,
                deployment: DEPLOYMENT,
                coin: COIN,
                previous_state: [107; 32],
                operation: [108; 32],
                recipient_claim: [109; 32],
                session_auth: SigningKey::from_bytes(&Scalar::from(41u64).to_bytes())
                    .unwrap()
                    .verifying_key()
                    .to_bytes()
                    .into(),
            },
            backing,
            activation_input: activation_parent,
            activation,
            draft_server: point_bytes(ProjectivePoint::GENERATOR * server).unwrap(),
            refresh_commitment: [110; 32],
            previous_capability: [111; 32],
            next_capability: [112; 32],
            schedule: RecoverySchedule {
                initial: 480,
                gap: 60,
                margin: 6,
            },
            previous_delay: RecoveryDelay::from_sequence(480).unwrap(),
            next_delay: RecoveryDelay::from_sequence(420).unwrap(),
            fee: 1000,
        },
        user: user.to_bytes().into(),
        payout: Scalar::from(37u64).to_bytes().into(),
        server,
    }
}

fn complete(home: &Home) -> (RecoveryDraft, [Transaction; 2]) {
    let fixture = fixture();
    let context = fixture.parameters.context.clone();
    let activation = fixture.parameters.activation.clone();
    let nonce = Scalar::from(29u64);
    let rs = point_bytes(ProjectivePoint::GENERATOR * nonce).unwrap();
    let mut draft = RecoveryDraft::create(
        &home.0.join("draft"),
        fixture.parameters,
        &fixture.user,
        &fixture.payout,
    )
    .unwrap();
    let binding = draft.bind_server_nonce(&context, rs).unwrap();
    let partial = (nonce + scalar(&binding.blinded_challenge).unwrap() * fixture.server)
        .to_bytes()
        .into();
    let recovery = draft.finish(&context, rs, partial).unwrap();
    (draft, [activation, recovery])
}

fn read(path: &Path) -> anyhow::Result<PortableRecovery> {
    PortableRecovery::read(path, &DEPLOYMENT, &COIN)
}

fn write_test_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn copied_export_alone_validates_both_transactions_and_controls_its_payout() {
    let source = Home::new();
    let (draft, expected) = complete(&source);
    draft.export_portable(&source.export()).unwrap();
    assert_eq!(
        fs::metadata(source.export()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let original_bytes = Zeroizing::new(fs::read(source.export()).unwrap());
    // Existing destination, including a prior valid export, is never replaced.
    assert!(draft.export_portable(&source.export()).is_err());
    assert!(fs::read(source.export()).unwrap() == *original_bytes);
    let portable_home = Home::new();
    fs::copy(source.export(), portable_home.export()).unwrap();
    drop(draft);
    let source_path = source.0.clone();
    drop(source); // Deletes only this test's synthetic draft and original file.
    assert!(!source_path.exists());
    assert_eq!(fs::read_dir(&portable_home.0).unwrap().count(), 1);
    let portable = read(&portable_home.export()).unwrap();
    assert_eq!(portable.transactions().unwrap(), expected);
    assert_eq!(portable.relative_blocks(), 420);
    let destination: [u8; 32] = SigningKey::from_bytes(&Scalar::from(43u64).to_bytes())
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into();
    let mut spend = portable.sign_payout_spend(destination, 1000).unwrap();
    assert_eq!(
        spend.input[0].previous_output,
        OutPoint::new(expected[1].compute_txid(), 0)
    );
    assert_eq!(spend.output[0].value.to_sat(), 97_000);
    assert_eq!(spend.output[0].script_pubkey, p2tr(&destination));
    let signature: [u8; 64] = spend.input[0].witness[0].try_into().unwrap();
    spend.input[0].witness.clear();
    let payout_key: [u8; 32] = expected[1].output[0].script_pubkey.as_bytes()[2..]
        .try_into()
        .unwrap();
    attach_signature(&mut spend, 98_000, payout_key, &signature).unwrap();
    for fee in [0, 10_001, 98_000, u64::MAX] {
        assert!(portable.sign_payout_spend(destination, fee).is_err());
    }
    assert!(portable.sign_payout_spend([255; 32], 1000).is_err());
}

#[test]
fn export_contains_no_history_or_receiver_signing_material() {
    let home = Home::new();
    let (draft, _) = complete(&home);
    draft.export_portable(&home.export()).unwrap();
    let bytes = Zeroizing::new(fs::read(home.export()).unwrap());
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        vec![
            "activation",
            "activation_parent",
            "backing",
            "coin",
            "deployment",
            "fee_sat",
            "payout_secret",
            "protocol_version",
            "recovery",
            "relative_blocks",
            "schema",
            "version"
        ]
    );
    for name in ["activation_parent", "backing"] {
        assert_eq!(
            value[name]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["amount", "output_key", "txid", "vout"]
        );
    }
    for forbidden in [
        "user_secret",
        "alpha",
        "beta",
        "server_nonce",
        "partial",
        "funding_salt",
        "backup_salt",
        "nonce_salt",
        "draft_server",
        "refresh_commitment",
        "previous_capability",
        "next_capability",
        "proofs",
        "history",
        "mask",
        "delta",
    ] {
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains(&format!("\"{forbidden}\""))
        );
    }
}

#[test]
fn metadata_keys_transactions_and_unexpected_fields_fail_closed() {
    let home = Home::new();
    let (draft, _) = complete(&home);
    draft.export_portable(&home.export()).unwrap();
    let original: Value =
        serde_json::from_slice(&Zeroizing::new(fs::read(home.export()).unwrap())).unwrap();
    let mut changes: Vec<Value> = Vec::new();
    macro_rules! altered {
        ($($index:expr),+ => $value:expr) => {{ let mut v = original.clone(); v$([$index])+ = $value; changes.push(v); }};
    }
    altered!("version" => json!(2));
    altered!("protocol_version" => json!(7));
    altered!("deployment" => json!(([1u8; 32])));
    altered!("coin" => json!(([1u8; 32])));
    altered!("activation_parent", "amount" => json!(100_001));
    altered!("activation_parent", "vout" => json!(3));
    altered!("activation_parent", "txid" => json!(hex::encode([1; 32])));
    altered!("activation_parent", "output_key" => json!(([255u8; 32])));
    altered!("backing", "amount" => json!(99_001));
    altered!("backing", "vout" => json!(1));
    altered!("backing", "txid" => json!(hex::encode([1; 32])));
    altered!("backing", "output_key" => json!(([255u8; 32])));
    altered!("fee_sat" => json!(999));
    altered!("relative_blocks" => json!(119));
    altered!("relative_blocks" => json!(1u32 << 22));
    altered!("relative_blocks" => json!(1u32 << 31));
    altered!("payout_secret" => json!(([0u8; 32])));
    altered!("payout_secret" => json!(([255u8; 32])));
    altered!("payout_secret" => json!(<[u8; 32]>::from(Scalar::from(38u64).to_bytes())));
    let saved_scalar: [u8; 32] = serde_json::from_value(original["payout_secret"].clone()).unwrap();
    altered!("payout_secret" => json!(<[u8; 32]>::from((-scalar(&saved_scalar).unwrap()).to_bytes())));
    altered!("history" => json!([]));
    altered!("backing", "history" => json!([]));
    altered!("activation" => json!(original["activation"].as_str().unwrap().to_uppercase()));
    altered!("recovery" => json!("00".repeat(1025)));
    for field in ["activation", "recovery"] {
        let mut tx: Transaction =
            deserialize(&hex::decode(original[field].as_str().unwrap()).unwrap()).unwrap();
        let mut signature = tx.input[0].witness[0].to_vec();
        signature[4] ^= 1;
        tx.input[0].witness.clear();
        tx.input[0].witness.push(signature);
        altered!(field => json!(hex::encode(serialize(&tx))));
    }
    for (index, value) in changes.iter().enumerate() {
        let path = home.0.join(format!("bad-{index}.json"));
        write_test_file(&path, &Zeroizing::new(serde_json::to_vec(value).unwrap()));
        assert!(
            read(&path).is_err(),
            "invalid synthetic export case {index} accepted"
        );
    }
    assert!(PortableRecovery::read(&home.export(), &[0; 32], &COIN).is_err());
    assert!(PortableRecovery::read(&home.export(), &DEPLOYMENT, &[0; 32]).is_err());
    assert!(PortableRecovery::read(&home.export(), &[1; 32], &COIN).is_err());
    assert!(PortableRecovery::read(&home.export(), &DEPLOYMENT, &[1; 32]).is_err());
}

#[test]
fn valid_signatures_cannot_relax_recovery_shape_or_relative_delay_rules() {
    let home = Home::new();
    let (draft, _) = complete(&home);
    draft.export_portable(&home.export()).unwrap();
    let original: Value =
        serde_json::from_slice(&Zeroizing::new(fs::read(home.export()).unwrap())).unwrap();
    for case in 0..6 {
        let mut value = original.clone();
        let mut tx: Transaction =
            deserialize(&hex::decode(value["recovery"].as_str().unwrap()).unwrap()).unwrap();
        tx.input[0].witness.clear();
        match case {
            0 => {
                tx.input[0].sequence = bitcoin::Sequence::MAX;
                value["relative_blocks"] = json!(u32::MAX);
            }
            1 => {
                tx.input[0].sequence = bitcoin::Sequence(1 << 22 | 120);
                value["relative_blocks"] = json!(1 << 22 | 120);
            }
            2 => tx.version = bitcoin::transaction::Version::ONE,
            3 => tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1),
            4 => {
                tx.output[0].value = bitcoin::Amount::from_sat(50_000);
                value["fee_sat"] = json!(49_000);
            }
            _ => {
                tx.output[0].value = bitcoin::Amount::from_sat(97_000);
                let mut second = tx.output[0].clone();
                second.value = bitcoin::Amount::from_sat(1000);
                tx.output.push(second);
            }
        }
        sign_funding(&mut tx, 99_000, Scalar::from(23u64), Scalar::from(7u64));
        value["recovery"] = json!(hex::encode(serialize(&tx)));
        let path = home.0.join(format!("signed-bad-{case}.json"));
        write_test_file(&path, &Zeroizing::new(serde_json::to_vec(&value).unwrap()));
        assert!(read(&path).is_err());
    }
}

#[test]
fn partial_or_unsafe_files_and_incomplete_drafts_cannot_be_exports() {
    let home = Home::new();
    let f = fixture();
    let draft =
        RecoveryDraft::create(&home.0.join("draft"), f.parameters, &f.user, &f.payout).unwrap();
    assert!(draft.export_portable(&home.export()).is_err());
    assert!(!home.export().exists());
    let other = Home::new();
    let (completed, _) = complete(&other);
    completed.export_portable(&other.export()).unwrap();
    let original = Zeroizing::new(fs::read(other.export()).unwrap());
    for (index, cut) in [0, 1, 20, original.len() / 2, original.len() - 1]
        .into_iter()
        .enumerate()
    {
        let path = home.0.join(format!("partial-{index}.json"));
        write_test_file(&path, &original[..cut]);
        assert!(read(&path).is_err());
        assert!(completed.export_portable(&path).is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), cut as u64);
    }
    let huge = home.0.join("huge.json");
    write_test_file(&huge, &vec![b' '; MAX_EXPORT_BYTES as usize + 1]);
    assert!(read(&huge).is_err());
    let soft = home.0.join("symlink.json");
    symlink(other.export(), &soft).unwrap();
    assert!(read(&soft).is_err());
    assert!(completed.export_portable(&soft).is_err());
    let hard = home.0.join("hardlink.json");
    fs::hard_link(other.export(), &hard).unwrap();
    assert!(read(&hard).is_err());
    fs::remove_file(&hard).unwrap();
    let fifo = home.0.join("fifo.json");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // Opening a FIFO without O_NONBLOCK would wait forever before its type check.
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    assert!(read(&fifo).is_err());
    fs::set_permissions(other.export(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read(&other.export()).is_err());
    fs::set_permissions(other.export(), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&other.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(read(&other.export()).is_err());
}
