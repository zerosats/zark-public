//! Synthetic transaction construction and explicit proof-qualification exports.
use bitcoin::{OutPoint, Txid, consensus::serialize, hashes::Hash};
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};
use zark_protocol::{
    even,
    handoff::{RecoveryDelay, RecoverySchedule, SigningBinding, TransferContext},
    point_bytes, random32, scalar, tagged_hash,
};
use zark_wallet::{
    bitcoin::{attach_signature, sighash},
    recovery::{RecoveryDraft, RecoveryParameters},
    signing::{Blinding, FundingKey},
    types::Input,
};

pub(super) struct Home(pub(super) PathBuf);
impl Home {
    pub(super) fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("zark-recovery-test-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    pub(super) fn draft(&self) -> PathBuf {
        self.0.join("draft")
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) struct Fixture {
    pub(super) parameters: RecoveryParameters,
    pub(super) user: [u8; 32],
    pub(super) payout: [u8; 32],
    pub(super) server: Scalar,
    pub(super) server_nonce: Scalar,
    pub(super) session_secret: Scalar,
}

pub(super) fn fixture() -> Fixture {
    fixture_with_shares(Scalar::from(23u64), Scalar::from(7u64))
}

pub(super) fn fixture_with_shares(server: Scalar, user: Scalar) -> Fixture {
    let context = TransferContext {
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: [9; 32],
        coin: [8; 32],
        previous_state: [7; 32],
        operation: [6; 32],
        recipient_claim: [5; 32],
        session_auth: SigningKey::from_bytes(&Scalar::from(41u64).to_bytes())
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into(),
    };
    // Default old shares are 13 + 17; receiver shares are 23 + 7.
    let backing_key = FundingKey::new(ProjectivePoint::GENERATOR * server, user).unwrap();
    let old_key = FundingKey::new(
        ProjectivePoint::GENERATOR * (server - Scalar::from(10u64)),
        user + Scalar::from(10u64),
    )
    .unwrap();
    assert!(backing_key.xonly().unwrap() == old_key.xonly().unwrap());
    let deposit_server = Scalar::from(21u64);
    let deposit_key = FundingKey::new(
        ProjectivePoint::GENERATOR * deposit_server,
        Scalar::from(31u64),
    )
    .unwrap();
    let activation_input = Input {
        deployment: hex::encode(context.deployment),
        id: hex::encode([10; 32]),
        funding_salt: hex::encode([11; 32]),
        internal_point: hex::encode(point_bytes(deposit_key.internal).unwrap()),
        txid: Txid::from_byte_array([12; 32]).to_string(),
        vout: 0,
        amount: 100_000,
    };
    let mut activation = zark_wallet::bitcoin::activation(
        OutPoint::new(Txid::from_byte_array([12; 32]), 0),
        100_000,
        &[(99_000, backing_key.xonly().unwrap())],
        0,
    )
    .unwrap();
    let activation_blind = Blinding::default();
    let activation_nonce = Scalar::from(17u64);
    let rs = ProjectivePoint::GENERATOR * activation_nonce;
    let server_point = ProjectivePoint::GENERATOR * deposit_server;
    let session = activation_blind
        .bind(
            &deposit_key,
            server_point,
            rs,
            sighash(&activation, 100_000, deposit_key.xonly().unwrap()).unwrap(),
        )
        .unwrap();
    let signature = activation_blind
        .finish(
            &deposit_key,
            &session,
            server_point,
            rs,
            activation_nonce + session.challenge * deposit_server,
        )
        .unwrap();
    attach_signature(
        &mut activation,
        100_000,
        deposit_key.xonly().unwrap(),
        &signature,
    )
    .unwrap();
    let backing = Input {
        deployment: hex::encode(context.deployment),
        id: hex::encode(context.coin),
        funding_salt: hex::encode([19; 32]),
        internal_point: hex::encode(point_bytes(backing_key.internal).unwrap()),
        txid: activation.compute_txid().to_string(),
        vout: 0,
        amount: 99_000,
    };
    Fixture {
        parameters: RecoveryParameters {
            context,
            backing,
            activation_input,
            activation,
            draft_server: point_bytes(ProjectivePoint::GENERATOR * server).unwrap(),
            refresh_commitment: [20; 32],
            previous_capability: [21; 32],
            next_capability: [22; 32],
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
        server_nonce: Scalar::from(29u64),
        session_secret: Scalar::from(41u64),
    }
}

/// A synthetic server helper, separate from the production receiver API.
pub(super) fn server_contribution(
    binding: &SigningBinding,
    server: Scalar,
    nonce: Scalar,
) -> [u8; 32] {
    assert!(binding.draft_server == point_bytes(ProjectivePoint::GENERATOR * server).unwrap());
    assert!(binding.server_nonce == point_bytes(ProjectivePoint::GENERATOR * nonce).unwrap());
    (nonce + scalar(&binding.blinded_challenge).unwrap() * server)
        .to_bytes()
        .into()
}

pub(super) fn export_fixture(variable: &str, fixture: &serde_json::Value) {
    let work = Path::new(env!("CARGO_MANIFEST_DIR")).join("work");
    fs::create_dir_all(&work).unwrap();
    let destination =
        PathBuf::from(std::env::var_os(variable).expect("explicit fixture destination"));
    assert!(destination.is_absolute());
    assert!(
        destination
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap()
            .starts_with(work.canonicalize().unwrap())
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(fixture).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}

pub(super) fn native_fixture_value(f: Fixture, nonce_odd: Option<bool>) -> serde_json::Value {
    let home = Home::new();
    let context = f.parameters.context.clone();
    let backing = f.parameters.backing.clone();
    let signed_activation = hex::encode(serialize(&f.parameters.activation));
    let fee = f.parameters.fee;
    let delay = f.parameters.next_delay.blocks();
    let server_point = ProjectivePoint::GENERATOR * f.server;
    let raw_internal = server_point + ProjectivePoint::GENERATOR * scalar(&f.user).unwrap();
    let internal = even(raw_internal).unwrap().0;
    let tweak = scalar(&tagged_hash(
        "TapTweak",
        &[&point_bytes(internal).unwrap()[..32]],
    ))
    .unwrap();
    let raw_output = internal + ProjectivePoint::GENERATOR * tweak;
    let mut draft = RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).unwrap();
    // Only this test's synthetic private record is inspected, never a real wallet.
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(home.draft().join("recovery-draft.json")).unwrap())
            .unwrap();
    let alpha =
        scalar(&serde_json::from_value::<[u8; 32]>(record["alpha"].clone()).unwrap()).unwrap();
    let beta =
        scalar(&serde_json::from_value::<[u8; 32]>(record["beta"].clone()).unwrap()).unwrap();
    let nonce = match nonce_odd {
        None => f.server_nonce,
        Some(expected) => (1u64..128)
            .map(Scalar::from)
            .find(|nonce| {
                let raw = ProjectivePoint::GENERATOR * (*nonce + alpha) + server_point * beta;
                (point_bytes(raw).unwrap()[63] & 1 == 1) == expected
            })
            .expect("synthetic nonce parity search"),
    };
    let raw_nonce = ProjectivePoint::GENERATOR * (nonce + alpha) + server_point * beta;
    let parities =
        [raw_internal, raw_output, raw_nonce].map(|p| point_bytes(p).unwrap()[63] & 1 == 1);
    let rs = point_bytes(ProjectivePoint::GENERATOR * nonce).unwrap();
    let binding = draft.bind_server_nonce(&context, rs).unwrap();
    let partial = server_contribution(&binding, f.server, nonce);
    let tx = draft.finish(&context, rs, partial).unwrap();
    let destination_point = point_bytes(
        even(ProjectivePoint::GENERATOR * scalar(&f.payout).unwrap())
            .unwrap()
            .0,
    )
    .unwrap();
    let session_point = point_bytes(
        even(ProjectivePoint::GENERATOR * f.session_secret)
            .unwrap()
            .0,
    )
    .unwrap();
    json!({
        "fixture_version": 1, "source": "synthetic test keys and coins only; never for funds",
        "parities": parities,
        "statement": binding.encode().unwrap(), "binding_digest": binding.digest().unwrap(),
        "user": f.user, "alpha": record["alpha"], "beta": record["beta"],
        "funding_salt": hex::decode(&backing.funding_salt).unwrap(), "backup_salt": record["backup_salt"], "nonce_salt": record["nonce_salt"],
        "txid": Txid::from_str(&backing.txid).unwrap().to_byte_array(), "vout": backing.vout, "amount": backing.amount, "fee": fee,
        "destination": destination_point.to_vec(), "delay": delay, "session_auth_point": session_point.to_vec(),
        "partial": partial, "signature": tx.input[0].witness.iter().next().unwrap().to_vec(),
        "expected_message": sighash(&tx, backing.amount, backing.key().unwrap()).unwrap(),
        "input_output_key": backing.key().unwrap(), "signed_activation": signed_activation, "signed_recovery": hex::encode(serialize(&tx)),
    })
    // No server secret, server nonce scalar, payout secret, or parent key is
    // exported. Only receiver witnesses and actual public native evidence.
}

pub(super) fn parity_fixtures() -> Vec<serde_json::Value> {
    let server = Scalar::from(23u64);
    let mut shares = std::collections::BTreeMap::new();
    for candidate in 1u64..128 {
        let user = Scalar::from(candidate);
        let raw = ProjectivePoint::GENERATOR * (server + user);
        let internal = even(raw).unwrap().0;
        let tweak = scalar(&tagged_hash(
            "TapTweak",
            &[&point_bytes(internal).unwrap()[..32]],
        ))
        .unwrap();
        let output = internal + ProjectivePoint::GENERATOR * tweak;
        let key = (
            point_bytes(raw).unwrap()[63] & 1 == 1,
            point_bytes(output).unwrap()[63] & 1 == 1,
        );
        shares.entry(key).or_insert(user);
        if shares.len() == 4 {
            break;
        }
    }
    assert_eq!(shares.len(), 4, "synthetic internal/output parity coverage");
    let mut cases = Vec::new();
    for ((internal, output), user) in shares {
        for nonce in [false, true] {
            let value = native_fixture_value(fixture_with_shares(server, user), Some(nonce));
            assert_eq!(value["parities"], json!([internal, output, nonce]));
            cases.push(value);
        }
    }
    cases
}
