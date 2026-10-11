//! Synthetic native exit fixtures; no node or existing wallet is accessed.
use anyhow::{Context, Result, ensure};
use bitcoin::{OutPoint, Txid, consensus::deserialize, hashes::Hash};
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zark_protocol::{
    exit,
    handoff::{
        FundingOpening, RecoverySchedule, ServerShareOpening, SigningBinding, StateOpening,
        TransferContext, capability_commitment, issuance_commitment, policy_commitment,
    },
    lineage::{LineageBinding, LineagePolicy},
    point, point_bytes, random_scalar, random32, scalar,
};
use zark_wallet::{
    bitcoin::{attach_signature, cooperative_exit, sighash},
    exit::{ExitDraft, ExitParameters},
    signing::{Blinding, FundingKey},
    types::Input,
};
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("zark-exit-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

type NativeExitFixture = (ExitParameters, [u8; 32], [u8; 32], Scalar, Scalar);
fn parameters() -> Result<NativeExitFixture> {
    parameters_with_shared_authority(true)
}
fn parameters_with_shared_authority(shared: bool) -> Result<NativeExitFixture> {
    let server = Scalar::from(23u64);
    let user = Scalar::from(7u64);
    let capability = SigningKey::from_bytes(&[5; 32])?.to_bytes().into();
    let server_salt = [6; 32];
    let key = FundingKey::new(ProjectivePoint::GENERATOR * server, user)?;
    let parent_server = if shared { server } else { Scalar::from(21u64) };
    let parent_key = FundingKey::new(
        ProjectivePoint::GENERATOR * parent_server,
        if shared { user } else { Scalar::from(31u64) },
    )?;
    let activation_input = Input {
        deployment: hex::encode([9; 32]),
        id: hex::encode([8; 32]),
        funding_salt: hex::encode([11; 32]),
        internal_point: hex::encode(point_bytes(parent_key.internal)?),
        txid: Txid::from_byte_array([12; 32]).to_string(),
        vout: 0,
        amount: 100_000,
    };
    let mut activation = zark_wallet::bitcoin::activation(
        OutPoint::new(Txid::from_byte_array([12; 32]), 0),
        100_000,
        &[(99_000, key.xonly()?)],
        0,
    )?;
    let blind = Blinding::default();
    let parent_nonce = Scalar::from(17u64);
    let s = ProjectivePoint::GENERATOR * parent_server;
    let rs = ProjectivePoint::GENERATOR * parent_nonce;
    let session = blind.bind(
        &parent_key,
        s,
        rs,
        sighash(&activation, 100_000, parent_key.xonly()?)?,
    )?;
    let signature = blind.finish(
        &parent_key,
        &session,
        s,
        rs,
        parent_nonce + session.challenge * parent_server,
    )?;
    attach_signature(&mut activation, 100_000, parent_key.xonly()?, &signature)?;
    let backing = Input {
        deployment: hex::encode([9; 32]),
        id: hex::encode([8; 32]),
        funding_salt: hex::encode([19; 32]),
        internal_point: hex::encode(point_bytes(key.internal)?),
        txid: activation.compute_txid().to_string(),
        vout: 0,
        amount: 99_000,
    };
    let funding = FundingOpening {
        deployment: [9; 32],
        coin: [8; 32],
        salt: [19; 32],
        txid: activation.compute_txid().to_byte_array(),
        vout: 0,
        amount: 99_000,
        internal_point: point_bytes(key.internal)?,
    }
    .commitment()?;
    let schedule = RecoverySchedule {
        initial: 480,
        gap: 60,
        margin: 6,
    };
    let server_point = point_bytes(ProjectivePoint::GENERATOR * server)?;
    let state = StateOpening {
        deployment: [9; 32],
        coin: [8; 32],
        funding,
        capability: capability_commitment(&[9; 32], &[8; 32], &capability)?,
        recovery: [3; 32],
        server_share: ServerShareOpening {
            deployment: [9; 32],
            coin: [8; 32],
            server: server_point,
            salt: server_salt,
        }
        .commitment()?,
        policy: policy_commitment(schedule)?,
        issuance: [4; 32],
    }
    .commitment()?;
    let context = TransferContext {
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: [9; 32],
        coin: [8; 32],
        previous_state: state,
        operation: [2; 32],
        recipient_claim: exit::intent(&[9; 32], &[8; 32], &[2; 32])?,
        session_auth: SigningKey::from_bytes(&[13; 32])?
            .verifying_key()
            .to_bytes()
            .into(),
    };
    Ok((
        ExitParameters {
            context,
            backing,
            activation_input,
            activation,
            server: server_point,
            current_recovery: [3; 32],
            current_issuance: [4; 32],
            server_salt,
            schedule,
            destination: SigningKey::from_bytes(&[14; 32])?
                .verifying_key()
                .to_bytes()
                .into(),
            fee: 777,
        },
        user.to_bytes().into(),
        capability,
        server,
        Scalar::from(71u64),
    ))
}

#[test]
fn direct_exit_rejects_a_valid_activation_with_a_different_deposit_key() -> Result<()> {
    let home = Home::new();
    let (p, user, cap, _, _) = parameters_with_shared_authority(false)?;
    let error = ExitDraft::create(&home.0.join("different-deposit-authority"), p, &user, &cap)
        .err()
        .context("different deposit key must be rejected")?;
    assert!(
        error
            .to_string()
            .contains("shared deposit and recovery authority")
    );
    Ok(())
}

#[test]
fn exit_completes_actual_signature_and_replays_exact_response_after_restart() -> Result<()> {
    let home = Home::new();
    let (p, user, cap, server, nonce) = parameters()?;
    let context = p.context.clone();
    let destination = p.destination;
    let mut draft = ExitDraft::create(&home.0.join("draft"), p, &user, &cap)?;
    let commitments = draft.commitments()?;
    drop(draft);
    draft = ExitDraft::open(&home.0.join("draft"), &context)?;
    assert_eq!(draft.commitments()?, commitments);
    let rs = point_bytes(ProjectivePoint::GENERATOR * nonce)?;
    let binding = draft.bind_nonce(&context, rs)?;
    assert!(
        draft
            .bind_nonce(
                &context,
                point_bytes(ProjectivePoint::GENERATOR * (nonce + Scalar::ONE))?
            )
            .is_err()
    );
    let partial: [u8; 32] = (nonce + scalar(&binding.blinded_challenge)? * server)
        .to_bytes()
        .into();
    drop(draft);
    draft = ExitDraft::open(&home.0.join("draft"), &context)?;
    let tx = draft.finish(&context, rs, partial)?;
    assert_eq!(tx.input[0].sequence, bitcoin::Sequence::MAX);
    assert_eq!(tx.lock_time.to_consensus_u32(), 0);
    assert_eq!(tx.output[0].value.to_sat(), 99_223);
    assert_eq!(
        tx.input[0].previous_output,
        OutPoint::new(Txid::from_byte_array([12; 32]), 0)
    );
    assert_eq!(
        tx.output[0].script_pubkey,
        zark_wallet::bitcoin::p2tr(&destination)
    );
    drop(draft);
    draft = ExitDraft::open(&home.0.join("draft"), &context)?;
    assert_eq!(draft.completed_transaction()?, tx);
    assert_eq!(draft.finish(&context, rs, partial)?, tx);
    let mut wrong = partial;
    wrong[31] ^= 1;
    assert!(draft.finish(&context, rs, wrong).is_err());
    assert_eq!(
        fs::metadata(home.0.join("draft/cooperative-exit.json"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    Ok(())
}

#[test]
fn exit_record_rejects_changed_state_capability_and_context() -> Result<()> {
    let home = Home::new();
    let (p, user, cap, _, nonce) = parameters()?;
    let context = p.context.clone();
    let mut wrong = cap;
    wrong[0] ^= 1;
    assert!(ExitDraft::create(&home.0.join("wrong"), parameters()?.0, &user, &wrong).is_err());
    let mut draft = ExitDraft::create(&home.0.join("draft"), p, &user, &cap)?;
    let rs = point_bytes(ProjectivePoint::GENERATOR * nonce)?;
    draft.bind_nonce(&context, rs)?;
    drop(draft);
    let path = home.0.join("draft/cooperative-exit.json");
    let original = fs::read(&path)?;
    for field in [
        "current_recovery",
        "current_issuance",
        "server_salt",
        "capability",
        "nonce_salt",
        "exit_salt",
    ] {
        let mut record: Value = serde_json::from_slice(&original)?;
        let first = record[field][0].as_u64().expect("byte field");
        record[field][0] = json!(first ^ 1);
        fs::write(&path, serde_json::to_vec(&record)?)?;
        assert!(ExitDraft::open(&home.0.join("draft"), &context).is_err());
    }
    let mut record: Value = serde_json::from_slice(&original)?;
    record["state"]["phase"] = json!("unknown");
    fs::write(&path, serde_json::to_vec(&record)?)?;
    assert!(ExitDraft::open(&home.0.join("draft"), &context).is_err());
    fs::write(path, original)?;
    let mut wrong_context = context.clone();
    wrong_context.operation[0] ^= 1;
    assert!(ExitDraft::open(&home.0.join("draft"), &wrong_context).is_err());
    Ok(())
}

fn bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::from_value(value.clone())?)
}
fn digest(value: &Value) -> Result<[u8; 32]> {
    bytes(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("fixture digest"))
}
fn json_file(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

#[test]
#[ignore = "exports only synthetic current-Carol exit authorization; requires completed lineage fixtures"]
fn export_current_carol_exit_authorization() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let base = root.join("work/private-lineage-fixture");
    let common = json_file(&base.join("common.json"))?;
    let current = json_file(&base.join("carol/recovery.json"))?;
    let old = SigningBinding::decode(&bytes(&current["statement"])?)?;
    let manifest = json_file(&root.join("work/private-lineage/manifest.json"))?;
    let mut hashes = [[0; 32]; zark_protocol::lineage::ROLE_COUNT];
    for (i, role) in manifest["roles"]
        .as_array()
        .context("roles")?
        .iter()
        .enumerate()
    {
        hashes[i] = zark_protocol::hex32(
            role["vk_field_hash"]
                .as_str()
                .context("hash")?
                .strip_prefix("0x")
                .context("prefix")?,
        )?;
    }
    let policy = LineagePolicy {
        deployment: old.context.deployment,
        origin_key: digest(&common["origin_key"])?,
        role_hashes: hashes,
        schedule: RecoverySchedule {
            initial: common["schedule"]["initial"]
                .as_u64()
                .context("initial")?
                .try_into()?,
            gap: common["schedule"]["gap"]
                .as_u64()
                .context("gap")?
                .try_into()?,
            margin: common["schedule"]["margin"]
                .as_u64()
                .context("margin")?
                .try_into()?,
        },
    };
    let mut context = old.context.clone();
    context.previous_state = digest(&current["state_commitment"])?;
    context.operation = random32();
    context.session_auth = SigningKey::from_bytes(&random_scalar().to_bytes())?
        .verifying_key()
        .to_bytes()
        .into();
    context.recipient_claim = exit::intent(&context.deployment, &context.coin, &context.operation)?;
    let p = ExitParameters {
        context: context.clone(),
        backing: serde_json::from_value(common["backing"].clone())?,
        activation_input: serde_json::from_value(common["activation_input"].clone())?,
        activation: deserialize(&hex::decode(
            common["activation"].as_str().context("activation")?,
        )?)?,
        server: old.draft_server,
        current_recovery: old.recovery,
        current_issuance: issuance_commitment(&old.digest()?, &digest(&current["partial"])?)?,
        server_salt: digest(&current["server_salt"])?,
        schedule: policy.schedule,
        destination: SigningKey::from_bytes(&random_scalar().to_bytes())?
            .verifying_key()
            .to_bytes()
            .into(),
        fee: 777,
    };
    let out = PathBuf::from(
        std::env::var("ZARK_EXIT_FIXTURE_OUT").context("set fresh ZARK_EXIT_FIXTURE_OUT")?,
    );
    fs::DirBuilder::new().mode(0o700).create(&out)?;
    let mut draft = ExitDraft::create(
        &out.join("draft"),
        p,
        &digest(&current["user"])?,
        &digest(&current["capability"])?,
    )?;
    let rs = point_bytes(ProjectivePoint::GENERATOR * random_scalar())?;
    let binding = draft.bind_nonce(&context, rs)?;
    let path = out.join("authorization.json");
    draft.write_authorization_witness(&path, &policy)?;
    let mut witness = json_file(&path)?;
    witness["source"] = json!("synthetic test keys and coins only; never for funds");
    witness["fixture_version"] = json!(1);
    witness["partial_generated"] = json!(false);
    witness["host_issuance_verified"] = json!(false);
    let server = point(&binding.draft_server)?;
    let nonce = point(&binding.server_nonce)?;
    let key = FundingKey::new(server, scalar(&digest(&witness["user"])?)?)?;
    let blind = Blinding {
        alpha: scalar(&digest(&witness["alpha"])?)?,
        beta: scalar(&digest(&witness["beta"])?)?,
    };
    let destination_bytes = bytes(&witness["destination"])?;
    let destination: [u8; 32] = destination_bytes[..32].try_into()?;
    let amount = witness["deposit_amount"]
        .as_u64()
        .context("deposit amount")?;
    let fee = witness["fee"].as_u64().context("fee")?;
    let mut tx = cooperative_exit(
        OutPoint::new(
            Txid::from_byte_array(digest(&witness["deposit_txid"])?),
            witness["deposit_vout"]
                .as_u64()
                .context("deposit vout")?
                .try_into()?,
        ),
        amount,
        fee,
        destination,
    )?;
    ensure!(
        sighash(&tx, amount, key.xonly()?)? == digest(&witness["expected_message"])?,
        "native exit message mismatch"
    );
    tx.input[0].sequence = bitcoin::Sequence(60);
    witness["bad_sequence_challenge"] = json!(
        &blind
            .bind(&key, server, nonce, sighash(&tx, amount, key.xonly()?)?)?
            .challenge
            .to_bytes()[..]
    );
    tx.input[0].sequence = bitcoin::Sequence::MAX;
    tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
    witness["bad_locktime_challenge"] = json!(
        &blind
            .bind(&key, server, nonce, sighash(&tx, amount, key.xonly()?)?)?
            .challenge
            .to_bytes()[..]
    );
    let public = fs::read(root.join("work/private-lineage/carol-lineage/public_inputs"))?;
    ensure!(public.len() == 388 * 32, "current certificate ABI");
    let mut encoded = Vec::new();
    for field in public.chunks_exact(32) {
        ensure!(field[..31] == [0; 31], "non-byte certificate field");
        encoded.push(field[31]);
    }
    let cert = LineageBinding::decode(&encoded)?;
    ensure!(
        cert.state == context.previous_state,
        "exit current certificate mismatch"
    );
    witness["current"] = json!(encoded);
    fs::write(&path, serde_json::to_vec(&witness)?)?;
    println!(
        "Synthetic current-owner exit authorization: {}",
        path.display()
    );
    Ok(())
}
