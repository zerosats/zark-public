//! Explicit adapter for scripts/check-zark-recovery-regtest.py. Fresh test keys
//! only; never run against an existing wallet/node or a user-selected key file.
use anyhow::{Context, Result, ensure};
use bitcoin::{
    Address, Network, OutPoint, Transaction, Txid,
    consensus::{deserialize, serialize},
};
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};
use zark_protocol::{
    handoff::{RecoveryDelay, RecoverySchedule, TransferContext},
    point_bytes, random_scalar, random32, scalar,
};
use zark_wallet::{
    bitcoin::{attach_signature, backup, p2tr, sighash},
    recovery::{RecoveryDraft, RecoveryParameters},
    recovery_export::PortableRecovery,
    signing::{Blinding, FundingKey},
    types::Input,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Fixture {
    deployment: [u8; 32],
    coin: [u8; 32],
    operation: [u8; 32],
    previous: [u8; 32],
    claim: [u8; 32],
    parent_user: [u8; 32],
    parent_server: [u8; 32],
    user: [u8; 32],
    server: [u8; 32],
    payout: [u8; 32],
    session: [u8; 32],
    nonce: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Funding {
    txid: String,
    vout: u32,
    amount: u64,
    transaction: String,
}

fn secret() -> [u8; 32] {
    random_scalar().to_bytes().into()
}
fn policy() -> RecoverySchedule {
    RecoverySchedule {
        initial: 32,
        gap: 4,
        margin: 1,
    }
}

fn home() -> Result<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("work")
        .canonicalize()?;
    let supplied = PathBuf::from(std::env::var("ZARK_REGTEST_HOME")?);
    let metadata = fs::symlink_metadata(&supplied)?;
    ensure!(
        metadata.is_dir()
            && metadata.permissions().mode() & 0o777 == 0o700
            && metadata.uid() == unsafe { libc::geteuid() },
        "private generated test directory required"
    );
    let path = supplied.canonicalize()?;
    ensure!(
        path.parent() == Some(root.as_path())
            && path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("zark-regtest-"),
        "adapter only accepts a generated regtest directory under this checkout's work"
    );
    let marker: Value = serde_json::from_slice(&read(&path.join("run.json"))?)?;
    ensure!(
        marker["schema"] == "zark-regtest-test-run" && marker["version"] == 1,
        "missing generated test marker"
    );
    Ok(path)
}

fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() },
        "private synthetic file required"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file).take(65_537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65_536, "synthetic adapter file too large");
    Ok(bytes)
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().context("test parent")?)?.sync_all()?;
    Ok(())
}

fn public(path: &Path, value: Value) -> Result<()> {
    write(path, &serde_json::to_vec(&value)?)
}

fn prepare(home: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(home.join("source"))?;
    let f = Fixture {
        deployment: random32(),
        coin: random32(),
        operation: random32(),
        previous: random32(),
        claim: random32(),
        parent_user: secret(),
        parent_server: secret(),
        user: secret(),
        server: secret(),
        payout: secret(),
        session: secret(),
        nonce: secret(),
    };
    let parent = FundingKey::new(
        ProjectivePoint::GENERATOR * scalar(&f.parent_server)?,
        scalar(&f.parent_user)?,
    )?;
    let address = Address::from_script(&p2tr(&parent.xonly()?), Network::Regtest)?;
    write(
        &home.join("source/synthetic-keys.json"),
        &Zeroizing::new(serde_json::to_vec(&f)?),
    )?;
    public(
        &home.join("prepared.json"),
        json!({"deployment":f.deployment,"coin":f.coin,"funding_address":address.to_string(),"amount_sat":100000,"previous_delay":12,"next_delay":8,"margin":1}),
    )
}

/// Simulates the server only in this synthetic adapter. Production APIs do not
/// receive either secret. No old-owner data is used to construct the new draft.
fn sign_test(tx: &mut Transaction, amount: u64, user: Scalar, server: Scalar) -> Result<()> {
    let point = ProjectivePoint::GENERATOR * server;
    let key = FundingKey::new(point, user)?;
    let nonce = random_scalar();
    let rs = ProjectivePoint::GENERATOR * nonce;
    let blind = Blinding::default();
    let session = blind.bind(&key, point, rs, sighash(tx, amount, key.xonly()?)?)?;
    let signature = blind.finish(
        &key,
        &session,
        point,
        rs,
        nonce + session.challenge * server,
    )?;
    attach_signature(tx, amount, key.xonly()?, &signature)
}

fn build(home: &Path) -> Result<()> {
    let f: Fixture = serde_json::from_slice(&read(&home.join("source/synthetic-keys.json"))?)?;
    let funding: Funding = serde_json::from_slice(&read(&home.join("funding.json"))?)?;
    let tx: Transaction = deserialize(&hex::decode(&funding.transaction)?)?;
    ensure!(
        tx.compute_txid().to_string() == funding.txid && funding.amount == 100_000,
        "public funding identity/amount mismatch"
    );
    let parent = FundingKey::new(
        ProjectivePoint::GENERATOR * scalar(&f.parent_server)?,
        scalar(&f.parent_user)?,
    )?;
    let out = tx
        .output
        .get(funding.vout as usize)
        .context("funding output")?;
    ensure!(
        out.value.to_sat() == funding.amount && out.script_pubkey == p2tr(&parent.xonly()?),
        "funding does not pay fresh synthetic parent key"
    );
    let key = FundingKey::new(
        ProjectivePoint::GENERATOR * scalar(&f.server)?,
        scalar(&f.user)?,
    )?;
    let outpoint = OutPoint::new(Txid::from_str(&funding.txid)?, funding.vout);
    let mut activation =
        zark_wallet::bitcoin::activation(outpoint, funding.amount, &[(99_000, key.xonly()?)], 0)?;
    sign_test(
        &mut activation,
        funding.amount,
        scalar(&f.parent_user)?,
        scalar(&f.parent_server)?,
    )?;
    let activation_parent = Input {
        deployment: hex::encode(f.deployment),
        id: hex::encode(random32()),
        funding_salt: hex::encode(random32()),
        internal_point: hex::encode(point_bytes(parent.internal)?),
        txid: funding.txid,
        vout: funding.vout,
        amount: funding.amount,
    };
    let backing = Input {
        deployment: hex::encode(f.deployment),
        id: hex::encode(f.coin),
        funding_salt: hex::encode(random32()),
        internal_point: hex::encode(point_bytes(key.internal)?),
        txid: activation.compute_txid().to_string(),
        vout: 0,
        amount: 99_000,
    };
    let context = TransferContext {
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: f.deployment,
        coin: f.coin,
        previous_state: f.previous,
        operation: f.operation,
        recipient_claim: f.claim,
        session_auth: SigningKey::from_bytes(&f.session)?
            .verifying_key()
            .to_bytes()
            .into(),
    };
    let parameters = RecoveryParameters {
        context: context.clone(),
        backing,
        activation_input: activation_parent,
        activation: activation.clone(),
        draft_server: point_bytes(ProjectivePoint::GENERATOR * scalar(&f.server)?)?,
        refresh_commitment: random32(),
        previous_capability: random32(),
        next_capability: random32(),
        schedule: policy(),
        previous_delay: RecoveryDelay::from_sequence(12)?,
        next_delay: RecoveryDelay::from_sequence(8)?,
        fee: 1000,
    };
    let mut draft =
        RecoveryDraft::create(&home.join("source/draft"), parameters, &f.user, &f.payout)?;
    let nonce = scalar(&f.nonce)?;
    let rs = point_bytes(ProjectivePoint::GENERATOR * nonce)?;
    let binding = draft.bind_server_nonce(&context, rs)?;
    let partial = (nonce + scalar(&binding.blinded_challenge)? * scalar(&f.server)?)
        .to_bytes()
        .into();
    let recovery = draft.finish(&context, rs, partial)?;
    draft.export_portable(&home.join("source/recovery.json"))?;
    // A test-only comparator with the predecessor delay. This is not passed to
    // the recipient export; it solely tests Core's relative-delay evaluation.
    let payout: [u8; 32] = SigningKey::from_bytes(&f.payout)?
        .verifying_key()
        .to_bytes()
        .into();
    let mut old = backup(
        OutPoint::new(activation.compute_txid(), 0),
        99_000,
        1000,
        payout,
        12,
    )?;
    sign_test(&mut old, 99_000, scalar(&f.user)?, scalar(&f.server)?)?;
    public(
        &home.join("transactions.json"),
        json!({"activation":hex::encode(serialize(&activation)),"recovery":hex::encode(serialize(&recovery)),"old_delay_comparator":hex::encode(serialize(&old)),"activation_txid":activation.compute_txid().to_string(),"recovery_txid":recovery.compute_txid().to_string()}),
    )
}

fn payout(home: &Path) -> Result<()> {
    ensure!(
        !home.join("source").exists(),
        "original source must be unavailable for portable test"
    );
    let prepared: Value = serde_json::from_slice(&read(&home.join("prepared.json"))?)?;
    let deployment = serde_json::from_value(prepared["deployment"].clone())?;
    let coin = serde_json::from_value(prepared["coin"].clone())?;
    let portable =
        PortableRecovery::read(&home.join("portable/recovery.json"), &deployment, &coin)?;
    let recipient = SigningKey::from_bytes(&secret())?;
    let destination: [u8; 32] = recipient.verifying_key().to_bytes().into();
    let spend = portable.sign_payout_spend(destination, 1000)?;
    // This final test destination key is fresh and funded only on regtest; keep
    // it private rather than displaying it in audit/CLI output.
    write(
        &home.join("portable/test-payout-key.json"),
        &Zeroizing::new(serde_json::to_vec(&<[u8; 32]>::from(recipient.to_bytes()))?),
    )?;
    public(
        &home.join("payout.json"),
        json!({"transaction":hex::encode(serialize(&spend)),"txid":spend.compute_txid().to_string(),"destination_output_key":hex::encode(destination),"amount_sat":97000}),
    )
}

fn windows(home: &Path) -> Result<()> {
    let observation: Value = serde_json::from_slice(&read(&home.join("observations.json"))?)?;
    let height: u32 = observation["activation_height"]
        .as_u64()
        .context("activation height")?
        .try_into()?;
    let mut results = Vec::new();
    for observation in observation["tips"].as_array().context("observed tips")? {
        let tip: u32 = observation["height"]
            .as_u64()
            .context("observed height")?
            .try_into()?;
        let result = policy().confirmed_transfer_window(
            RecoveryDelay::from_sequence(12)?,
            RecoveryDelay::from_sequence(8)?,
            height,
            tip,
            1,
        );
        results.push(match result {
            Ok(window) => json!({"label":observation["label"],"tip":tip,"accepted":true,"previous_maturity":window.previous_maturity,"next_maturity":window.next_maturity,"earliest_next_confirmation":window.earliest_next_confirmation,"remaining_margin":window.remaining_margin}),
            Err(_) => json!({"label":observation["label"],"tip":tip,"accepted":false}),
        });
    }
    let wrong_decrement_rejected = policy()
        .confirmed_transfer_window(
            RecoveryDelay::from_sequence(12)?,
            RecoveryDelay::from_sequence(7)?,
            height,
            height,
            1,
        )
        .is_err();
    let time_flag_rejected = RecoveryDelay::from_sequence((1 << 22) | 8).is_err();
    public(
        &home.join("windows.json"),
        json!({"observations":results,"wrong_decrement_rejected":wrong_decrement_rejected,"time_flag_rejected":time_flag_rejected}),
    )
}

#[test]
#[ignore = "explicit isolated Bitcoin Core regtest adapter; use scripts/check-zark-recovery-regtest.py"]
fn zark_regtest_adapter() -> Result<()> {
    let home = home()?;
    match std::env::var("ZARK_REGTEST_PHASE")?.as_str() {
        "prepare" => prepare(&home),
        "build" => build(&home),
        "payout" => payout(&home),
        "windows" => windows(&home),
        _ => anyhow::bail!("unknown isolated regtest adapter phase"),
    }
}
