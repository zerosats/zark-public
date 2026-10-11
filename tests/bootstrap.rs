//! Synthetic joint-parent bootstrap; never accesses a node or real wallet.
use anyhow::{Context, Result};
use bitcoin::{OutPoint, Txid, hashes::Hash};
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
};
use zark_protocol::{
    bootstrap::BootstrapBinding,
    handoff::{TransferContext, origin_previous_state},
    point_bytes, random32, scalar,
};
use zark_wallet::bootstrap::{BootstrapDraft, BootstrapParameters};
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("zark-bootstrap-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn parameters() -> Result<BootstrapParameters> {
    Ok(BootstrapParameters {
        context: TransferContext {
            start_revision: 0,
            scope: zark_protocol::handoff::OperationScope::Single,
            deployment: [23; 32],
            coin: [27; 32],
            previous_state: origin_previous_state(&[23; 32], &[27; 32])?,
            operation: [31; 32],
            recipient_claim: [39; 32],
            session_auth: SigningKey::from_bytes(&[71; 32])?
                .verifying_key()
                .to_bytes()
                .into(),
        },
        parent: OutPoint::new(Txid::from_byte_array([17; 32]), 1),
        amount: 100_000,
        fee: 1000,
        parent_server: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(41u64))?,
        active_server: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(41u64))?,
    })
}
fn secret(n: u64) -> [u8; 32] {
    Scalar::from(n).to_bytes().into()
}
fn owner_secret() -> [u8; 32] {
    SigningKey::from_bytes(&[37; 32]).unwrap().to_bytes().into()
}

#[test]
fn joint_activation_is_fixed_before_nonce_and_completes_after_restart() -> Result<()> {
    let h = Home::new();
    let p = parameters()?;
    let ctx = p.context.clone();
    let mut draft = BootstrapDraft::create(
        &h.0.join("owner"),
        p,
        &secret(7),
        &secret(7),
        &owner_secret(),
    )?;
    let commitments = draft.commitments()?;
    let (parent, active, unsigned) = draft.local_inputs()?;
    assert_eq!(unsigned.input[0].sequence, bitcoin::Sequence::MAX);
    assert_eq!(unsigned.lock_time.to_consensus_u32(), 0);
    assert_eq!(unsigned.output.len(), 1);
    assert_eq!(active.amount, 99_000);
    assert_eq!(parent.amount, 100_000);
    assert_eq!(active.txid, unsigned.compute_txid().to_string());
    drop(draft);
    draft = BootstrapDraft::open(&h.0.join("owner"), &ctx)?;
    assert_eq!(draft.commitments()?, commitments);
    let nonce = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(47u64))?;
    let b = draft.bind_nonce(&ctx, nonce)?;
    assert_eq!(
        BootstrapBinding::decode(&b.encode()?)?
            .public_inputs()?
            .len(),
        621
    );
    assert!(
        draft
            .bind_nonce(
                &ctx,
                point_bytes(ProjectivePoint::GENERATOR * Scalar::from(53u64))?
            )
            .is_err()
    );
    draft.write_authorization_witness(&h.0.join("authorization.json"))?;
    let partial = (Scalar::from(47u64) + scalar(&b.blinded_challenge)? * Scalar::from(41u64))
        .to_bytes()
        .into();
    drop(draft);
    draft = BootstrapDraft::open(&h.0.join("owner"), &ctx)?;
    let complete = draft.finish(&ctx, nonce, partial)?;
    assert_eq!(complete.compute_txid(), unsigned.compute_txid());
    assert_eq!(complete.input[0].witness.len(), 1);
    drop(draft);
    let mut draft = BootstrapDraft::open(&h.0.join("owner"), &ctx)?;
    assert_eq!(draft.completed_activation()?, complete);
    assert_eq!(draft.finish(&ctx, nonce, partial)?, complete);
    let mut wrong = partial;
    wrong[31] ^= 1;
    assert!(draft.finish(&ctx, nonce, wrong).is_err());
    assert_eq!(
        fs::metadata(h.0.join("authorization.json"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    Ok(())
}

#[test]
fn bootstrap_rejects_invalid_context_shares_and_tampered_frozen_record() -> Result<()> {
    let h = Home::new();
    let mut p = parameters()?;
    p.context.previous_state = [9; 32];
    assert!(
        BootstrapDraft::create(
            &h.0.join("wrong"),
            p,
            &secret(7),
            &secret(11),
            &owner_secret()
        )
        .is_err()
    );
    let mut p = parameters()?;
    p.active_server = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(43u64))?;
    assert!(
        BootstrapDraft::create(
            &h.0.join("wrong"),
            p,
            &secret(7),
            &secret(11),
            &owner_secret()
        )
        .is_err()
    );
    assert!(
        BootstrapDraft::create(
            &h.0.join("wrong"),
            parameters()?,
            &[0; 32],
            &secret(11),
            &owner_secret()
        )
        .is_err()
    );
    let ctx = parameters()?.context;
    let mut d = BootstrapDraft::create(
        &h.0.join("owner"),
        parameters()?,
        &secret(7),
        &secret(7),
        &owner_secret(),
    )?;
    let nonce = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(47u64))?;
    let b = d.bind_nonce(&ctx, nonce)?;
    let partial = (Scalar::from(47u64) + scalar(&b.blinded_challenge)? * Scalar::from(41u64))
        .to_bytes()
        .into();
    d.finish(&ctx, nonce, partial)?;
    drop(d);
    let file = h.0.join("owner/bootstrap-draft.json");
    let original = fs::read(&file)?;
    for (field, value) in [
        ("fee", json!(999)),
        ("vout", json!(0)),
        ("active_salt", json!(vec![3; 32])),
    ] {
        let mut record: Value = serde_json::from_slice(&original)?;
        record[field] = value;
        fs::write(&file, serde_json::to_vec(&record)?)?;
        assert!(BootstrapDraft::open(&h.0.join("owner"), &ctx).is_err());
    }
    Ok(())
}

#[test]
#[ignore = "exports synthetic bootstrap witnesses only; set a fresh ZARK_BOOTSTRAP_FIXTURE_OUT"]
fn export_joint_parent_bootstrap_authorization() -> Result<()> {
    let out = PathBuf::from(
        std::env::var("ZARK_BOOTSTRAP_FIXTURE_OUT").context("set fresh fixture output")?,
    );
    fs::DirBuilder::new().mode(0o700).create(&out)?;
    let p = parameters()?;
    let ctx = p.context.clone();
    let mut draft = BootstrapDraft::create(
        &out.join("owner"),
        p,
        &secret(7),
        &secret(7),
        &owner_secret(),
    )?;
    let nonce = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(47u64))?;
    let b = draft.bind_nonce(&ctx, nonce)?;
    let path = out.join("authorization.json");
    draft.write_authorization_witness(&path)?;
    let mut v: Value = serde_json::from_slice(&fs::read(&path)?)?;
    v["source"] = json!("synthetic test keys and coins only; never for funds");
    v["fixture_version"] = json!(1);
    v["host_release_verified"] = json!(false);
    v["initial_recovery_complete"] = json!(false);
    fs::write(&path, serde_json::to_vec(&v)?)?;
    // Deliberately do not release a parent partial in an authorization fixture.
    assert_eq!(b.public_inputs()?.len(), 621);
    println!("Synthetic joint-parent authorization: {}", path.display());
    Ok(())
}
