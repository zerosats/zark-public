//! Native persistence cut-point tests only. The synthetic certificate proof
//! bytes below are never passed to a verifier and confer no ownership authority.
//! The parent activation and final exit signatures are actual BIP340 signatures.
use super::*;
use crate::{
    bitcoin::{attach_signature, sighash},
    signing::{Blinding, FundingKey},
};
use bitcoin::{OutPoint, Txid, hashes::Hash};
use k256::{ProjectivePoint, Scalar};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    sync::atomic::{AtomicUsize, Ordering},
};
use zark_protocol::proof::PROOF_BYTES;
use zark_protocol::{
    handoff::{
        FundingOpening, RecoverySchedule, ServerShareOpening, capability_commitment,
        policy_commitment,
    },
    point_bytes, scalar,
};

struct Home(PathBuf);
impl Home {
    fn new() -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("zark-exit-journal-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Unavailable(AtomicUsize);
impl SignerClient for Unavailable {
    fn request(&self, _: &Request) -> Result<Value> {
        self.0.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("synthetic signer unavailable")
    }
}

fn saved_cut_point(home: &Home, complete_native: bool) -> Result<LineagePolicy> {
    let directory = home.0.join("operation");
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let server = Scalar::from(23u64);
    let user = Scalar::from(7u64);
    let secret: Digest = SigningKey::from_bytes(&[5; 32])?.to_bytes().into();
    let server_salt = [6; 32];
    let key = FundingKey::new(ProjectivePoint::GENERATOR * server, user)?;
    let parent_server = server;
    let parent_key = FundingKey::new(ProjectivePoint::GENERATOR * parent_server, user)?;
    let activation_input = Input {
        deployment: hex::encode([9; 32]),
        id: hex::encode([8; 32]),
        funding_salt: hex::encode([11; 32]),
        internal_point: hex::encode(point_bytes(parent_key.internal)?),
        txid: Txid::from_byte_array([12; 32]).to_string(),
        vout: 0,
        amount: 100_000,
    };
    let mut activation = crate::bitcoin::activation(
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
    let prior_signing = zark_protocol::handoff::SigningBinding {
        context: TransferContext {
            deployment: [9; 32],
            coin: [8; 32],
            previous_state: [18; 32],
            operation: [20; 32],
            recipient_claim: [21; 32],
            session_auth: SigningKey::from_bytes(&[22; 32])?
                .verifying_key()
                .to_bytes()
                .into(),
            start_revision: 1,
            scope: zark_protocol::handoff::OperationScope::Single,
        },
        funding,
        refresh_commitment: [23; 32],
        previous_capability: [24; 32],
        next_capability: capability_commitment(&[9; 32], &[8; 32], &secret)?,
        recovery: [3; 32],
        nonce_commitment: [25; 32],
        draft_server: server_point,
        server_nonce: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(59u64))?,
        blinded_challenge: Scalar::from(61u64).to_bytes().into(),
    };
    let prior_partial: Digest = (Scalar::from(59u64) + Scalar::from(61u64) * server)
        .to_bytes()
        .into();
    let state = StateOpening {
        deployment: [9; 32],
        coin: [8; 32],
        funding,
        capability: capability_commitment(&[9; 32], &[8; 32], &secret)?,
        recovery: [3; 32],
        server_share: ServerShareOpening {
            deployment: [9; 32],
            coin: [8; 32],
            server: server_point,
            salt: server_salt,
        }
        .commitment()?,
        policy: policy_commitment(schedule)?,
        issuance: zark_protocol::handoff::issuance_commitment(
            &prior_signing.digest()?,
            &prior_partial,
        )?,
    };
    let session = SigningKey::from_bytes(&[13; 32])?;
    let context = TransferContext {
        deployment: [9; 32],
        coin: [8; 32],
        previous_state: state.commitment()?,
        operation: [2; 32],
        recipient_claim: exit::intent(&[9; 32], &[8; 32], &[2; 32])?,
        session_auth: session.verifying_key().to_bytes().into(),
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
    };
    let destination = SigningKey::from_bytes(&[14; 32])?
        .verifying_key()
        .to_bytes()
        .into();
    let policy = LineagePolicy {
        deployment: [9; 32],
        schedule,
        origin_key: SigningKey::from_bytes(&[15; 32])?
            .verifying_key()
            .to_bytes()
            .into(),
        role_hashes: std::array::from_fn(|i| Scalar::from(i as u64 + 1).to_bytes().into()),
    };
    let mut draft = ExitDraft::create(
        &directory.join("draft"),
        ExitParameters {
            context: context.clone(),
            backing: backing.clone(),
            activation_input: activation_input.clone(),
            activation: activation.clone(),
            server: server_point,
            current_recovery: state.recovery,
            current_issuance: state.issuance,
            server_salt,
            schedule,
            destination,
            fee: 777,
        },
        &user.to_bytes().into(),
        &secret,
    )?;
    let (f, e, b) = draft.commitments()?;
    let preparation = Request::sign(
        context.clone(),
        Command::ExitPrepare {
            funding: f,
            server_share: state.server_share,
            capability: state.capability,
            exit: e,
            blinding: b,
            owner_authorization: draft.owner_authorization()?,
        },
        &session,
    )?;
    let nonce = Scalar::from(71u64);
    let nonce_point = point_bytes(ProjectivePoint::GENERATOR * nonce)?;
    let binding = draft.bind_nonce(&context, nonce_point)?;
    let partial = (nonce + scalar(&binding.blinded_challenge)? * server)
        .to_bytes()
        .into();
    let issuance = IssuanceBinding {
        signing: binding,
        policy: state.policy,
        origin_key: policy.origin_key,
        role_hashes: policy.role_hashes,
    };
    let request = Request::sign(
        context.clone(),
        Command::ExitIssue {
            predecessor: PredecessorKind::Transfer,
            statement: issuance.encode()?,
            proof: vec![0; PROOF_BYTES],
        },
        &session,
    )?;
    if complete_native {
        draft.finish(&context, nonce_point, partial)?;
    }
    drop(draft);
    let owner_session = SigningKey::from_bytes(&[16; 32])?;
    let mut head_context = context.clone();
    head_context.operation = [17; 32];
    head_context.session_auth = owner_session.verifying_key().to_bytes().into();
    let record = Record {
        version: 3,
        head_context,
        head_session: owner_session.to_bytes().into(),
        context,
        session: session.to_bytes().into(),
        backing,
        activation_input,
        activation: hex::encode(serialize(&activation)),
        certificate: hex::encode(
            &*OwnerCertificate::TransferIssued {
                authorization: IssuanceBinding {
                    signing: prior_signing,
                    policy: state.policy,
                    origin_key: policy.origin_key,
                    role_hashes: policy.role_hashes,
                }
                .encode()?,
                proof: vec![0; PROOF_BYTES],
                partial: prior_partial,
                server_salt,
            }
            .encode_private()?,
        ),
        predecessor: PredecessorKind::Transfer,
        capability: state.capability,
        server_share: state.server_share,
        destination,
        fee: 777,
        prepare: Some(hex::encode(&*preparation.encode()?)),
        issue: Some(hex::encode(&*request.encode()?)),
        terminal: false,
    };
    // Construct a storage cut point, not an accepted cryptographic certificate.
    let operation = ExitOperation {
        directory: directory.clone(),
        record,
        policy: policy.clone(),
        _lock: lock(&directory)?,
    };
    operation.persist()?;
    drop(operation);
    Ok(policy)
}

#[test]
fn accepted_head_uses_owner_session_until_exit_prepare_admits_new_session() -> Result<()> {
    let home = Home::new()?;
    let policy = saved_cut_point(&home, false)?;
    let operation = ExitOperation::open(&home.0.join("operation"), &policy)?;
    let accepted = operation.head_probe(Phase::Accepted)?;
    let draft = operation.head_probe(Phase::Draft)?;
    assert_eq!(accepted.request().context, operation.record.head_context);
    assert_eq!(draft.request().context, operation.record.context);
    assert_ne!(
        accepted.request().context.session_auth,
        draft.request().context.session_auth
    );
    Ok(())
}

#[test]
fn fresh_exit_preparation_releases_draft_lock_before_journal_validation() -> Result<()> {
    let home = Home::new()?;
    let policy = saved_cut_point(&home, false)?;
    let directory = home.0.join("operation");
    let mut operation = ExitOperation::open(&directory, &policy)?;
    // Use the native storage cut point without conferring proof authority.
    // Removing the frozen requests exercises the same first-preparation path
    // called after production certificate and live-head verification.
    operation.record.prepare = None;
    operation.record.issue = None;
    operation.persist()?;
    let request = operation.freeze_preparation()?;
    let exact = request.encode()?.to_vec();
    assert_eq!(operation.freeze_preparation()?.encode()?.as_slice(), exact);
    // Reopening validates the persisted owner signature and reacquires the
    // draft lock. A retry must keep the randomized owner signature unchanged.
    drop(operation);
    let mut reopened = ExitOperation::open(&directory, &policy)?;
    assert_eq!(reopened.freeze_preparation()?.encode()?.as_slice(), exact);
    assert!(matches!(request.command, Command::ExitPrepare { .. }));
    Ok(())
}

#[test]
fn native_completion_survives_outer_terminal_write_crash_without_signer_or_prover() -> Result<()> {
    let home = Home::new()?;
    let policy = saved_cut_point(&home, true)?;
    let directory = home.0.join("operation");
    let mut operation = ExitOperation::open(&directory, &policy)?;
    assert!(!operation.is_terminal()?);
    let offline = Unavailable(AtomicUsize::new(0));
    let transaction = operation.retrieve(&offline)?;
    assert!(operation.is_terminal()?);
    assert_eq!(offline.0.load(Ordering::SeqCst), 0);
    assert_eq!(transaction.output[0].value.to_sat(), 99_223);
    assert_eq!(transaction.input[0].witness.len(), 1);
    drop(operation);
    let mut reopened = ExitOperation::open(&directory, &policy)?;
    assert_eq!(reopened.retrieve(&offline)?, transaction);
    assert_eq!(offline.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn outer_terminal_marker_and_noncanonical_session_cannot_fake_native_completion() -> Result<()> {
    let home = Home::new()?;
    let policy = saved_cut_point(&home, false)?;
    let directory = home.0.join("operation");
    let path = directory.join("exit-operation.json");
    let original = fs::read(&path)?;
    let mut record: Value = serde_json::from_slice(&original)?;
    record["terminal"] = true.into();
    fs::write(&path, serde_json::to_vec(&record)?)?;
    assert!(ExitOperation::open(&directory, &policy).is_err());
    record = serde_json::from_slice(&original)?;
    let normalized: Digest = serde_json::from_value(record["session"].clone())?;
    let negated: Digest = (-scalar(&normalized)?).to_bytes().into();
    record["session"] = serde_json::json!(negated);
    fs::write(&path, serde_json::to_vec(&record)?)?;
    assert!(ExitOperation::open(&directory, &policy).is_err());
    fs::write(&path, original)?;
    let mut operation = ExitOperation::open(&directory, &policy)?;
    let offline = Unavailable(AtomicUsize::new(0));
    assert!(operation.retrieve(&offline).is_err());
    assert_eq!(offline.0.load(Ordering::SeqCst), 1);
    assert!(!operation.is_terminal()?);
    Ok(())
}
