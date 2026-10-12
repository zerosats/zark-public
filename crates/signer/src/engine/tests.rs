//! These tests exercise the durable host using a deliberately test-only relation
//! oracle. They are NOT evidence that a ZK witness, lineage, or Bitcoin spend is
//! valid. Production Engine::open accepts only the external pinned verifier.
mod batch;
mod batch_qualification;
mod harness;
use batch::BatchCase;
use harness::Harness;
mod bootstrap;
mod browser;
mod cancellation;
mod capacity;
mod exit;
mod plan_c;
mod verification;
use super::*;
use std::collections::BTreeMap;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use zark_protocol::owner_auth::{
    OwnerAuthorization, OwnerAuthorizationPayload, public_capability_commitment,
};
use zark_protocol::{
    batch::{Manifest as BatchManifest, Member as BatchMember},
    handoff::{RecoverySchedule, TransferIntent},
};
use zark_protocol::{head::HeadQuery, proof::PROOF_BYTES, session::sign_request};

pub(super) struct TestTip(Mutex<Digest>);
impl TestTip {
    fn new() -> Self {
        Self(Mutex::new([42; 32]))
    }

    fn set(&self, tip: Digest) {
        *self.0.lock().unwrap() = tip;
    }
}
impl BatchTip for TestTip {
    fn current_tip(&self) -> Result<Digest> {
        Ok(*self.0.lock().unwrap())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Fault {
    AfterVerification,
    BeforeCommit,
    AfterCommit,
    AfterCheckpoint,
}
impl Engine {
    pub(super) fn trip(&self, point: Fault) -> Result<()> {
        let mut fault = self.fault.lock().unwrap();
        if *fault == Some(point) {
            *fault = None;
            anyhow::bail!("injected crash at {point:?}");
        }
        Ok(())
    }
}
type VerificationHook = Box<dyn FnOnce() -> Result<()> + Send>;

#[derive(Clone, Default)]
pub(super) struct Oracle {
    calls: Arc<AtomicUsize>,
    hook: Arc<Mutex<Option<VerificationHook>>>,
    native_hook: Arc<Mutex<Option<VerificationHook>>>,
}
impl Oracle {
    pub fn after_native_authorization(&self) -> Result<()> {
        let hook = self.native_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook()?;
        }
        Ok(())
    }
    pub fn verify(&self, spec: &ProofSpec, proof: &[u8]) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ensure!(
            proof.len() == PROOF_BYTES
                && proof[..32] == hash(&[&spec.expected])
                && proof[32..64] == role_digest(spec.relation),
            "test oracle binding mismatch"
        );
        let hook = self.hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook()?;
        }
        Ok(())
    }
}
fn role_digest(relation: Relation) -> Digest {
    hash(&[format!("{relation:?}").as_bytes()])
}

#[test]
fn shared_wire_roundtrip_and_request_guard_cover_proof_commit_and_replay() -> Result<()> {
    let h = Harness::new()?;
    let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    let decoded = Request::decode(&issue.encode()?)?;
    assert_eq!(decoded.digest()?, issue.digest()?);
    let expired = Arc::new(AtomicBool::new(false));
    let during = expired.clone();
    *h.oracle.hook.lock().unwrap() = Some(Box::new(move || {
        during.store(true, Ordering::SeqCst);
        Ok(())
    }));
    let before = fs::read(&h.engine.checkpoint)?;
    assert!(
        h.engine
            .handle_guarded(&decoded, || {
                ensure!(!expired.load(Ordering::SeqCst), "request deadline");
                Ok(())
            })
            .is_err()
    );
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    let response = h.engine.handle_guarded(&decoded, || Ok(()))?;
    assert!(
        h.engine
            .handle_guarded(&decoded, || anyhow::bail!("expired replay"))
            .is_err()
    );
    assert_eq!(response, h.reopen()?.handle(&decoded)?);
    Ok(())
}
#[derive(Default)]
struct Gate(AtomicBool);
impl Admission for Gate {
    fn authorize(&self, _: &TransferContext) -> Result<()> {
        ensure!(!self.0.load(Ordering::SeqCst), "credential revoked");
        Ok(())
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&random_scalar().to_bytes()).unwrap()
}
fn number(n: u64) -> Digest {
    Scalar::from(n).to_bytes().into()
}
fn pubkey(k: &SigningKey) -> Digest {
    k.verifying_key().to_bytes().into()
}
fn placeholder_owner_authorization() -> OwnerAuthorization {
    OwnerAuthorization {
        public_key: pubkey(&key()),
        signature: vec![0; 64],
    }
}
fn test_token(ctx: &TransferContext) -> Digest {
    hash(&[b"signer-test-only-token", &ctx.operation])
}
#[test]
fn origin_attestation_follows_joint_issuance_and_acknowledgement_replays() -> Result<()> {
    let h = Harness::new()?;
    let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    let issued = h.engine.handle(&issue)?;
    assert_eq!(issued, h.reopen()?.handle(&issue)?);
    let accept = h.request(
        &h.origin_context,
        Command::AcceptOrigin {
            state: [0; 32],
            issuance_identity: [0; 32],
        },
        &h.alice,
    )?;
    let response = h.engine.handle(&accept)?;
    let (coin, _) = h.snapshot()?;
    assert!(coin.phase == Phase::Accepted);
    h.engine.lineage(&coin).verify_origin_attestation(
        &serde_json::from_value::<Vec<u8>>(issued["origin_signature"].clone())?
            .try_into()
            .unwrap(),
    )?;
    assert_eq!(response, h.reopen()?.handle(&accept)?);
    Ok(())
}

#[test]
fn issuance_moves_authority_before_ack_and_separates_role_caches() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (old, _) = h.snapshot()?;
    let (s, sk, r, rk) = h.transfer_contexts()?;
    let reserve = h.request(
        &s,
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &sk,
    )?;
    let mask = h.engine.handle(&reserve)?;
    // Continue using the exact reserved context without creating another reserve.
    let (coin, _) = h.snapshot()?;
    let p = coin.pending.as_ref().unwrap();
    let outer = LineageHandoverBinding {
        handover: HandoverBinding {
            intent: s.intent(),
            funding: coin.funding,
            mask: p.cm.unwrap(),
            masked_share: random32(),
            bridge: random32(),
            previous_capability: coin.capability,
            server_share: ServerShareOpening {
                deployment: coin.deployment,
                coin: coin.coin,
                server: point(coin.server_secret)?.try_into().unwrap(),
                salt: coin.server_salt,
            }
            .commitment()?,
            policy: policy_commitment(h.engine.policy.schedule)?,
            draft_access: draft_access_commitment(&s.intent(), &test_token(&s))?,
        },
        origin_key: h.engine.policy.origin_key,
        role_hashes: h.engine.policy.role_hashes,
    };
    h.send(
        &s,
        Command::Handover {
            statement: outer.encode()?,
            predecessor: PredecessorKind::Origin,
            proof: vec![0; PROOF_BYTES],
        },
        &sk,
    )?;
    let claim = h.claim(&r, &rk)?;
    let claim_response = h.engine.handle(&claim)?;
    assert!(mask.get("mask").is_some());
    assert!(claim_response.get("mask").is_none());
    assert!(h.engine.handle(&reserve)?.get("mask").is_none());
    let mut stolen = claim.clone();
    stolen.context = s.clone();
    stolen.signature = sign_request(&sk, &s, stolen.command.purpose(), &stolen.digest()?)?;
    assert!(h.engine.handle(&stolen).is_err());
    let issue = h.prepare_issue(&r, &rk)?;
    let released = h.engine.handle(&issue)?;
    let (new, _) = h.snapshot()?;
    assert!(new.phase == Phase::Issued);
    assert_ne!(old.state, new.state);
    assert_ne!(old.capability, new.capability);
    let (new_context, k, _, _) = h.transfer_contexts()?;
    let req = Request::sign(
        new_context,
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &k,
    )?;
    assert!(h.engine.handle(&req).is_err());
    assert_eq!(released, h.reopen()?.handle(&issue)?);
    assert_eq!(
        h.send(&s, Command::CompleteSender {}, &sk)?["completed"],
        false
    );
    h.send(&r, h.acknowledgement(&r)?, &rk)?;
    assert_eq!(
        h.send(&s, Command::CompleteSender {}, &sk)?["completed"],
        true
    );
    Ok(())
}

#[test]
fn revoked_admission_preserves_admitted_retries_and_bound_issued_recovery() -> Result<()> {
    let h = Harness::new()?;
    let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    let response = h.engine.handle(&issue)?;
    let calls = h.oracle.calls.load(Ordering::SeqCst);
    h.gate.0.store(true, Ordering::SeqCst);
    assert_eq!(response, h.engine.handle(&issue)?);
    assert_eq!(calls, h.oracle.calls.load(Ordering::SeqCst));
    let digest = serde_json::from_value(response["binding_digest"].clone())?;
    let req = Request::sign(
        h.origin_context.clone(),
        Command::RetrieveIssued {
            binding_digest: digest,
        },
        &h.alice,
    )?;
    assert_eq!(response, h.reopen()?.handle(&req)?);
    let wrong = key();
    let mut ctx = h.origin_context.clone();
    ctx.session_auth = pubkey(&wrong);
    assert!(
        h.engine
            .handle(&Request::sign(
                ctx,
                Command::RetrieveIssued {
                    binding_digest: digest
                },
                &wrong
            )?)
            .is_err()
    );
    Ok(())
}

#[test]
fn malformed_session_and_changed_nonce_request_have_no_side_effects() -> Result<()> {
    let h = Harness::new()?;
    let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    let before = fs::read(&h.engine.checkpoint)?;
    let mut invalid = issue.clone();
    invalid.signature[0] ^= 1;
    assert!(h.engine.handle(&invalid).is_err());
    assert_eq!(h.oracle.calls.load(Ordering::SeqCst), 0);
    let changed = Request::sign(
        h.origin_context.clone(),
        Command::Prepare {
            recovery: random32(),
            blinding: random32(),
        },
        &h.alice,
    )?;
    assert!(h.engine.handle(&changed).is_err());
    let mut invalid = issue.clone();
    if let Command::IssueDeposit { proof, .. } = &mut invalid.command {
        proof[0] ^= 1;
    }
    invalid = Request::sign(invalid.context, invalid.command, &h.alice)?;
    assert!(h.engine.handle(&invalid).is_err());
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    h.engine.handle(&issue)?;
    Ok(())
}

#[test]
fn revocation_after_native_owner_authorization_is_rechecked() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (sender, sender_key, _, _) = h.transfer_contexts()?;
    let reserve = h.request(
        &sender,
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &sender_key,
    )?;
    let before = fs::read(&h.engine.checkpoint)?;
    let gate = h.gate.clone();
    *h.oracle.native_hook.lock().unwrap() = Some(Box::new(move || {
        gate.0.store(true, Ordering::SeqCst);
        Ok(())
    }));
    assert!(h.engine.handle(&reserve).is_err());
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    Ok(())
}

#[test]
fn stale_verified_revision_cannot_issue_after_competing_commit() -> Result<()> {
    let h = Harness::new()?;
    let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    let competing = h.reopen()?;
    let exact = issue.clone();
    *h.oracle.hook.lock().unwrap() = Some(Box::new(move || {
        competing.handle(&exact)?;
        Ok(())
    }));
    assert!(
        h.engine
            .handle(&issue)
            .unwrap_err()
            .to_string()
            .contains("stale verified revision")
    );
    let response = h.reopen()?.handle(&issue)?;
    assert_eq!(response["issued"], true);
    Ok(())
}

#[test]
fn crash_boundaries_preserve_exact_partial_and_require_explicit_gap_repair() -> Result<()> {
    for fault in [
        Fault::AfterVerification,
        Fault::BeforeCommit,
        Fault::AfterCommit,
        Fault::AfterCheckpoint,
    ] {
        let h = Harness::new()?;
        let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
        *h.engine.fault.lock().unwrap() = Some(fault);
        assert!(h.engine.handle(&issue).is_err());
        if fault == Fault::AfterCommit {
            assert!(h.reopen().is_err());
            assert!(h.engine.handle(&issue).is_err());
            h.engine.repair_interrupted_checkpoint()?;
        }
        let response = h.reopen()?.handle(&issue)?;
        assert_eq!(response["issued"], true);
        assert_eq!(response, h.reopen()?.handle(&issue)?);
        let (coin, _) = h.snapshot()?;
        assert!(coin.pending.as_ref().unwrap().nonce_secret.is_none());
    }
    Ok(())
}

#[test]
fn checkpoint_rollback_missing_and_corruption_fail_closed() -> Result<()> {
    let h = Harness::new()?;
    let old = fs::read(&h.engine.checkpoint)?;
    h.origin()?;
    let good = fs::read(&h.engine.checkpoint)?;
    fs::write(&h.engine.checkpoint, old)?;
    assert!(h.reopen().is_err());
    assert!(h.engine.repair_interrupted_checkpoint().is_err());
    fs::remove_file(&h.engine.checkpoint)?;
    assert!(h.reopen().is_err());
    fs::write(&h.engine.checkpoint, &good)?;
    h.reopen()?;
    let sql = rusqlite::Connection::open(&h.engine.db)?;
    sql.execute("UPDATE coins SET body='{}'", [])?;
    assert!(h.reopen().is_err());
    Ok(())
}

#[test]
fn fresh_head_is_current_signed_and_excludes_role_secrets() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let query = HeadQuery::fresh([1; 32], [2; 32], h.origin_context.session_auth)?;
    let response = h.send(
        &h.origin_context,
        Command::Head {
            query: query.clone(),
        },
        &h.alice,
    )?;
    let head: Head = serde_json::from_value(response["head"].clone())?;
    let signature: Vec<u8> = serde_json::from_value(response["signature"].clone())?;
    head.verify(
        &query,
        &pubkey(&h.engine.control),
        &signature.try_into().unwrap(),
    )?;
    assert!(response.get("server_secret").is_none());
    assert!(response.get("mask").is_none());
    let other = HeadQuery::fresh([1; 32], [2; 32], h.origin_context.session_auth)?;
    assert_ne!(query.challenge, other.challenge);
    Ok(())
}

#[test]
fn all_coin_validation_rejects_invalid_phase_even_with_recomputed_checksums() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (mut coin, _) = h.snapshot()?;
    coin.phase = Phase::Prepared;
    coin.pending = Some(Pending::new(false));
    let body = serde_json::to_string(&coin)?;
    let sql = rusqlite::Connection::open(&h.engine.db)?;
    sql.execute(
        "UPDATE coins SET body=?1,checksum=?2",
        rusqlite::params![body, hash(&[body.as_bytes()]).as_slice()],
    )?;
    assert!(
        Store::open(&h.engine.db, h.engine.config)?
            .validate(&h.engine.policy)
            .is_err()
    );
    assert!(h.reopen().is_err());
    Ok(())
}

#[test]
fn honest_chain_failure_after_issue_does_not_restore_sender_authority() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (s, sk, r, rk) = h.transfer_contexts()?;
    h.handover(&s, &sk)?;
    h.claim(&r, &rk)?;
    let issue = h.prepare_issue(&r, &rk)?;
    let response = h.engine.handle(&issue)?;
    // Recipient discovers a chain/window problem and withholds acceptance. No
    // chain-safe flag or cancellation endpoint can restore the sender's share.
    let (coin, _) = h.snapshot()?;
    assert!(coin.phase == Phase::Issued);
    assert_eq!(json!(coin.state), response["state"]);
    let reserve = Request::sign(
        s.clone(),
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &sk,
    )?;
    assert!(h.engine.handle(&reserve).is_err());
    assert_eq!(response, h.reopen()?.handle(&issue)?);
    Ok(())
}
