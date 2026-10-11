//! Fresh bootstrap host ordering; relation oracle remains explicitly test-only.
use super::*;
use zark_protocol::bootstrap::BootstrapBinding;

impl Harness {
    fn bootstrap_allocate(&self) -> Result<(Request, Value)> {
        let req = Request::sign(
            self.origin_context.clone(),
            Command::BootstrapAllocate {},
            &self.alice,
        )?;
        let response = self.engine.handle(&req)?;
        Ok((req, response))
    }
    fn bootstrap_hold(&self) -> Result<Request> {
        let (_, allocated) = self.bootstrap_allocate()?;
        let prepared = self.send(
            &self.origin_context,
            Command::BootstrapPrepare {
                parent_funding: [5; 32],
                active_funding: [6; 32],
                capability: self.initial_capability,
                blinding: [8; 32],
            },
            &self.alice,
        )?;
        let bytes = |value: &Value| -> Result<[u8; 64]> {
            Ok(serde_json::from_value::<Vec<u8>>(value.clone())?
                .try_into()
                .unwrap())
        };
        let b = BootstrapBinding {
            context: self.origin_context.clone(),
            parent_funding: [5; 32],
            active_funding: [6; 32],
            initial_capability: self.initial_capability,
            parent_server: bytes(&allocated["parent_server"])?,
            active_server: bytes(&allocated["active_server"])?,
            nonce_commitment: [8; 32],
            parent_nonce: bytes(&prepared["parent_nonce"])?,
            blinded_challenge: number(9),
        };
        let req = self.request(
            &self.origin_context,
            Command::BootstrapFreeze {
                statement: b.encode()?,
            },
            &self.alice,
        )?;
        self.engine.handle(&req)?;
        Ok(req)
    }
}

#[test]
fn bootstrap_allocates_one_authority_for_both_outputs_and_replays_without_reallocation()
-> Result<()> {
    let h = Harness::with_test_allocation(false)?;
    let (req, response) = h.bootstrap_allocate()?;
    assert_eq!(response["parent_server"], response["active_server"]);
    assert_eq!(
        response,
        h.reopen()?.handle(&Request::decode(&req.encode()?)?)?
    );
    let mut ctx = h.origin_context.clone();
    let outsider = key();
    ctx.session_auth = pubkey(&outsider);
    let before = fs::read(&h.engine.checkpoint)?;
    assert!(
        h.engine
            .handle(&Request::sign(
                ctx,
                Command::BootstrapAllocate {},
                &outsider
            )?)
            .is_err()
    );
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    Ok(())
}

#[test]
fn activation_and_recovery_release_only_after_exact_combined_authorization() -> Result<()> {
    let h = Harness::with_test_allocation(false)?;
    let authorization = h.bootstrap_hold()?;
    let held = h.engine.handle(&authorization)?;
    assert_eq!(held["activation_held"], true);
    assert!(held.get("activation_partial").is_none());
    let retrieve = Request::sign(
        h.origin_context.clone(),
        Command::RetrieveBootstrap {
            binding_digest: random32(),
        },
        &h.alice,
    )?;
    assert!(h.engine.handle(&retrieve).is_err());
    let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    let recovery = h.engine.handle(&issue)?;
    assert!(recovery.get("activation_partial").is_some());
    let mut ack = h.request(
        &h.origin_context,
        Command::AcceptOrigin {
            state: [0; 32],
            issuance_identity: [0; 32],
        },
        &h.alice,
    )?;
    if let Command::AcceptOrigin {
        issuance_identity, ..
    } = &mut ack.command
    {
        issuance_identity[0] ^= 1;
    }
    ack = Request::sign(ack.context, ack.command, &h.alice)?;
    let before = fs::read(&h.engine.checkpoint)?;
    assert!(h.engine.handle(&ack).is_err());
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    h.send(
        &h.origin_context,
        Command::AcceptOrigin {
            state: [0; 32],
            issuance_identity: [0; 32],
        },
        &h.alice,
    )?;
    assert!(recovery.get("origin_signature").is_some());
    let (coin, _) = h.snapshot()?;
    let stored = serde_json::to_value(&coin.bootstrap)?;
    assert!(stored.get("parent_secret").is_none());
    assert_eq!(json!(point(coin.server_secret)?), stored["parent_server"]);
    assert!(stored["nonce_secret"].is_null());
    assert!(!stored["partial"].is_null());
    let signature: Vec<u8> = serde_json::from_value(recovery["origin_signature"].clone())?;
    h.engine
        .lineage(&coin)
        .verify_origin_attestation(&signature.try_into().unwrap())?;
    let digest = serde_json::from_value(recovery["activation_binding_digest"].clone())?;
    h.gate.0.store(true, Ordering::SeqCst);
    assert_eq!(
        recovery,
        h.reopen()?.handle(&Request::sign(
            h.origin_context.clone(),
            Command::RetrieveBootstrap {
                binding_digest: digest
            },
            &h.alice
        )?)?
    );
    Ok(())
}

#[test]
fn transferring_bootstrapped_coin_replaces_the_only_share_for_both_outputs() -> Result<()> {
    let h = Harness::with_test_allocation(false)?;
    h.bootstrap_hold()?;
    h.engine
        .handle(&h.prepare_issue(&h.origin_context, &h.alice)?)?;
    h.send(
        &h.origin_context,
        Command::AcceptOrigin {
            state: [0; 32],
            issuance_identity: [0; 32],
        },
        &h.alice,
    )?;
    let (old, _) = h.snapshot()?;
    let user = Scalar::from(17u64);
    let original = ProjectivePoint::GENERATOR * (scalar(&old.server_secret)? + user);
    let (s, sk, r, rk) = h.transfer_contexts()?;
    h.handover(&s, &sk)?;
    let (reserved, _) = h.snapshot()?;
    let mask = scalar(&reserved.pending.as_ref().unwrap().mask.unwrap())?;
    h.claim(&r, &rk)?;
    let issue = h.prepare_issue(&r, &rk)?;
    h.engine.handle(&issue)?;
    let (current, _) = h.snapshot()?;
    // The harness supplies delta=11. This models the receiver's matching share;
    // the proof oracle tests lifecycle only, not the real handover relation.
    let receiver = user + mask - Scalar::from(11u64);
    assert_eq!(
        ProjectivePoint::GENERATOR * (scalar(&current.server_secret)? + receiver),
        original
    );
    assert_ne!(
        ProjectivePoint::GENERATOR * (scalar(&current.server_secret)? + user),
        original
    );
    assert_ne!(current.server_secret, old.server_secret);
    let stored = serde_json::to_vec(&current)?;
    let old_secret = serde_json::to_vec(&old.server_secret)?;
    assert!(!stored.windows(old_secret.len()).any(|w| w == old_secret));
    assert!(current.pending.as_ref().unwrap().draft_secret.is_none());
    let before = fs::read(&h.engine.checkpoint)?;
    assert!(
        h.engine
            .handle(&Request::sign(
                h.origin_context.clone(),
                Command::Prepare {
                    recovery: random32(),
                    blinding: random32()
                },
                &h.alice
            )?)
            .is_err()
    );
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    Ok(())
}

#[test]
fn parent_release_crashes_recover_one_identical_partial_and_attestation() -> Result<()> {
    for fault in [
        Fault::AfterVerification,
        Fault::BeforeCommit,
        Fault::AfterCommit,
        Fault::AfterCheckpoint,
    ] {
        let h = Harness::with_test_allocation(false)?;
        h.bootstrap_hold()?;
        let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
        let (coin, _) = h.snapshot()?;
        let raw = serde_json::to_value(&coin.bootstrap)?;
        let parent = coin.server_secret;
        let nonce: Digest = serde_json::from_value(raw["nonce_secret"].clone())?;
        let expected: Digest = (scalar(&nonce)? + Scalar::from(9u64) * scalar(&parent)?)
            .to_bytes()
            .into();
        let recovery_nonce = coin.pending.as_ref().unwrap().nonce_secret.unwrap();
        let expected_recovery: Digest = (scalar(&recovery_nonce)?
            + Scalar::from(7u64) * scalar(&parent)?)
        .to_bytes()
        .into();
        *h.engine.fault.lock().unwrap() = Some(fault);
        assert!(h.engine.handle(&issue).is_err());
        if fault == Fault::AfterCommit {
            assert!(h.reopen().is_err());
            h.engine.repair_interrupted_checkpoint()?;
        }
        let response = h.reopen()?.handle(&issue)?;
        assert_eq!(response["activation_partial"], json!(expected));
        assert_eq!(response["partial"], json!(expected_recovery));
        let (saved, _) = h.snapshot()?;
        assert!(saved.pending.as_ref().unwrap().nonce_secret.is_none());
        assert!(serde_json::to_value(&saved.bootstrap)?["nonce_secret"].is_null());
        assert_eq!(response, h.reopen()?.handle(&issue)?);
    }
    Ok(())
}

#[test]
fn bootstrap_wrong_kind_changed_freeze_and_early_transfer_are_rejected() -> Result<()> {
    let h = Harness::with_test_allocation(false)?;
    h.bootstrap_allocate()?;
    let early = Request::sign(
        h.origin_context.clone(),
        Command::Prepare {
            recovery: random32(),
            blinding: random32(),
        },
        &h.alice,
    )?;
    assert!(h.engine.handle(&early).is_err());
    h.send(
        &h.origin_context,
        Command::BootstrapPrepare {
            parent_funding: [5; 32],
            active_funding: [6; 32],
            capability: h.initial_capability,
            blinding: [8; 32],
        },
        &h.alice,
    )?;
    let before = fs::read(&h.engine.checkpoint)?;
    let changed = Request::sign(
        h.origin_context.clone(),
        Command::BootstrapPrepare {
            parent_funding: [5; 32],
            active_funding: [9; 32],
            capability: h.initial_capability,
            blinding: [8; 32],
        },
        &h.alice,
    )?;
    assert!(h.engine.handle(&changed).is_err());
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    // Exact prepare/allocate replay permits constructing the original request.
    let authorization = h.bootstrap_hold()?;
    let mut wrong = authorization.command.clone();
    if let Command::BootstrapFreeze { statement } = &mut wrong {
        statement[237] ^= 1;
    }
    assert!(
        h.engine
            .handle(&Request::sign(h.origin_context.clone(), wrong, &h.alice)?)
            .is_err()
    );
    let (sender, sender_key, _, _) = h.transfer_contexts()?;
    assert!(
        h.engine
            .handle(&Request::sign(
                sender,
                Command::Reserve {
                    owner_authorization: placeholder_owner_authorization()
                },
                &sender_key
            )?)
            .is_err()
    );
    Ok(())
}

#[test]
fn bootstrap_allocation_checkpoint_gap_cannot_duplicate_shares() -> Result<()> {
    let h = Harness::with_test_allocation(false)?;
    let request = Request::sign(
        h.origin_context.clone(),
        Command::BootstrapAllocate {},
        &h.alice,
    )?;
    *h.engine.fault.lock().unwrap() = Some(Fault::AfterCommit);
    assert!(h.engine.handle(&request).is_err());
    assert!(h.reopen().is_err());
    h.engine.repair_interrupted_checkpoint()?;
    let response = h.reopen()?.handle(&request)?;
    assert_eq!(response, h.reopen()?.handle(&request)?);
    Ok(())
}

#[test]
fn one_deposit_proof_rejects_bypass_and_releases_neither_nonce_on_failure() -> Result<()> {
    let h = Harness::with_test_allocation(false)?;
    h.bootstrap_hold()?;
    assert_eq!(h.oracle.calls.load(Ordering::SeqCst), 0);
    let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    assert_eq!(h.oracle.calls.load(Ordering::SeqCst), 0);
    let Command::IssueDeposit { statement, proof } = &issue.command else {
        unreachable!()
    };
    let deposit = DepositBinding::decode(statement)?;
    let before = fs::read(&h.engine.checkpoint)?;
    let mut invalid = proof.clone();
    invalid[0] ^= 1;
    for command in [
        Command::IssueDeposit {
            statement: statement.clone(),
            proof: invalid,
        },
        Command::Issue {
            statement: deposit.authorization.encode()?,
            proof: proof.clone(),
        },
        Command::AcceptOrigin {
            state: [1; 32],
            issuance_identity: [2; 32],
        },
    ] {
        assert!(
            h.engine
                .handle(&Request::sign(h.origin_context.clone(), command, &h.alice)?)
                .is_err()
        );
        assert_eq!(before, fs::read(&h.engine.checkpoint)?);
        let (coin, _) = h.snapshot()?;
        assert!(
            coin.bootstrap
                .as_ref()
                .unwrap()
                .released_partial()
                .is_none()
        );
        assert!(coin.pending.as_ref().unwrap().nonce_secret.is_some());
        assert!(coin.pending.as_ref().unwrap().partial.is_none());
    }
    // Both activation and recovery are exact immutable bindings; a valid proof
    // for another frozen message cannot reuse either prepared nonce.
    for offset in [
        237usize,
        845,
        IssuanceBinding::ENCODED_LEN + 237,
        IssuanceBinding::ENCODED_LEN + 557,
    ] {
        let mut changed = statement.clone();
        changed[offset] ^= 1;
        assert!(
            h.engine
                .handle(&Request::sign(
                    h.origin_context.clone(),
                    Command::IssueDeposit {
                        statement: changed,
                        proof: proof.clone()
                    },
                    &h.alice
                )?)
                .is_err()
        );
        assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    }
    let calls = h.oracle.calls.load(Ordering::SeqCst);
    let response = h.engine.handle(&issue)?;
    assert_eq!(h.oracle.calls.load(Ordering::SeqCst), calls + 1);
    assert!(response.get("partial").is_some() && response.get("activation_partial").is_some());
    let accept = h.request(
        &h.origin_context,
        Command::AcceptOrigin {
            state: [0; 32],
            issuance_identity: [0; 32],
        },
        &h.alice,
    )?;
    h.engine.handle(&accept)?;
    assert_eq!(h.oracle.calls.load(Ordering::SeqCst), calls + 1);
    assert_eq!(response, h.reopen()?.handle(&issue)?);
    assert!(Command::decode(br#"{"op":"bootstrap_authorize","statement":[],"proof":[]}"#).is_err());
    Ok(())
}

#[test]
fn deposited_signatures_remain_privately_retrievable_after_share_rotation() -> Result<()> {
    let h = Harness::new()?;
    let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    let issued = h.engine.handle(&issue)?;
    h.send(
        &h.origin_context,
        Command::AcceptOrigin {
            state: [0; 32],
            issuance_identity: [0; 32],
        },
        &h.alice,
    )?;
    let (s, sk, r, rk) = h.transfer_contexts()?;
    h.handover(&s, &sk)?;
    h.claim(&r, &rk)?;
    h.engine.handle(&h.prepare_issue(&r, &rk)?)?;
    h.gate.0.store(true, Ordering::SeqCst);
    let retrieve = Request::sign(
        h.origin_context.clone(),
        Command::RetrieveIssued {
            binding_digest: serde_json::from_value(issued["binding_digest"].clone())?,
        },
        &h.alice,
    )?;
    assert_eq!(issued, h.reopen()?.handle(&retrieve)?);
    let mut outsider = h.origin_context.clone();
    let key = key();
    outsider.session_auth = pubkey(&key);
    assert!(
        h.reopen()?
            .handle(&Request::sign(outsider, retrieve.command, &key)?)
            .is_err()
    );
    Ok(())
}
