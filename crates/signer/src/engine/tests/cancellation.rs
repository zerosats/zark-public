//! Durable state-machine qualification with the test oracle, not real ZK proofs.
use super::*;

fn cancel(context: &TransferContext, key: &SigningKey) -> Result<Request> {
    Request::sign(context.clone(), Command::CancelTransfer {}, key)
}

#[test]
fn every_precommit_phase_cancels_and_old_receipts_do_not_change_new_activity() -> Result<()> {
    for phase in 0..4 {
        let h = Harness::new()?;
        h.origin()?;
        let old = h.snapshot()?.0;
        let (s, sk, r, rk) = h.transfer_contexts()?;
        let reserve = h.request(
            &s,
            Command::Reserve {
                owner_authorization: placeholder_owner_authorization(),
            },
            &sk,
        )?;
        let mut delayed = vec![reserve.clone()];
        if phase >= 1 {
            delayed.push(h.handover(&s, &sk)?);
        } else {
            h.engine.handle(&reserve)?;
        }
        if phase >= 2 {
            delayed.push(h.claim(&r, &rk)?);
        }
        if phase >= 3 {
            let issue = h.prepare_issue(&r, &rk)?;
            let coin = h.snapshot()?.0;
            let p = coin.pending.as_ref().unwrap();
            delayed.push(Request::sign(
                r.clone(),
                Command::Prepare {
                    recovery: p.recovery.unwrap(),
                    blinding: p.blinding.unwrap(),
                },
                &rk,
            )?);
            delayed.push(issue);
        }
        let request = cancel(&s, &sk)?;
        let decoded = Request::decode(&request.encode()?)?;
        h.gate.0.store(true, Ordering::SeqCst);
        let receipt = h.engine.handle(&decoded)?;
        assert_eq!(receipt["cancelled"], true);
        let restored = h.snapshot()?.0;
        assert!(restored.phase == Phase::Accepted && restored.pending.is_none());
        assert_eq!(restored.server_secret, old.server_secret);
        assert_eq!(restored.server_salt, old.server_salt);
        assert_eq!(restored.state, old.state);
        assert_eq!(restored.capability, old.capability);
        assert!(restored.current_session == old.current_session);
        assert_eq!(receipt, h.reopen()?.handle(&request)?);
        h.gate.0.store(false, Ordering::SeqCst);
        for stale in &delayed {
            assert!(h.engine.handle(stale).is_err());
        }
        let store = Store::open(&h.engine.db, h.engine.config)?;
        assert!(
            store
                .response_for(Purpose::SenderReservation, &s)?
                .is_none()
        );
        assert!(
            store
                .response_for(Purpose::RecipientProposal, &r)?
                .is_none()
        );
        assert!(
            store
                .response_for(Purpose::RecoveryPreparation, &r)?
                .is_none()
        );
        let (fresh, fresh_key, _, _) = h.transfer_contexts()?;
        h.send(
            &fresh,
            Command::Reserve {
                owner_authorization: placeholder_owner_authorization(),
            },
            &fresh_key,
        )?;
        let checkpoint = fs::read(&h.engine.checkpoint)?;
        assert_eq!(receipt, h.reopen()?.handle(&request)?);
        assert!(h.engine.handle(&cancel(&r, &rk)?).is_err());
        let mut altered = s.clone();
        altered.previous_state = random32();
        assert!(h.engine.handle(&cancel(&altered, &sk)?).is_err());
        assert_eq!(checkpoint, fs::read(&h.engine.checkpoint)?);
        h.engine.handle(&cancel(&fresh, &fresh_key)?)?;
        let (_, _, exit) = h.exit_preparation()?;
        h.engine.handle(&exit)?;
    }
    Ok(())
}

#[test]
fn cancellation_requires_the_reserved_sender_and_exact_context() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (s, sk, r, rk) = h.transfer_contexts()?;
    let before = fs::read(&h.engine.checkpoint)?;
    assert!(h.engine.handle(&cancel(&s, &sk)?).is_err());
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    h.handover(&s, &sk)?;
    let before = fs::read(&h.engine.checkpoint)?;
    assert!(h.engine.handle(&cancel(&r, &rk)?).is_err());
    for field in 0..5 {
        let mut context = s.clone();
        match field {
            0 => context.deployment = random32(),
            1 => context.coin = random32(),
            2 => context.previous_state = random32(),
            3 => context.operation = random32(),
            _ => context.recipient_claim = random32(),
        }
        assert!(h.engine.handle(&cancel(&context, &sk)?).is_err());
    }
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    h.engine.handle(&cancel(&s, &sk)?)?;
    assert!(h.engine.handle(&cancel(&r, &rk)?).is_err());
    let mut changed = s.clone();
    changed.previous_state = random32();
    assert!(h.engine.handle(&cancel(&changed, &sk)?).is_err());
    Ok(())
}

#[test]
fn cancellation_never_applies_to_origin_exit_or_batch() -> Result<()> {
    let h = Harness::new()?;
    assert!(
        h.engine
            .handle(&cancel(&h.origin_context, &h.alice)?)
            .is_err()
    );
    h.origin()?;
    let (context, owner, prepare) = h.exit_preparation()?;
    h.engine.handle(&prepare)?;
    assert!(h.engine.handle(&cancel(&context, &owner)?).is_err());
    let b = BatchCase::new()?;
    b.reserve(0)?;
    assert!(
        b.h.engine
            .handle(&cancel(&b.senders[0], &b.sender_keys[0])?)
            .is_err()
    );
    Ok(())
}

#[test]
fn cancellation_wins_against_an_already_verified_issuance() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (s, sk, r, rk) = h.transfer_contexts()?;
    h.handover(&s, &sk)?;
    h.claim(&r, &rk)?;
    let issue = h.prepare_issue(&r, &rk)?;
    let request = cancel(&s, &sk)?;
    let competing = h.reopen()?;
    let exact = request.clone();
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
    assert_eq!(h.reopen()?.handle(&request)?["cancelled"], true);
    assert!(h.engine.handle(&issue).is_err());
    assert!(h.snapshot()?.0.phase == Phase::Accepted);
    Ok(())
}

#[test]
fn issuance_wins_even_when_its_response_was_lost() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (s, sk, r, rk) = h.transfer_contexts()?;
    h.handover(&s, &sk)?;
    h.claim(&r, &rk)?;
    let issue = h.prepare_issue(&r, &rk)?;
    *h.engine.fault.lock().unwrap() = Some(Fault::AfterCheckpoint);
    assert!(h.engine.handle(&issue).is_err());
    assert!(h.reopen()?.handle(&cancel(&s, &sk)?).is_err());
    h.gate.0.store(true, Ordering::SeqCst);
    let response = h.reopen()?.handle(&issue)?;
    let retrieve = Request::sign(
        r,
        Command::RetrieveIssued {
            binding_digest: serde_json::from_value(response["binding_digest"].clone())?,
        },
        &rk,
    )?;
    assert_eq!(response, h.reopen()?.handle(&retrieve)?);
    Ok(())
}

#[test]
fn cancellation_crashes_preserve_tombstone_and_checkpoint_repair_rules() -> Result<()> {
    for fault in [
        Fault::BeforeCommit,
        Fault::AfterCommit,
        Fault::AfterCheckpoint,
    ] {
        let h = Harness::new()?;
        h.origin()?;
        let (s, sk, r, rk) = h.transfer_contexts()?;
        h.handover(&s, &sk)?;
        h.claim(&r, &rk)?;
        let issue = h.prepare_issue(&r, &rk)?;
        let request = cancel(&s, &sk)?;
        *h.engine.fault.lock().unwrap() = Some(fault);
        assert!(h.engine.handle(&request).is_err());
        if fault == Fault::AfterCommit {
            assert!(h.reopen().is_err());
            h.engine.repair_interrupted_checkpoint()?;
        }
        let response = h.reopen()?.handle(&request)?;
        assert_eq!(response["cancelled"], true);
        assert_eq!(response, h.reopen()?.handle(&request)?);
        assert!(h.engine.handle(&issue).is_err());
        assert!(h.snapshot()?.0.pending.is_none());
    }
    Ok(())
}
