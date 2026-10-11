//! Deterministic state-machine qualification using the test-only proof oracle.
//! These cases establish no claims about real ZK proof or Bitcoin validity.
use super::*;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

fn abort_request(b: &BatchCase, member: usize) -> Result<Request> {
    Request::sign(
        b.senders[member].clone(),
        Command::BatchAbort {
            manifest: b.manifest.clone(),
        },
        &b.sender_keys[member],
    )
}

/// Pause one already-verified request while another request reaches a durable
/// decision. Timeouts are deadlock diagnostics, not scheduling assumptions.
fn pause_verification(h: &Harness) -> (Receiver<()>, SyncSender<()>) {
    let (entered_tx, entered_rx) = sync_channel(1);
    let (resume_tx, resume_rx) = sync_channel(1);
    *h.oracle.hook.lock().unwrap() = Some(Box::new(move || {
        entered_tx.send(())?;
        resume_rx.recv_timeout(Duration::from_secs(10))?;
        Ok(())
    }));
    (entered_rx, resume_tx)
}

fn assert_old_authority(b: &BatchCase, old: &[Digest]) -> Result<()> {
    let store = Store::open(&b.h.engine.db, b.h.engine.config)?;
    for (i, member) in b.manifest.members.iter().enumerate() {
        let (coin, _) = b.h.snapshot_for(&member.coin)?;
        assert!(coin.phase == Phase::Accepted);
        assert_eq!(coin.state, old[i]);
        assert!(coin.pending.is_none());
        assert!(store.ready(&b.manifest.id, &member.coin)?.is_none());
        assert!(
            store
                .response_for(Purpose::BatchReadiness, &b.recipients[i])?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn confirmed_block_after_first_readiness_prevents_commit_even_after_restart() -> Result<()> {
    let b = BatchCase::new()?;
    let ready = b.prepare_both()?;
    let old = [
        b.h.snapshot_for(&b.senders[0].coin)?.0.state,
        b.h.snapshot_for(&b.senders[1].coin)?.0.state,
    ];
    assert_eq!(b.h.engine.handle(&ready[0])?["pending"], true);
    b.h.tip.set([43; 32]);
    let checkpoint = fs::read(&b.h.engine.checkpoint)?;
    let reopened = b.h.reopen()?;
    for signer in [&b.h.engine, &reopened] {
        assert!(signer.handle(&ready[1]).is_err());
        assert!(signer.handle(&ready[0]).is_err());
    }
    assert_eq!(checkpoint, fs::read(&b.h.engine.checkpoint)?);
    let store = Store::open(&b.h.engine.db, b.h.engine.config)?;
    for recipient in &b.recipients {
        assert!(
            store
                .response_for(Purpose::BatchReadiness, recipient)?
                .is_none()
        );
    }
    drop(store);
    assert_eq!(b.h.engine.handle(&abort_request(&b, 0)?)?["aborted"], true);
    assert_old_authority(&b, &old)
}

#[test]
fn tip_change_during_proof_verification_does_not_save_readiness() -> Result<()> {
    let b = BatchCase::new()?;
    let ready = b.prepare_both()?;
    let tip = b.h.tip.clone();
    *b.h.oracle.hook.lock().unwrap() = Some(Box::new(move || {
        tip.set([44; 32]);
        Ok(())
    }));
    let checkpoint = fs::read(&b.h.engine.checkpoint)?;
    assert!(b.h.engine.handle(&ready[0]).is_err());
    assert_eq!(checkpoint, fs::read(&b.h.engine.checkpoint)?);
    assert!(
        Store::open(&b.h.engine.db, b.h.engine.config)?
            .ready(&b.manifest.id, &b.recipients[0].coin)?
            .is_none()
    );
    Ok(())
}

#[test]
fn abort_wins_against_verified_second_readiness() -> Result<()> {
    let b = BatchCase::new()?;
    let ready = b.prepare_both()?;
    let old = [
        b.h.snapshot_for(&b.senders[0].coin)?.0.state,
        b.h.snapshot_for(&b.senders[1].coin)?.0.state,
    ];
    b.h.engine.handle(&ready[0])?;
    let competing = b.h.reopen()?;
    let abort = abort_request(&b, 0)?;
    let (entered, resume) = pause_verification(&b.h);
    std::thread::scope(|scope| -> Result<()> {
        let issuance = scope.spawn(|| b.h.engine.handle(&ready[1]));
        entered.recv_timeout(Duration::from_secs(10))?;
        assert_eq!(competing.handle(&abort)?["aborted"], true);
        resume.send(())?;
        assert!(issuance.join().unwrap().is_err());
        Ok(())
    })?;
    assert_old_authority(&b, &old)?;
    for request in &ready {
        assert!(b.h.reopen()?.handle(request).is_err());
    }
    assert_eq!(b.h.reopen()?.handle(&abort)?["aborted"], true);
    Ok(())
}

#[test]
fn commit_wins_against_authenticated_inflight_abort() -> Result<()> {
    let b = BatchCase::new()?;
    let ready = b.prepare_both()?;
    b.h.engine.handle(&ready[0])?;
    let competing = b.h.reopen()?;
    let abort = abort_request(&b, 1)?;
    let (entered_tx, entered_rx) = sync_channel(1);
    let (resume_tx, resume_rx) = sync_channel(1);
    std::thread::scope(|scope| -> Result<()> {
        let cancellation = scope.spawn(move || {
            competing.handle_guarded(&abort, || {
                // handle_guarded authenticates before its initial guard call.
                entered_tx.send(())?;
                resume_rx.recv_timeout(Duration::from_secs(10))?;
                Ok(())
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(10))?;
        assert_eq!(b.h.engine.handle(&ready[1])?["issued"], true);
        resume_tx.send(())?;
        assert!(
            cancellation
                .join()
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("committed batch cannot be aborted")
        );
        Ok(())
    })?;
    b.h.tip.set([45; 32]);
    for request in &ready {
        assert_eq!(b.h.reopen()?.handle(request)?["issued"], true);
    }
    Ok(())
}

#[test]
fn concurrent_readiness_commits_once_and_retries_exactly() -> Result<()> {
    let b = BatchCase::new()?;
    let ready = b.prepare_both()?;
    let competing = b.h.reopen()?;
    let (entered, resume) = pause_verification(&b.h);
    let first = std::thread::scope(|scope| -> Result<Value> {
        let first = scope.spawn(|| b.h.engine.handle(&ready[0]));
        entered.recv_timeout(Duration::from_secs(10))?;
        let pending = competing.handle(&ready[1])?;
        assert_eq!(pending["pending"], true);
        assert!(pending.get("partial").is_none());
        resume.send(())?;
        // Saving the other member's readiness changes checkpoint sequence, not
        // either coin revision or the repair generation. Both verified requests
        // therefore compose into exactly one joint issuance.
        first.join().unwrap()
    })?;
    assert_eq!(first["issued"], true);
    let second = b.h.reopen()?.handle(&ready[1])?;
    let checkpoint = fs::read(&b.h.engine.checkpoint)?;
    for _ in 0..2 {
        assert_eq!(first, b.h.reopen()?.handle(&ready[0])?);
        assert_eq!(second, b.h.reopen()?.handle(&ready[1])?);
    }
    assert_eq!(checkpoint, fs::read(&b.h.engine.checkpoint)?);
    Ok(())
}

#[test]
fn expiry_during_verification_cannot_save_readiness_or_commit() -> Result<()> {
    for prior_ready in [false, true] {
        let b = BatchCase::new()?;
        let ready = b.prepare_both()?;
        let old = [
            b.h.snapshot_for(&b.senders[0].coin)?.0.state,
            b.h.snapshot_for(&b.senders[1].coin)?.0.state,
        ];
        if prior_ready {
            b.h.engine.handle(&ready[0])?;
        }
        let clock = b.h.engine.batch_clock.clone();
        let expiry = b.manifest.expires_at;
        clock.store(expiry - 1, Ordering::SeqCst);
        *b.h.oracle.hook.lock().unwrap() = Some(Box::new(move || {
            // Equality is expired, including when verification began in time.
            clock.store(expiry, Ordering::SeqCst);
            Ok(())
        }));
        let checkpoint = fs::read(&b.h.engine.checkpoint)?;
        assert!(b.h.engine.handle(&ready[1]).is_err());
        assert_eq!(checkpoint, fs::read(&b.h.engine.checkpoint)?);
        assert!(
            Store::open(&b.h.engine.db, b.h.engine.config)?
                .ready(&b.manifest.id, &b.recipients[1].coin)?
                .is_none()
        );
        for member in &b.manifest.members {
            assert!(b.h.snapshot_for(&member.coin)?.0.phase == Phase::Prepared);
        }
        // Expiry blocks new progress; it does not automatically restore shares.
        b.h.gate.0.store(true, Ordering::SeqCst);
        let abort = abort_request(&b, 0)?;
        assert_eq!(b.h.engine.handle(&abort)?["aborted"], true);
        assert_old_authority(&b, &old)?;
    }
    Ok(())
}

#[test]
fn expired_partial_join_needs_abort_and_postcommit_expiry_cannot_revoke() -> Result<()> {
    let b = BatchCase::new()?;
    b.reserve(0)?;
    b.h.engine
        .batch_clock
        .store(b.manifest.expires_at, Ordering::SeqCst);
    assert!(b.reserve(1).is_err());
    assert!(b.h.snapshot_for(&b.senders[0].coin)?.0.phase == Phase::Reserved);
    b.h.gate.0.store(true, Ordering::SeqCst);
    assert_eq!(b.h.engine.handle(&abort_request(&b, 0)?)?["aborted"], true);
    assert!(b.h.snapshot_for(&b.senders[0].coin)?.0.phase == Phase::Accepted);

    let b = BatchCase::new()?;
    let ready = b.prepare_both()?;
    b.h.engine.handle(&ready[0])?;
    b.h.engine.handle(&ready[1])?;
    b.h.engine
        .batch_clock
        .store(b.manifest.expires_at + 1, Ordering::SeqCst);
    assert!(b.h.engine.handle(&abort_request(&b, 1)?).is_err());
    for request in &ready {
        assert_eq!(b.h.engine.handle(request)?["issued"], true);
    }
    Ok(())
}

#[test]
fn batch_commit_crash_matrix_preserves_both_exact_responses() -> Result<()> {
    for fault in [
        Fault::AfterVerification,
        Fault::BeforeCommit,
        Fault::AfterCommit,
        Fault::AfterCheckpoint,
    ] {
        let b = BatchCase::new()?;
        let ready = b.prepare_both()?;
        b.h.engine.handle(&ready[0])?;
        *b.h.engine.fault.lock().unwrap() = Some(fault);
        assert!(b.h.engine.handle(&ready[1]).is_err());
        let committed = matches!(fault, Fault::AfterCommit | Fault::AfterCheckpoint);
        for member in &b.manifest.members {
            let (coin, _) = b.h.snapshot_for(&member.coin)?;
            assert_eq!(coin.phase == Phase::Issued, committed);
            assert_eq!(coin.phase == Phase::Prepared, !committed);
        }
        if fault == Fault::AfterCommit {
            assert!(b.h.reopen().is_err());
            b.h.engine.repair_interrupted_checkpoint()?;
        }
        b.h.reopen()?.handle(&ready[1])?;
        let responses = [
            b.h.reopen()?.handle(&ready[0])?,
            b.h.reopen()?.handle(&ready[1])?,
        ];
        b.h.gate.0.store(true, Ordering::SeqCst);
        for (i, response) in responses.iter().enumerate() {
            let retrieve = Request::sign(
                b.recipients[i].clone(),
                Command::RetrieveIssued {
                    binding_digest: serde_json::from_value(response["binding_digest"].clone())?,
                },
                &b.recipient_keys[i],
            )?;
            assert_eq!(*response, b.h.reopen()?.handle(&retrieve)?);
            assert_eq!(*response, b.h.reopen()?.handle(&retrieve)?);
            let mut foreign = b.recipients[i].clone();
            foreign.session_auth = pubkey(&b.recipient_keys[1 - i]);
            let foreign =
                Request::sign(foreign, retrieve.command.clone(), &b.recipient_keys[1 - i])?;
            assert!(b.h.reopen()?.handle(&foreign).is_err());
        }
    }
    Ok(())
}

#[test]
fn batch_abort_crash_matrix_keeps_tombstone_and_old_authority() -> Result<()> {
    for fault in [
        Fault::BeforeCommit,
        Fault::AfterCommit,
        Fault::AfterCheckpoint,
    ] {
        let b = BatchCase::new()?;
        let ready = b.prepare_both()?;
        let old = [
            b.h.snapshot_for(&b.senders[0].coin)?.0.state,
            b.h.snapshot_for(&b.senders[1].coin)?.0.state,
        ];
        b.h.engine.handle(&ready[0])?;
        let abort = abort_request(&b, 1)?;
        *b.h.engine.fault.lock().unwrap() = Some(fault);
        assert!(b.h.engine.handle(&abort).is_err());
        if fault == Fault::AfterCommit {
            assert!(b.h.reopen().is_err());
            b.h.engine.repair_interrupted_checkpoint()?;
        }
        b.h.gate.0.store(true, Ordering::SeqCst);
        assert_eq!(b.h.reopen()?.handle(&abort)?["aborted"], true);
        assert_old_authority(&b, &old)?;
        b.h.gate.0.store(false, Ordering::SeqCst);
        for request in &ready {
            assert!(b.h.reopen()?.handle(request).is_err());
        }
        assert!(b.reserve(0).is_err());
        assert!(b.reserve(1).is_err());
    }
    Ok(())
}

#[test]
fn multi_coin_batches_require_every_readiness_in_shuffled_order() -> Result<()> {
    for count in 2..=zark_protocol::batch::MAX_BATCH_MEMBERS {
        let b = BatchCase::with_count(count)?;
        let ready = b.prepare_all()?;
        // Fixed PRNG seed keeps failures reproducible while exercising different
        // final members and noncanonical arrival orders at every supported size.
        let mut order: Vec<_> = (0..count).collect();
        let mut seed = 0x38b72u64 + count as u64;
        for index in (1..count).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            order.swap(index, seed as usize % (index + 1));
        }
        for (position, index) in order.into_iter().enumerate() {
            let response = b.h.engine.handle(&ready[index])?;
            if position + 1 < count {
                assert_eq!(response["pending"], true);
                assert!(response.get("issued").is_none());
                for member in &b.manifest.members {
                    let coin = b.h.snapshot_for(&member.coin)?.0;
                    assert!(coin.phase == Phase::Prepared);
                    assert!(coin.pending.as_ref().unwrap().issued_transfer.is_none());
                }
            } else {
                assert_eq!(response["issued"], true);
            }
        }
        for request in &ready {
            assert_eq!(b.h.reopen()?.handle(request)?["issued"], true);
        }
    }
    Ok(())
}

#[test]
fn maximum_batch_commit_crash_matrix_and_private_retrieval() -> Result<()> {
    for fault in [
        Fault::BeforeCommit,
        Fault::AfterCommit,
        Fault::AfterCheckpoint,
    ] {
        let b = BatchCase::with_count(10)?;
        let ready = b.prepare_all()?;
        for request in ready.iter().take(9) {
            assert_eq!(b.h.engine.handle(request)?["pending"], true);
        }
        *b.h.engine.fault.lock().unwrap() = Some(fault);
        assert!(b.h.engine.handle(&ready[9]).is_err());
        let committed = fault != Fault::BeforeCommit;
        for member in &b.manifest.members {
            assert_eq!(
                b.h.snapshot_for(&member.coin)?.0.phase == Phase::Issued,
                committed
            );
        }
        if fault == Fault::AfterCommit {
            assert!(b.h.reopen().is_err());
            b.h.engine.repair_interrupted_checkpoint()?;
        }
        b.h.reopen()?.handle(&ready[9])?;
        b.h.engine
            .batch_clock
            .store(b.manifest.expires_at + 1, Ordering::SeqCst);
        assert!(b.h.engine.handle(&abort_request(&b, 0)?).is_err());
        for (index, request) in ready.iter().enumerate() {
            let response = b.h.reopen()?.handle(request)?;
            let retrieve = Command::RetrieveIssued {
                binding_digest: serde_json::from_value(response["binding_digest"].clone())?,
            };
            let own = Request::sign(
                b.recipients[index].clone(),
                retrieve.clone(),
                &b.recipient_keys[index],
            )?;
            assert_eq!(b.h.reopen()?.handle(&own)?, response);
            let other = (index + 1) % 10;
            let mut foreign = b.recipients[index].clone();
            foreign.session_auth = pubkey(&b.recipient_keys[other]);
            let foreign = Request::sign(foreign, retrieve, &b.recipient_keys[other])?;
            assert!(b.h.reopen()?.handle(&foreign).is_err());
        }
    }
    Ok(())
}

#[test]
fn maximum_batch_abort_restores_all_partial_readiness_and_tombstones() -> Result<()> {
    for fault in [
        Fault::BeforeCommit,
        Fault::AfterCommit,
        Fault::AfterCheckpoint,
    ] {
        let b = BatchCase::with_count(10)?;
        let ready = b.prepare_all()?;
        let old: Vec<_> = b
            .manifest
            .members
            .iter()
            .map(|member| Ok(b.h.snapshot_for(&member.coin)?.0.state))
            .collect::<Result<_>>()?;
        for request in ready.iter().take(9) {
            b.h.engine.handle(request)?;
        }
        let abort = abort_request(&b, 7)?;
        *b.h.engine.fault.lock().unwrap() = Some(fault);
        assert!(b.h.engine.handle(&abort).is_err());
        if fault == Fault::AfterCommit {
            assert!(b.h.reopen().is_err());
            b.h.engine.repair_interrupted_checkpoint()?;
        }
        assert_eq!(b.h.reopen()?.handle(&abort)?["aborted"], true);
        for (index, member) in b.manifest.members.iter().enumerate() {
            let coin = b.h.snapshot_for(&member.coin)?.0;
            assert!(coin.phase == Phase::Accepted);
            assert_eq!(coin.state, old[index]);
            assert!(coin.pending.is_none());
            assert!(b.h.engine.handle(&ready[index]).is_err());
            assert!(b.reserve(index).is_err());
        }
    }
    Ok(())
}

#[test]
fn maximum_batch_partial_join_abort_releases_only_joined_members() -> Result<()> {
    let b = BatchCase::with_count(10)?;
    for index in [0, 3, 8] {
        b.reserve(index)?;
    }
    // A missing member prevents even handover for a joined member.
    assert!(b.handover(0).is_err());
    b.h.engine
        .batch_clock
        .store(b.manifest.expires_at + 1, Ordering::SeqCst);
    assert_eq!(b.h.engine.handle(&abort_request(&b, 3)?)?["aborted"], true);
    for member in &b.manifest.members {
        let coin = b.h.snapshot_for(&member.coin)?.0;
        assert!(coin.phase == Phase::Accepted);
        assert!(coin.pending.is_none());
    }
    b.h.reopen()?;
    Ok(())
}

#[test]
fn maximum_batch_final_readiness_loses_to_abort_or_expiry_without_partial_issue() -> Result<()> {
    for abort in [true, false] {
        let b = BatchCase::with_count(10)?;
        let ready = b.prepare_all()?;
        let old = b
            .manifest
            .members
            .iter()
            .map(|member| Ok(b.h.snapshot_for(&member.coin)?.0.state))
            .collect::<Result<Vec<_>>>()?;
        for request in ready.iter().take(9) {
            b.h.engine.handle(request)?;
        }
        let competing = b.h.reopen()?;
        let abort_request = abort_request(&b, 7)?;
        let (entered, resume) = pause_verification(&b.h);
        std::thread::scope(|scope| -> Result<()> {
            let issuance = scope.spawn(|| b.h.engine.handle(&ready[9]));
            entered.recv_timeout(Duration::from_secs(10))?;
            if abort {
                assert_eq!(competing.handle(&abort_request)?["aborted"], true);
            } else {
                b.h.engine
                    .batch_clock
                    .store(b.manifest.expires_at + 1, Ordering::SeqCst);
            }
            resume.send(())?;
            assert!(issuance.join().unwrap().is_err());
            Ok(())
        })?;
        if !abort {
            for member in &b.manifest.members {
                assert!(b.h.snapshot_for(&member.coin)?.0.phase == Phase::Prepared);
            }
            b.h.engine.handle(&abort_request)?;
        }
        assert_old_authority(&b, &old)?;
    }
    Ok(())
}
