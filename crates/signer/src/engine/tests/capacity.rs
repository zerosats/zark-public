//! Capacity fixtures and tests use synthetic transcripts/the test oracle, not ZK.
use super::*;
use rusqlite::{Connection, params};

fn response_count(h: &Harness) -> Result<u64> {
    Ok(Connection::open(&h.engine.db)?.query_row(
        "SELECT count(*) FROM responses WHERE coin=?1",
        [[2u8; 32].as_slice()],
        |r| r.get(0),
    )?)
}

/// Construct compact cancelled-operation transcripts without repeatedly proving
/// fixture reservations. This is storage/state-machine coverage only.
fn fill_responses(h: &Harness, target: u64) -> Result<()> {
    let connection = Connection::open(&h.engine.db)?;
    let (context, key, _, _) = h.transfer_contexts()?;
    for _ in response_count(h)?..target {
        let mut context = context.clone();
        context.operation = random32();
        let request = Request::sign(context.clone(), Command::CancelTransfer {}, &key)?;
        let body = serde_json::to_string(&json!({"cancelled":true,"operation":context.operation}))?;
        connection.execute(
            "INSERT INTO responses VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                context.coin.as_slice(),
                context.operation.as_slice(),
                Purpose::TransferCancellation as u8,
                context.session_auth.as_slice(),
                hash(&[&context.encode()?]).as_slice(),
                request.digest()?.as_slice(),
                body,
                hash(&[body.as_bytes()]).as_slice(),
            ],
        )?;
    }
    Store::open(&h.engine.db, h.engine.config)?.publish(&h.engine.checkpoint)?;
    Ok(())
}

#[test]
fn journal_admission_reserves_transfer_completion_and_exit_at_256() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    fill_responses(&h, 248)?;
    let (s, sk, r, rk) = h.transfer_contexts()?;
    let handover = h.handover(&s, &sk)?;
    h.claim(&r, &rk)?;
    let issue = h.prepare_issue(&r, &rk)?;
    h.gate.0.store(true, Ordering::SeqCst);
    let issued = h.reopen()?.handle(&issue)?;
    h.send(&r, h.acknowledgement(&r)?, &rk)?;
    assert_eq!(response_count(&h)?, 254);
    h.gate.0.store(false, Ordering::SeqCst);
    let (fresh, fresh_key, _, _) = h.transfer_contexts()?;
    let start = h.request(
        &fresh,
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &fresh_key,
    )?;
    let calls = h.oracle.calls.load(Ordering::SeqCst);
    assert!(h.engine.handle(&start).is_err());
    assert_eq!(calls, h.oracle.calls.load(Ordering::SeqCst));
    let (exit_ctx, exit_key, prepare) = h.exit_preparation()?;
    h.engine.handle(&prepare)?;
    let exit = h.exit_issuance(&exit_ctx, &exit_key)?;
    h.gate.0.store(true, Ordering::SeqCst);
    let exit_response = h.reopen()?.handle(&exit)?;
    assert_eq!(response_count(&h)?, 256);
    assert_eq!(issued, h.reopen()?.handle(&issue)?);
    assert_eq!(exit_response, h.reopen()?.handle(&exit)?);
    assert_eq!(h.engine.handle(&handover)?["authorized"], true);
    let retrieve = Request::sign(
        r,
        Command::RetrieveIssued {
            binding_digest: serde_json::from_value(issued["binding_digest"].clone())?,
        },
        &rk,
    )?;
    assert_eq!(issued, h.reopen()?.handle(&retrieve)?);
    assert_eq!(response_count(&h)?, 256);
    Ok(())
}

#[test]
fn cancellation_reuses_capacity_and_cannot_bypass_start_admission() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    fill_responses(&h, 248)?;
    let (s, sk, r, rk) = h.transfer_contexts()?;
    h.handover(&s, &sk)?;
    h.claim(&r, &rk)?;
    let issue = h.prepare_issue(&r, &rk)?;
    assert_eq!(response_count(&h)?, 252);
    h.gate.0.store(true, Ordering::SeqCst);
    let cancel = Request::sign(s, Command::CancelTransfer {}, &sk)?;
    let receipt = h.reopen()?.handle(&cancel)?;
    assert_eq!(response_count(&h)?, 249);
    assert_eq!(receipt, h.reopen()?.handle(&cancel)?);
    assert!(h.engine.handle(&issue).is_err());
    assert_eq!(response_count(&h)?, 249);
    h.gate.0.store(false, Ordering::SeqCst);
    let (fresh, key, _, _) = h.transfer_contexts()?;
    let reserve = h.request(
        &fresh,
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &key,
    )?;
    assert!(h.engine.handle(&reserve).is_err());
    let (exit_ctx, exit_key, prepare) = h.exit_preparation()?;
    h.engine.handle(&prepare)?;
    h.engine.handle(&h.exit_issuance(&exit_ctx, &exit_key)?)?;
    assert!(h.snapshot()?.0.phase == Phase::Terminal);
    Ok(())
}

#[test]
#[ignore = "aggregate storage benchmark; run scripts/check-local.sh capacity-benchmark"]
fn near_limit_storage_measurements() -> Result<()> {
    use std::time::Instant;
    let mut h = Harness::new()?;
    // Retain this fully populated 1,000-coin benchmark at its configured ceiling.
    h.engine.capacity_limits.coins = 1000;
    h.origin()?;
    let template = h.snapshot()?.0;
    let issued = Store::open(&h.engine.db, h.engine.config)?
        .response_for(Purpose::DepositIssuance, &h.origin_context)?
        .unwrap();
    let retrieve = Request::sign(
        h.origin_context.clone(),
        Command::RetrieveIssued {
            binding_digest: serde_json::from_value(issued["binding_digest"].clone())?,
        },
        &h.alice,
    )?;
    // Leave one further transfer's full budget after cancelling the current
    // operation, so completion and exit can also run under aggregate pressure.
    fill_responses(&h, 247)?;
    let (s, sk, r, rk) = h.transfer_contexts()?;
    h.handover(&s, &sk)?;
    h.claim(&r, &rk)?;
    let issue = h.prepare_issue(&r, &rk)?;

    let fixture_started = Instant::now();
    let mut connection = Connection::open(&h.engine.db)?;
    let tx = connection.transaction()?;
    let mut ids = vec![[2; 32]];
    {
        let mut insert_coin = tx.prepare("INSERT INTO coins VALUES(?1,1,?2,?3)")?;
        let mut insert_response =
            tx.prepare("INSERT INTO responses VALUES(?1,?2,20,?3,?4,?5,?6,?7)")?;
        for i in 1u64..1000 {
            let id = hash(&[b"capacity-fixture-coin", &i.to_le_bytes()]);
            ids.push(id);
            let mut coin = template.clone();
            coin.coin = id;
            coin.current_session.coin = id;
            // These synthetic capacity rows do not represent spendable origins;
            // do not reuse another coin's immutable bootstrap receipt.
            coin.bootstrap = None;
            coin.validate(&h.engine.policy)?;
            let body = serde_json::to_string(&coin)?;
            insert_coin.execute(params![
                id.as_slice(),
                body,
                hash(&[body.as_bytes()]).as_slice()
            ])?;
            for j in 0u64..256 {
                let operation = hash(&[b"capacity-fixture-response", &id, &j.to_le_bytes()]);
                let mut context = coin.current_session.clone();
                context.operation = operation;
                let body = serde_json::to_string(&json!({"cancelled":true,"operation":operation}))?;
                insert_response.execute(params![
                    id.as_slice(),
                    operation.as_slice(),
                    context.session_auth.as_slice(),
                    hash(&[&context.encode()?]).as_slice(),
                    hash(&[b"synthetic-request", &operation]).as_slice(),
                    body,
                    hash(&[body.as_bytes()]).as_slice()
                ])?;
            }
        }
        ids.sort();
        let mut insert_batch = tx.prepare("INSERT INTO batches VALUES(?1,?2,?3)")?;
        let mut insert_member = tx.prepare("INSERT INTO batch_members VALUES(?1,?2,?3,?4)")?;
        for i in 0u64..10_000 {
            let id = hash(&[b"capacity-fixture-batch", &i.to_le_bytes()]);
            let members = (0..2)
                .map(|index| BatchMember {
                    coin: ids[index],
                    previous_state: template.state,
                    operation: hash(&[b"capacity-fixture-member", &id, &[index as u8]]),
                    recipient_claim: template.current_session.recipient_claim,
                    sender_session: template.current_session.session_auth,
                    revision: 1,
                })
                .collect();
            let batch = persistence::Batch {
                manifest: BatchManifest {
                    id,
                    deployment: template.deployment,
                    expires_at: batch_now()? + 3600,
                    members,
                },
                joined: vec![true, true],
                phase: BatchPhase::Aborted,
                ready_tip: None,
            };
            let body = serde_json::to_string(&batch)?;
            insert_batch.execute(params![
                id.as_slice(),
                body,
                hash(&[body.as_bytes()]).as_slice()
            ])?;
            for (index, member) in batch.manifest.members.iter().enumerate() {
                insert_member.execute(params![
                    id.as_slice(),
                    member.coin.as_slice(),
                    member.operation.as_slice(),
                    index
                ])?;
            }
        }
    }
    tx.commit()?;
    let store = Store::open(&h.engine.db, h.engine.config)?;
    store.publish(&h.engine.checkpoint)?;
    let fixture_ms = fixture_started.elapsed().as_secs_f64() * 1000.0;
    let restart_started = Instant::now();
    let reopened = h.reopen()?;
    let restart_ms = restart_started.elapsed().as_secs_f64() * 1000.0;
    let mut checkpoint_ms = Vec::new();
    let mut retrieval_ms = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        store.verify_checkpoint(&h.engine.checkpoint)?;
        checkpoint_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        let started = Instant::now();
        assert_eq!(issued, reopened.handle(&retrieve)?);
        retrieval_ms.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    let cancel = Request::sign(s, Command::CancelTransfer {}, &sk)?;
    h.gate.0.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let receipt = reopened.handle(&cancel)?;
    let cancellation_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    assert_eq!(receipt, h.reopen()?.handle(&cancel)?);
    let restart_and_retry_ms = started.elapsed().as_secs_f64() * 1000.0;
    assert!(reopened.handle(&issue).is_err());
    assert_eq!(issued, reopened.handle(&retrieve)?);
    h.gate.0.store(false, Ordering::SeqCst);
    let before_rejections = fs::read(&h.engine.checkpoint)?;
    let mut allocation = h.origin_context.clone();
    allocation.coin = random32();
    allocation.operation = random32();
    allocation.previous_state = origin_previous_state(&allocation.deployment, &allocation.coin)?;
    let allocation = Request::sign(allocation, Command::BootstrapAllocate {}, &h.alice)?;
    assert!(
        reopened
            .handle(&allocation)
            .unwrap_err()
            .to_string()
            .contains("coin capacity")
    );
    let (fresh, fresh_key, next, next_key) = h.transfer_contexts()?;
    let other_id = *ids.iter().find(|id| **id != fresh.coin).unwrap();
    let (other, other_revision) = h.snapshot_for(&other_id)?;
    let mut members = vec![
        BatchMember {
            coin: fresh.coin,
            previous_state: fresh.previous_state,
            operation: fresh.operation,
            recipient_claim: fresh.recipient_claim,
            sender_session: fresh.session_auth,
            revision: h.snapshot()?.1,
        },
        BatchMember {
            coin: other_id,
            previous_state: other.state,
            operation: random32(),
            recipient_claim: random32(),
            sender_session: other.current_session.session_auth,
            revision: other_revision,
        },
    ];
    members.sort_by_key(|member| member.coin);
    let manifest = BatchManifest {
        id: random32(),
        deployment: fresh.deployment,
        expires_at: batch_now()? + 3600,
        members,
    };
    let mut batch_context = fresh.clone();
    batch_context.scope = zark_protocol::handoff::OperationScope::Batch {
        manifest_digest: manifest.digest()?,
    };
    let batch_start = h.request(
        &batch_context,
        Command::BatchReserve {
            manifest,
            owner_authorization: placeholder_owner_authorization(),
        },
        &fresh_key,
    )?;
    assert!(
        reopened
            .handle(&batch_start)
            .unwrap_err()
            .to_string()
            .contains("batch capacity")
    );
    assert_eq!(before_rejections, fs::read(&h.engine.checkpoint)?);
    let completion_started = Instant::now();
    h.handover(&fresh, &fresh_key)?;
    h.claim(&next, &next_key)?;
    let next_issue = h.prepare_issue(&next, &next_key)?;
    h.gate.0.store(true, Ordering::SeqCst);
    h.reopen()?.handle(&next_issue)?;
    h.send(&next, h.acknowledgement(&next)?, &next_key)?;
    assert_eq!(response_count(&h)?, 254);
    let completion_ms = completion_started.elapsed().as_secs_f64() * 1000.0;
    h.gate.0.store(false, Ordering::SeqCst);
    let (exit_context, exit_key, exit_prepare) = h.exit_preparation()?;
    let exit_started = Instant::now();
    reopened.handle(&exit_prepare)?;
    h.gate.0.store(true, Ordering::SeqCst);
    h.reopen()?
        .handle(&h.exit_issuance(&exit_context, &exit_key)?)?;
    let exit_ms = exit_started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(response_count(&h)?, 256);
    assert_eq!(issued, h.reopen()?.handle(&retrieve)?);
    assert_eq!(receipt, h.reopen()?.handle(&cancel)?);
    let database_bytes = fs::metadata(&h.engine.db)?.len();
    // Measure this benchmark process, not cargo/compiler children. macOS uses
    // bytes for ru_maxrss; Linux uses KiB. Includes fixture construction.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0,
        "benchmark resource accounting failed"
    );
    let peak_rss_bytes =
        u64::try_from(usage.ru_maxrss)? * if cfg!(target_os = "macos") { 1 } else { 1024 };
    println!(
        "CAPACITY_MEASUREMENTS {}",
        json!({
            "evidence":"synthetic storage fixture and oracle state machine; no real ZK",
            "profile":if cfg!(debug_assertions) {"debug"} else {"release"},
            "coins":1000,"batches":10000,"initial_response_rows":999*256+251,
            "final_response_rows":1000*256,
            "completion_with_restart_ms":completion_ms,"exit_with_restart_ms":exit_ms,
            "coin_and_batch_limit_rejections":true,
            "fixture_ms":fixture_ms,"restart_ms":restart_ms,"checkpoint_ms":checkpoint_ms,
            "retrieval_ms":retrieval_ms,"cancellation_ms":cancellation_ms,
            "restart_and_cancel_retry_ms":restart_and_retry_ms,"database_bytes":database_bytes,
            "peak_rss_bytes":peak_rss_bytes,
        })
    );
    Ok(())
}

#[test]
fn lowering_capacity_preserves_allocations_retries_and_checkpoint() -> Result<()> {
    let h = Harness::with_test_allocation(false)?;
    let limited = h.reopen()?.with_capacity_limits(CapacityLimits {
        coins: 1,
        batches: 1,
    })?;
    let first = Request::sign(
        h.origin_context.clone(),
        Command::BootstrapAllocate {},
        &h.alice,
    )?;
    let first_response = limited.handle(&first)?;
    let mut context = h.origin_context.clone();
    context.coin = random32();
    context.operation = random32();
    context.previous_state = origin_previous_state(&context.deployment, &context.coin)?;
    let second = Request::sign(context, Command::BootstrapAllocate {}, &h.alice)?;
    let checkpoint = fs::read(&h.engine.checkpoint)?;
    assert_eq!(
        limited.handle(&second).unwrap_err().to_string(),
        "private coin capacity reached"
    );
    assert_eq!(checkpoint, fs::read(&h.engine.checkpoint)?);
    assert_eq!(limited.handle(&first)?, first_response);
    let expanded = h.reopen()?.with_capacity_limits(CapacityLimits {
        coins: 2,
        batches: 1,
    })?;
    let second_response = expanded.handle(&second)?;
    let checkpoint = fs::read(&h.engine.checkpoint)?;
    let lowered = h.reopen()?.with_capacity_limits(CapacityLimits {
        coins: 1,
        batches: 1,
    })?;
    lowered.repair_interrupted_checkpoint()?;
    assert_eq!(lowered.handle(&first)?, first_response);
    assert_eq!(lowered.handle(&second)?, second_response);
    assert_eq!(
        lowered.storage_usage()?,
        json!({"coins":2,"coin_limit":1,
        "batches":0,"batch_limit":1,"near_capacity":true})
    );
    assert_eq!(checkpoint, fs::read(&h.engine.checkpoint)?);
    Ok(())
}

#[test]
fn full_batch_registry_still_joins_completes_and_retrieves_existing_batch() -> Result<()> {
    let mut b = BatchCase::new()?;
    b.h.engine.capacity_limits = CapacityLimits {
        coins: 1,
        batches: 1,
    };
    b.reserve(0)?;
    // A different manifest would create a new registry entry. Its failure must
    // roll back the reservation and response without stranding the old batch.
    let mut new_manifest = b.manifest.clone();
    new_manifest.id = random32();
    for member in &mut new_manifest.members {
        member.operation = random32();
    }
    let mut context = b.senders[1].clone();
    context.operation = new_manifest.members[1].operation;
    context.scope = zark_protocol::handoff::OperationScope::Batch {
        manifest_digest: new_manifest.digest()?,
    };
    let new_batch = b.h.request(
        &context,
        Command::BatchReserve {
            manifest: new_manifest,
            owner_authorization: placeholder_owner_authorization(),
        },
        &b.sender_keys[1],
    )?;
    let checkpoint = fs::read(&b.h.engine.checkpoint)?;
    let coin = serde_json::to_vec(&b.h.snapshot_for(&context.coin)?)?;
    assert_eq!(
        b.h.engine.handle(&new_batch).unwrap_err().to_string(),
        "batch capacity reached"
    );
    assert_eq!(checkpoint, fs::read(&b.h.engine.checkpoint)?);
    assert_eq!(coin, serde_json::to_vec(&b.h.snapshot_for(&context.coin)?)?);
    let ready = b.prepare_both()?;
    assert_eq!(b.h.engine.storage_usage()?["batches"], 1);
    let reopened = b.h.reopen()?;
    assert_eq!(reopened.handle(&ready[0])?["pending"], true);
    let response = reopened.handle(&ready[1])?;
    assert_eq!(response["issued"], true);
    assert_eq!(b.h.reopen()?.handle(&ready[1])?, response);
    Ok(())
}

#[test]
#[ignore = "expanded allocation registry benchmark; synthetic state and test proof oracle only"]
fn expanded_registry_preserves_replay_and_exit() -> Result<()> {
    use std::time::Instant;
    let h = Harness::new()?;
    h.origin()?;
    let template = h.snapshot()?.0;
    let issued = h
        .engine
        .store()?
        .response_for(Purpose::DepositIssuance, &h.origin_context)?
        .unwrap();
    let retrieve = Request::sign(
        h.origin_context.clone(),
        Command::RetrieveIssued {
            binding_digest: serde_json::from_value(issued["binding_digest"].clone())?,
        },
        &h.alice,
    )?;
    let count = CapacityLimits::default().coins;
    let mut connection = Connection::open(&h.engine.db)?;
    let tx = connection.transaction()?;
    // Isolated synthetic rows, without claiming that these are funded coins.
    // Leave one slot to exercise the real atomic allocation insertion path.
    {
        let mut insert = tx.prepare("INSERT INTO coins VALUES(?1,1,?2,?3)")?;
        for i in 1..count - 1 {
            let id = hash(&[b"expanded-capacity-fixture", &i.to_le_bytes()]);
            let mut coin = template.clone();
            coin.coin = id;
            coin.current_session.coin = id;
            coin.bootstrap = None;
            coin.validate(&h.engine.policy)?;
            let body = serde_json::to_string(&coin)?;
            insert.execute(params![
                id.as_slice(),
                body,
                hash(&[body.as_bytes()]).as_slice()
            ])?;
        }
    }
    tx.commit()?;
    h.engine.store()?.publish(&h.engine.checkpoint)?;
    let started = Instant::now();
    let reopened = h.reopen()?;
    let restart_ms = started.elapsed().as_millis();
    let mut context = h.origin_context.clone();
    context.coin = random32();
    context.operation = random32();
    context.previous_state = origin_previous_state(&context.deployment, &context.coin)?;
    let last = Request::sign(context.clone(), Command::BootstrapAllocate {}, &h.alice)?;
    let started = Instant::now();
    let response = reopened.handle(&last)?;
    let allocation_ms = started.elapsed().as_millis();
    assert_eq!(reopened.storage_usage()?["coins"], count);
    context.coin = random32();
    context.operation = random32();
    context.previous_state = origin_previous_state(&context.deployment, &context.coin)?;
    let overflow = Request::sign(context, Command::BootstrapAllocate {}, &h.alice)?;
    let checkpoint = fs::read(&h.engine.checkpoint)?;
    assert_eq!(
        reopened.handle(&overflow).unwrap_err().to_string(),
        "private coin capacity reached"
    );
    assert_eq!(checkpoint, fs::read(&h.engine.checkpoint)?);
    assert_eq!(reopened.handle(&last)?, response);
    let started = Instant::now();
    assert_eq!(reopened.handle(&retrieve)?, issued);
    let retrieval_ms = started.elapsed().as_millis();
    let (ctx, key, prepare) = h.exit_preparation()?;
    reopened.handle(&prepare)?;
    let issue = h.exit_issuance(&ctx, &key)?;
    let exit = reopened.handle(&issue)?;
    assert_eq!(h.reopen()?.handle(&issue)?, exit);
    assert!(h.snapshot()?.0.phase == Phase::Terminal);
    eprintln!(
        "{}",
        json!({"synthetic_registry_coins":count,"database_bytes":fs::metadata(&h.engine.db)?.len(),
        "restart_ms":restart_ms,"allocation_ms":allocation_ms,"retrieval_ms":retrieval_ms})
    );
    Ok(())
}
