//! Plan C signer authorization and confidentiality properties. Relation checking
//! uses the explicit native test oracle; these tests do not qualify ZK soundness.
use super::*;

fn proposal(h: &Harness, ctx: &TransferContext, session: &SigningKey) -> Result<Request> {
    let coin = h.snapshot_for(&ctx.coin)?.0;
    let handover = HandoverBinding::decode(
        coin.pending
            .as_ref()
            .context("pending")?
            .handover
            .as_ref()
            .context("handover")?,
    )?;
    let delta = number(11);
    let delta_salt = random32();
    let binding = ClaimBinding {
        context: ctx.clone(),
        mask: handover.mask,
        masked_share: handover.masked_share,
        bridge: handover.bridge,
        delta: delta_commitment(ctx, &delta, &delta_salt)?,
        next_capability: h.fresh_capability(&ctx.coin)?,
    };
    Request::sign(
        ctx.clone(),
        Command::ProposeRecipient {
            statement: binding.encode()?,
            token: test_token(ctx),
            delta,
            delta_salt,
        },
        session,
    )
}

#[test]
fn reservation_requires_independent_current_owner_and_exact_revision() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (ctx, session, _, _) = h.transfer_contexts()?;
    let valid = h.request(
        &ctx,
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &session,
    )?;
    let before = fs::read(&h.engine.checkpoint)?;
    let proof_calls = h.oracle.calls.load(Ordering::SeqCst);
    let mut wrong = valid.command.clone();
    if let Command::Reserve {
        owner_authorization,
    } = &mut wrong
    {
        // The current owner's old retry key is not its independent capability.
        *owner_authorization =
            OwnerAuthorization::sign_reservation(&ctx, &h.alice.to_bytes().into())?;
    }
    assert!(
        h.engine
            .handle(&Request::sign(ctx.clone(), wrong, &session)?)
            .is_err()
    );
    let mut changed = ctx.clone();
    changed.start_revision += 1;
    assert!(
        h.engine
            .handle(&Request::sign(changed, valid.command.clone(), &session)?)
            .is_err()
    );
    let mut changed = ctx.clone();
    changed.operation = random32();
    assert!(
        h.engine
            .handle(&Request::sign(changed, valid.command.clone(), &session)?)
            .is_err()
    );
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    let response = h.engine.handle(&valid)?;
    assert_eq!(proof_calls, h.oracle.calls.load(Ordering::SeqCst));
    assert_eq!(response, h.reopen()?.handle(&valid)?);
    Ok(())
}

#[test]
fn token_is_one_session_admission_never_cross_role_cache_authority() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (sender, sender_key, recipient, recipient_key) = h.transfer_contexts()?;
    h.handover(&sender, &sender_key)?;
    let original_share = h.snapshot()?.0.server_secret;
    let request = proposal(&h, &recipient, &recipient_key)?;
    let mut invalid = request.command.clone();
    if let Command::ProposeRecipient { token, .. } = &mut invalid {
        *token = random32();
    }
    let before = fs::read(&h.engine.checkpoint)?;
    assert!(
        h.engine
            .handle(&Request::sign(recipient.clone(), invalid, &recipient_key)?)
            .is_err()
    );
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    let calls = h.oracle.calls.load(Ordering::SeqCst);
    let response = h.engine.handle(&request)?;
    assert_eq!(calls, h.oracle.calls.load(Ordering::SeqCst));
    assert_eq!(response, h.reopen()?.handle(&request)?);
    let issued = h.snapshot()?.0;
    assert!(issued.phase == Phase::RecipientProposed);
    assert_eq!(issued.server_secret, original_share);
    assert!(issued.pending.as_ref().unwrap().nonce_secret.is_none());
    for field in ["delta", "token", "partial", "mask", "request"] {
        assert!(response.get(field).is_none());
    }
    let before = fs::read(&h.engine.checkpoint)?;
    // Sender knows the very same token and masked scalar, but cannot read the
    // actual recipient's tuple or response by presenting another session.
    let sender_attempt = proposal(&h, &sender, &sender_key)?;
    assert!(h.engine.handle(&sender_attempt).is_err());
    let foreign_key = key();
    let mut foreign = recipient.clone();
    foreign.session_auth = pubkey(&foreign_key);
    assert!(
        h.engine
            .handle(&proposal(&h, &foreign, &foreign_key)?)
            .is_err()
    );
    let mut changed = request.command.clone();
    if let Command::ProposeRecipient { delta, .. } = &mut changed {
        *delta = number(12);
    }
    assert!(
        h.engine
            .handle(&Request::sign(recipient.clone(), changed, &recipient_key)?)
            .is_err()
    );
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    assert_eq!(response, h.reopen()?.handle(&request)?);
    Ok(())
}

#[test]
fn competing_token_redemptions_freeze_only_one_session_and_no_signing_response() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (sender, sender_key, recipient, recipient_key) = h.transfer_contexts()?;
    h.handover(&sender, &sender_key)?;
    let first = proposal(&h, &recipient, &recipient_key)?;
    let other_key = key();
    let mut other = recipient.clone();
    other.session_auth = pubkey(&other_key);
    let second = proposal(&h, &other, &other_key)?;
    let barrier = std::sync::Barrier::new(2);
    let (a, b) = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            h.engine.handle(&first)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            h.engine.handle(&second)
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_ne!(a.is_ok(), b.is_ok());
    let winner = if a.is_ok() { &first } else { &second };
    let response = h.reopen()?.handle(winner)?;
    assert!(response.get("partial").is_none());
    let coin = h.snapshot()?.0;
    assert!(coin.phase == Phase::RecipientProposed);
    assert_eq!(
        coin.pending.as_ref().unwrap().recipient.as_ref(),
        Some(&winner.context)
    );
    Ok(())
}

#[test]
fn acknowledgement_binds_exact_issued_record_and_cannot_release_origin() -> Result<()> {
    let h = Harness::new()?;
    let origin_issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    let origin_response = h.engine.handle(&origin_issue)?;
    let origin_state: Digest = serde_json::from_value(origin_response["state"].clone())?;
    let early_ack = Request::sign(
        h.origin_context.clone(),
        Command::AcknowledgeTransfer {
            state: origin_state,
            issuance_identity: random32(),
        },
        &h.alice,
    )?;
    assert!(h.engine.handle(&early_ack).is_err());
    h.send(
        &h.origin_context,
        Command::AcceptOrigin {
            state: [0; 32],
            issuance_identity: [0; 32],
        },
        &h.alice,
    )?;
    let (sender, sender_key, recipient, recipient_key) = h.transfer_contexts()?;
    h.handover(&sender, &sender_key)?;
    h.claim(&recipient, &recipient_key)?;
    let request = h.prepare_issue(&recipient, &recipient_key)?;
    let response = h.engine.handle(&request)?;
    let ack = h.request(&recipient, h.acknowledgement(&recipient)?, &recipient_key)?;
    let before = fs::read(&h.engine.checkpoint)?;
    for state_field in [false, true] {
        let mut changed = ack.command.clone();
        if let Command::AcknowledgeTransfer {
            state,
            issuance_identity,
        } = &mut changed
        {
            if state_field {
                *state = random32();
            } else {
                *issuance_identity = random32();
            }
        }
        assert!(
            h.engine
                .handle(&Request::sign(recipient.clone(), changed, &recipient_key)?)
                .is_err()
        );
    }
    assert!(
        h.engine
            .handle(&Request::sign(
                sender.clone(),
                ack.command.clone(),
                &sender_key
            )?)
            .is_err()
    );
    assert!(
        h.engine
            .handle(&Request::sign(
                recipient.clone(),
                Command::AcceptOrigin {
                    state: [0; 32],
                    issuance_identity: [0; 32]
                },
                &recipient_key
            )?)
            .is_err()
    );
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    let calls = h.oracle.calls.load(Ordering::SeqCst);
    let accepted = h.engine.handle(&ack)?;
    assert_eq!(calls, h.oracle.calls.load(Ordering::SeqCst));
    assert_eq!(accepted, h.reopen()?.handle(&ack)?);
    let (next, next_key, _, _) = h.transfer_contexts()?;
    h.handover(&next, &next_key)?;
    let before = fs::read(&h.engine.checkpoint)?;
    assert_eq!(accepted, h.reopen()?.handle(&ack)?);
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    assert!(h.snapshot()?.0.phase == Phase::Handover);
    let binding_digest: Digest = serde_json::from_value(response["binding_digest"].clone())?;
    let retrieve = Request::sign(
        recipient,
        Command::RetrieveIssued { binding_digest },
        &recipient_key,
    )?;
    assert_eq!(response, h.reopen()?.handle(&retrieve)?);
    Ok(())
}

#[test]
fn predecessor_role_is_bound_to_durable_owner_kind_before_proof_verification() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (sender, sender_key, _, _) = h.transfer_contexts()?;
    let handover = h.handover(&sender, &sender_key)?;
    let mut changed = handover.command.clone();
    if let Command::Handover { predecessor, .. } = &mut changed {
        *predecessor = PredecessorKind::Transfer;
    }
    assert!(
        h.engine
            .handle(&Request::sign(sender, changed, &sender_key)?)
            .is_err()
    );
    let h = Harness::new()?;
    h.origin()?;
    let (exit_context, exit_key, prepare) = h.exit_preparation()?;
    h.engine.handle(&prepare)?;
    let mut exit = h.exit_issuance(&exit_context, &exit_key)?.command;
    if let Command::ExitIssue { predecessor, .. } = &mut exit {
        *predecessor = PredecessorKind::Transfer;
    }
    let calls = h.oracle.calls.load(Ordering::SeqCst);
    assert!(
        h.engine
            .handle(&Request::sign(exit_context, exit, &exit_key)?)
            .is_err()
    );
    assert_eq!(calls, h.oracle.calls.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn signer_refuses_legacy_schemas_even_when_other_metadata_matches() -> Result<()> {
    for version in [9, 10, 11] {
        let h = Harness::new()?;
        rusqlite::Connection::open(&h.engine.db)?.pragma_update(None, "user_version", version)?;
        assert!(h.reopen().is_err());
    }
    Ok(())
}
