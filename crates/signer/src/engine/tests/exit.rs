//! Host lifecycle tests with the enclosing module's explicit test-only oracle.
use super::*;

impl Harness {
    pub(super) fn exit_preparation(&self) -> Result<(TransferContext, SigningKey, Request)> {
        let (coin, revision) = self.snapshot()?;
        let owner = key();
        let operation = random32();
        let context = TransferIntent {
            start_revision: revision,
            scope: zark_protocol::handoff::OperationScope::Single,
            deployment: coin.deployment,
            coin: coin.coin,
            previous_state: coin.state,
            operation,
            recipient_claim: exit_protocol::intent(&coin.deployment, &coin.coin, &operation)?,
        }
        .with_session(pubkey(&owner))?;
        let server_share = ServerShareOpening {
            deployment: coin.deployment,
            coin: coin.coin,
            server: point(coin.server_secret)?.try_into().unwrap(),
            salt: coin.server_salt,
        }
        .commitment()?;
        let request = self.request(
            &context,
            Command::ExitPrepare {
                funding: coin.funding,
                server_share,
                capability: coin.capability,
                exit: random32(),
                blinding: random32(),
                owner_authorization: placeholder_owner_authorization(),
            },
            &owner,
        )?;
        Ok((context, owner, request))
    }
    pub(super) fn exit_issuance(
        &self,
        context: &TransferContext,
        owner: &SigningKey,
    ) -> Result<Request> {
        let (coin, _) = self.snapshot()?;
        let e = coin.exit.as_ref().context("exit")?;
        let draft_server = e.server_point.as_slice().try_into().unwrap();
        let binding = SigningBinding {
            context: context.clone(),
            funding: e.funding,
            refresh_commitment: exit_protocol::share_commitment(
                context,
                &e.funding,
                &draft_server,
            )?,
            previous_capability: e.capability,
            next_capability: exit_protocol::terminal_capability(context)?,
            recovery: e.exit,
            nonce_commitment: e.blinding,
            draft_server,
            server_nonce: e.nonce_point.as_slice().try_into().unwrap(),
            blinded_challenge: number(7),
        };
        let outer = IssuanceBinding {
            signing: binding,
            policy: policy_commitment(self.engine.policy.schedule)?,
            origin_key: self.engine.policy.origin_key,
            role_hashes: self.engine.policy.role_hashes,
        };
        self.request(
            context,
            Command::ExitIssue {
                statement: outer.encode()?,
                predecessor: coin.owner_kind,
                proof: vec![0; PROOF_BYTES],
            },
            owner,
        )
    }
}

#[test]
fn exit_becomes_terminal_before_release_and_exact_retry_survives_restart() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (old, _) = h.snapshot()?;
    let (context, owner, prepare) = h.exit_preparation()?;
    let prepared = h.engine.handle(&prepare)?;
    assert!(prepared.get("server_nonce").is_some());
    assert_eq!(prepared.as_object().unwrap().len(), 1);
    assert_eq!(prepared, h.reopen()?.handle(&prepare)?);
    let issue = h.exit_issuance(&context, &owner)?;
    let response = h.engine.handle(&issue)?;
    assert_eq!(response["terminal"], true);
    assert_eq!(response, h.reopen()?.handle(&issue)?);
    let (coin, _) = h.snapshot()?;
    assert!(coin.phase == Phase::Terminal);
    assert_eq!(coin.server_secret, [0; 32]);
    assert_eq!(coin.state, old.state);
    assert_eq!(
        coin.capability,
        exit_protocol::terminal_capability(&context)?
    );
    assert!(coin.exit.as_ref().unwrap().nonce_secret.is_none());
    assert!(coin.pending.is_none());
    let altered = Request::sign(
        context.clone(),
        Command::Prepare {
            recovery: random32(),
            blinding: random32(),
        },
        &owner,
    )?;
    assert!(h.engine.handle(&altered).is_err());
    let head_query = HeadQuery::fresh(coin.deployment, coin.coin, context.session_auth)?;
    let head_response = h.send(
        &context,
        Command::Head {
            query: head_query.clone(),
        },
        &owner,
    )?;
    let head: Head = serde_json::from_value(head_response["head"].clone())?;
    let sig: Vec<u8> = serde_json::from_value(head_response["signature"].clone())?;
    head.verify(
        &head_query,
        &pubkey(&h.engine.control),
        &sig.try_into().unwrap(),
    )?;
    assert_eq!(head.phase, HeadPhase::Terminal);
    assert_eq!(head_response.as_object().unwrap().len(), 2);
    assert!(head_response.get("partial").is_none());
    assert!(head_response.get("server_nonce").is_none());
    Ok(())
}

#[test]
fn exit_retries_cannot_change_commitments_session_or_proof_kind() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (context, owner, prepare) = h.exit_preparation()?;
    h.engine.handle(&prepare)?;
    let before = fs::read(&h.engine.checkpoint)?;
    let mut changed = prepare.command.clone();
    if let Command::ExitPrepare { exit, .. } = &mut changed {
        *exit = random32();
    }
    assert!(
        h.engine
            .handle(&Request::sign(context.clone(), changed, &owner)?)
            .is_err()
    );
    let issue = h.exit_issuance(&context, &owner)?;
    // Same 964-byte shape is insufficient: the proof must verify under exit VK.
    let mut wrong = issue.command.clone();
    if let Command::ExitIssue { proof, .. } = &mut wrong {
        proof[32..64].copy_from_slice(&role_digest(Relation::ReceiverAuthorization));
    }
    assert!(
        h.engine
            .handle(&Request::sign(context.clone(), wrong, &owner)?)
            .is_err()
    );
    let wrong_owner = key();
    let mut changed_context = context.clone();
    changed_context.session_auth = pubkey(&wrong_owner);
    assert!(
        h.engine
            .handle(&Request::sign(
                changed_context,
                issue.command.clone(),
                &wrong_owner
            )?)
            .is_err()
    );
    if let Command::ExitIssue {
        statement, proof, ..
    } = &issue.command
    {
        assert!(
            h.engine
                .handle(&Request::sign(
                    context.clone(),
                    Command::Issue {
                        statement: statement.clone(),
                        proof: proof.clone()
                    },
                    &owner
                )?)
                .is_err()
        );
    }
    let mut wrong = issue.command.clone();
    if let Command::ExitIssue { statement, .. } = &mut wrong {
        statement[324] ^= 1;
    }
    assert!(
        h.engine
            .handle(&Request::sign(context.clone(), wrong, &owner)?)
            .is_err()
    );
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    h.engine.handle(&issue)?;
    Ok(())
}

#[test]
fn exit_partial_recovery_is_exact_and_role_bound_after_credential_revocation() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (context, owner, prepare) = h.exit_preparation()?;
    h.engine.handle(&prepare)?;
    let issue = h.exit_issuance(&context, &owner)?;
    let response = h.engine.handle(&issue)?;
    let digest = serde_json::from_value(response["binding_digest"].clone())?;
    h.gate.0.store(true, Ordering::SeqCst);
    assert_eq!(response, h.engine.handle(&issue)?);
    let recover = Request::sign(
        context.clone(),
        Command::RetrieveExit {
            binding_digest: digest,
        },
        &owner,
    )?;
    assert_eq!(response, h.reopen()?.handle(&recover)?);
    assert!(
        h.engine
            .handle(&Request::sign(
                context.clone(),
                Command::RetrieveIssued {
                    binding_digest: digest
                },
                &owner
            )?)
            .is_err()
    );
    assert!(
        h.engine
            .handle(&Request::sign(
                context.clone(),
                Command::RetrieveExit {
                    binding_digest: random32()
                },
                &owner
            )?)
            .is_err()
    );
    let attacker = key();
    let mut ctx = context.clone();
    ctx.session_auth = pubkey(&attacker);
    assert!(
        h.engine
            .handle(&Request::sign(
                ctx,
                Command::RetrieveExit {
                    binding_digest: digest
                },
                &attacker
            )?)
            .is_err()
    );
    Ok(())
}

#[test]
fn exit_crashes_never_replace_a_frozen_nonce_or_terminal_partial() -> Result<()> {
    for fault in [
        Fault::AfterVerification,
        Fault::BeforeCommit,
        Fault::AfterCommit,
        Fault::AfterCheckpoint,
    ] {
        let h = Harness::new()?;
        h.origin()?;
        let (context, owner, prepare) = h.exit_preparation()?;
        h.engine.handle(&prepare)?;
        let issue = h.exit_issuance(&context, &owner)?;
        let (coin, _) = h.snapshot()?;
        let nonce = coin.exit.as_ref().unwrap().nonce_secret.unwrap();
        let expected: Digest = (scalar(&nonce)?
            + Scalar::from(7u64) * scalar(&coin.server_secret)?)
        .to_bytes()
        .into();
        *h.engine.fault.lock().unwrap() = Some(fault);
        assert!(h.engine.handle(&issue).is_err());
        if fault == Fault::AfterCommit {
            assert!(h.reopen().is_err());
            assert!(h.engine.handle(&issue).is_err());
            // Explicit repair succeeds after losing the original process too.
            Engine::open_inner(
                &h.engine.db,
                &h.engine.checkpoint,
                h.engine.policy.clone(),
                Proofs::Test(h.oracle.clone()),
                h.gate.clone(),
                h.tip.clone(),
                h.engine.control.clone(),
                h.engine.origin.clone(),
                true,
            )?;
        }
        let response = h.reopen()?.handle(&issue)?;
        assert_eq!(response["partial"], json!(expected));
        assert_eq!(response, h.reopen()?.handle(&issue)?);
        let (coin, _) = h.snapshot()?;
        assert_eq!(coin.server_secret, [0; 32]);
        assert!(coin.exit.as_ref().unwrap().nonce_secret.is_none());
    }
    Ok(())
}

#[test]
fn competing_transfer_reservation_invalidates_authenticated_exit_preparation() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (_, _, prepare) = h.exit_preparation()?;
    let (sender, sender_key, _, _) = h.transfer_contexts()?;
    let transfer = h.request(
        &sender,
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &sender_key,
    )?;
    let competing = h.reopen()?;
    *h.oracle.native_hook.lock().unwrap() = Some(Box::new(move || {
        competing.handle(&transfer)?;
        Ok(())
    }));
    assert!(
        h.engine
            .handle(&prepare)
            .unwrap_err()
            .to_string()
            .contains("stale verified revision")
    );
    let (coin, _) = h.snapshot()?;
    assert!(coin.phase == Phase::Reserved);
    assert!(coin.exit.is_none());
    assert!(h.engine.handle(&prepare).is_err());
    Ok(())
}

#[test]
fn competing_exact_exit_issuances_release_one_terminal_response() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (context, owner, prepare) = h.exit_preparation()?;
    h.engine.handle(&prepare)?;
    let issue = h.exit_issuance(&context, &owner)?;
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
    assert_eq!(h.reopen()?.handle(&issue)?, h.engine.handle(&issue)?);
    Ok(())
}

#[test]
fn exit_context_and_current_commitments_are_checked_before_nonce_or_proof() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (context, owner, prepare) = h.exit_preparation()?;
    let before = fs::read(&h.engine.checkpoint)?;
    let calls = h.oracle.calls.load(Ordering::SeqCst);
    for field in 0..4 {
        let mut ctx = context.clone();
        let mut command = prepare.command.clone();
        if let Command::ExitPrepare {
            funding,
            server_share,
            capability,
            ..
        } = &mut command
        {
            match field {
                0 => *funding = random32(),
                1 => *server_share = random32(),
                2 => *capability = random32(),
                _ => ctx.recipient_claim = random32(),
            }
        }
        assert!(
            h.engine
                .handle(&Request::sign(ctx, command, &owner)?)
                .is_err()
        );
    }
    let misuse = Request::sign(
        context.clone(),
        Command::Reserve {
            owner_authorization: placeholder_owner_authorization(),
        },
        &owner,
    )?;
    assert!(h.engine.handle(&misuse).is_err());
    assert_eq!(calls, h.oracle.calls.load(Ordering::SeqCst));
    assert_eq!(before, fs::read(&h.engine.checkpoint)?);
    h.engine.handle(&prepare)?;
    Ok(())
}

#[test]
fn terminal_state_validation_rejects_restored_secret_or_altered_partial() -> Result<()> {
    let h = Harness::new()?;
    h.origin()?;
    let (context, owner, prepare) = h.exit_preparation()?;
    h.engine.handle(&prepare)?;
    h.engine.handle(&h.exit_issuance(&context, &owner)?)?;
    let (coin, _) = h.snapshot()?;
    let mut changed = coin.clone();
    changed.server_secret = number(1);
    assert!(changed.validate(&h.engine.policy).is_err());
    let mut changed = coin.clone();
    changed.exit.as_mut().unwrap().partial = Some(number(1));
    assert!(changed.validate(&h.engine.policy).is_err());
    let mut changed = coin.clone();
    changed.capability = number(2);
    assert!(changed.validate(&h.engine.policy).is_err());
    let mut changed = coin.clone();
    changed.exit = None;
    assert!(changed.validate(&h.engine.policy).is_err());
    Ok(())
}
