//! Batch fixtures and durable commit/abort scenarios.
use super::{
    BatchManifest, BatchMember, Command, Fault, HandoverBinding, Harness, LineageHandoverBinding,
    Ordering, PROOF_BYTES, Phase, PredecessorKind, Request, Result, ServerShareOpening, SigningKey,
    Store, TransferContext, Value, batch_now, draft_access_commitment, ensure,
    placeholder_owner_authorization, point, policy_commitment, random32, test_token,
};

pub(super) struct BatchCase {
    pub(super) h: Harness,
    pub(super) manifest: BatchManifest,
    pub(super) senders: Vec<TransferContext>,
    pub(super) sender_keys: Vec<SigningKey>,
    pub(super) recipients: Vec<TransferContext>,
    pub(super) recipient_keys: Vec<SigningKey>,
}
impl BatchCase {
    pub(super) fn new() -> Result<Self> {
        Self::with_count(2)
    }
    pub(super) fn with_count(count: usize) -> Result<Self> {
        ensure!(
            (2..=zark_protocol::batch::MAX_BATCH_MEMBERS).contains(&count),
            "test batch count"
        );
        let h = Harness::new()?;
        h.origin()?;
        let mut senders = Vec::new();
        let mut sender_keys = Vec::new();
        let mut recipients = Vec::new();
        let mut recipient_keys = Vec::new();
        let mut members = Vec::new();
        for index in 0..count {
            let coin = [2 + 20 * index as u8; 32];
            if index > 0 {
                h.extra_origin(coin)?;
            }
            let (sender, sender_key, recipient, recipient_key) = h.transfer_contexts_for(&coin)?;
            members.push(BatchMember {
                coin,
                previous_state: sender.previous_state,
                operation: sender.operation,
                recipient_claim: sender.recipient_claim,
                sender_session: sender.session_auth,
                revision: h.snapshot_for(&coin)?.1,
            });
            senders.push(sender);
            sender_keys.push(sender_key);
            recipients.push(recipient);
            recipient_keys.push(recipient_key);
        }
        let manifest = BatchManifest {
            id: random32(),
            deployment: h.engine.policy.deployment,
            expires_at: batch_now()? + 3600,
            members,
        };
        manifest.validate()?;
        for ctx in senders.iter_mut().chain(recipients.iter_mut()) {
            ctx.scope = zark_protocol::handoff::OperationScope::Batch {
                manifest_digest: manifest.digest()?,
            };
        }
        Ok(Self {
            h,
            manifest,
            senders,
            sender_keys,
            recipients,
            recipient_keys,
        })
    }
    pub(super) fn reserve(&self, i: usize) -> Result<Value> {
        self.h.send(
            &self.senders[i],
            Command::BatchReserve {
                manifest: self.manifest.clone(),
                owner_authorization: placeholder_owner_authorization(),
            },
            &self.sender_keys[i],
        )
    }
    pub(super) fn handover(&self, i: usize) -> Result<()> {
        let ctx = &self.senders[i];
        let (coin, _) = self.h.snapshot_for(&ctx.coin)?;
        let p = coin.pending.as_ref().unwrap();
        let outer = LineageHandoverBinding {
            handover: HandoverBinding {
                intent: ctx.intent(),
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
                policy: policy_commitment(self.h.engine.policy.schedule)?,
                draft_access: draft_access_commitment(&ctx.intent(), &test_token(ctx))?,
            },
            origin_key: self.h.engine.policy.origin_key,
            role_hashes: self.h.engine.policy.role_hashes,
        };
        self.h.send(
            ctx,
            Command::Handover {
                statement: outer.encode()?,
                predecessor: PredecessorKind::Origin,
                proof: vec![0; PROOF_BYTES],
            },
            &self.sender_keys[i],
        )?;
        Ok(())
    }
    pub(super) fn ready_request(&self, i: usize) -> Result<Request> {
        self.h.prepare_issue_as(
            &self.recipients[i],
            &self.recipient_keys[i],
            Some(&self.manifest),
        )
    }
    pub(super) fn prepare_both(&self) -> Result<[Request; 2]> {
        self.reserve(0)?;
        self.reserve(1)?;
        for i in 0..2 {
            self.handover(i)?;
            self.h.claim(&self.recipients[i], &self.recipient_keys[i])?;
        }
        Ok([self.ready_request(0)?, self.ready_request(1)?])
    }
    pub(super) fn prepare_all(&self) -> Result<Vec<Request>> {
        // Deliberately join and prepare in a different order from the manifest.
        for i in (0..self.senders.len()).rev() {
            self.reserve(i)?;
        }
        let mut requests = Vec::new();
        for i in 0..self.senders.len() {
            self.handover(i)?;
            self.h.claim(&self.recipients[i], &self.recipient_keys[i])?;
            requests.push(self.ready_request(i)?);
        }
        Ok(requests)
    }
}

#[test]
fn two_coin_batch_commits_both_or_neither_and_retrieves_separately() -> Result<()> {
    let b = BatchCase::new()?;
    let old = [
        b.h.snapshot_for(&[2; 32])?.0.state,
        b.h.snapshot_for(&[22; 32])?.0.state,
    ];
    let reserve0 = b.h.request(
        &b.senders[0],
        Command::BatchReserve {
            manifest: b.manifest.clone(),
            owner_authorization: placeholder_owner_authorization(),
        },
        &b.sender_keys[0],
    )?;
    b.h.engine.handle(&reserve0)?;
    assert!(b.handover(0).is_err());
    assert_eq!(b.h.snapshot_for(&[2; 32])?.0.state, old[0]);
    b.reserve(1)?;
    for i in 0..2 {
        b.handover(i)?;
        b.h.claim(&b.recipients[i], &b.recipient_keys[i])?;
    }
    assert!(b.h.engine.handle(&reserve0)?.get("mask").is_none());
    let ready = [b.ready_request(0)?, b.ready_request(1)?];
    if let Command::BatchReady {
        statement, proof, ..
    } = ready[0].command.clone()
    {
        let ordinary = Request::sign(
            b.recipients[0].clone(),
            Command::Issue { statement, proof },
            &b.recipient_keys[0],
        )?;
        assert!(b.h.engine.handle(&ordinary).is_err());
    }
    let mut invalid = ready[1].clone();
    if let Command::BatchReady { proof, .. } = &mut invalid.command {
        proof[0] ^= 1;
    }
    invalid = Request::sign(invalid.context, invalid.command, &b.recipient_keys[1])?;
    assert_eq!(b.h.engine.handle(&ready[0])?["pending"], true);
    assert!(b.h.engine.handle(&invalid).is_err());
    let mut altered = ready[1].clone();
    if let Command::BatchReady { manifest, .. } = &mut altered.command {
        manifest.members[0].recipient_claim = random32();
    }
    altered = Request::sign(altered.context, altered.command, &b.recipient_keys[1])?;
    assert!(b.h.engine.handle(&altered).is_err());
    assert_eq!(b.h.snapshot_for(&[2; 32])?.0.state, old[0]);
    assert_eq!(b.h.snapshot_for(&[22; 32])?.0.state, old[1]);
    let released = b.h.engine.handle(&ready[1])?;
    assert_eq!(released["issued"], true);
    let responses = [
        b.h.reopen()?.handle(&ready[0])?,
        b.h.reopen()?.handle(&ready[1])?,
    ];
    b.h.gate.0.store(true, Ordering::SeqCst);
    let late_abort = Request::sign(
        b.senders[0].clone(),
        Command::BatchAbort {
            manifest: b.manifest.clone(),
        },
        &b.sender_keys[0],
    )?;
    assert!(b.h.engine.handle(&late_abort).is_err());
    for (i, id) in [[2; 32], [22; 32]].iter().enumerate() {
        let (coin, _) = b.h.snapshot_for(id)?;
        assert!(coin.phase == Phase::Issued);
        assert_ne!(coin.state, old[i]);
        let response = &responses[i];
        let binding = serde_json::from_value(response["binding_digest"].clone())?;
        let retrieve = Request::sign(
            b.recipients[i].clone(),
            Command::RetrieveIssued {
                binding_digest: binding,
            },
            &b.recipient_keys[i],
        )?;
        assert_eq!(*response, b.h.reopen()?.handle(&retrieve)?);
    }
    Ok(())
}

#[test]
fn batch_abort_tombstones_precommit_requests_and_restores_authority() -> Result<()> {
    let b = BatchCase::new()?;
    let old = b.h.snapshot_for(&[2; 32])?.0.state;
    let reserve = b.h.request(
        &b.senders[0],
        Command::BatchReserve {
            manifest: b.manifest.clone(),
            owner_authorization: placeholder_owner_authorization(),
        },
        &b.sender_keys[0],
    )?;
    b.h.engine.handle(&reserve)?;
    b.h.gate.0.store(true, Ordering::SeqCst);
    let abort = Request::sign(
        b.senders[0].clone(),
        Command::BatchAbort {
            manifest: b.manifest.clone(),
        },
        &b.sender_keys[0],
    )?;
    assert_eq!(b.h.engine.handle(&abort)?["aborted"], true);
    assert_eq!(b.h.reopen()?.handle(&abort)?["aborted"], true);
    b.h.gate.0.store(false, Ordering::SeqCst);
    let (coin, _) = b.h.snapshot_for(&[2; 32])?;
    assert!(coin.phase == Phase::Accepted);
    assert_eq!(coin.state, old);
    assert!(b.h.engine.handle(&reserve).is_err());
    assert!(b.reserve(1).is_err());
    Ok(())
}

#[test]
fn batch_abort_after_one_ready_erases_pending_proof_without_issuance() -> Result<()> {
    let b = BatchCase::new()?;
    let ready = b.prepare_both()?;
    let old = [
        b.h.snapshot_for(&[2; 32])?.0.state,
        b.h.snapshot_for(&[22; 32])?.0.state,
    ];
    assert_eq!(b.h.engine.handle(&ready[0])?["pending"], true);
    let abort = Request::sign(
        b.senders[1].clone(),
        Command::BatchAbort {
            manifest: b.manifest.clone(),
        },
        &b.sender_keys[1],
    )?;
    b.h.engine.handle(&abort)?;
    for (i, id) in [[2; 32], [22; 32]].iter().enumerate() {
        let (coin, _) = b.h.snapshot_for(id)?;
        assert!(coin.phase == Phase::Accepted);
        assert_eq!(coin.state, old[i]);
        assert!(b.h.engine.handle(&ready[i]).is_err());
        assert!(
            Store::open(&b.h.engine.db, b.h.engine.config)?
                .ready(&b.manifest.id, id)?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn batch_commit_checkpoint_gap_fails_closed_until_repair() -> Result<()> {
    let b = BatchCase::new()?;
    let ready = b.prepare_both()?;
    b.h.engine.handle(&ready[0])?;
    *b.h.engine.fault.lock().unwrap() = Some(Fault::AfterCommit);
    assert!(b.h.engine.handle(&ready[1]).is_err());
    assert!(b.h.reopen().is_err());
    b.h.engine.repair_interrupted_checkpoint()?;
    for request in &ready {
        assert_eq!(b.h.reopen()?.handle(request)?["issued"], true);
    }
    Ok(())
}

#[test]
fn batch_abort_checkpoint_gap_restores_both_or_pauses_service() -> Result<()> {
    let b = BatchCase::new()?;
    b.reserve(0)?;
    b.reserve(1)?;
    let abort = Request::sign(
        b.senders[0].clone(),
        Command::BatchAbort {
            manifest: b.manifest.clone(),
        },
        &b.sender_keys[0],
    )?;
    *b.h.engine.fault.lock().unwrap() = Some(Fault::AfterCommit);
    assert!(b.h.engine.handle(&abort).is_err());
    assert!(b.h.reopen().is_err());
    b.h.engine.repair_interrupted_checkpoint()?;
    assert_eq!(b.h.reopen()?.handle(&abort)?["aborted"], true);
    for id in [[2; 32], [22; 32]] {
        assert!(b.h.snapshot_for(&id)?.0.phase == Phase::Accepted);
    }
    Ok(())
}
