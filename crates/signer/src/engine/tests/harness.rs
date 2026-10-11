//! Synthetic owner/journal fixtures shared by lifecycle, adversarial and crash scenarios.
use super::{
    Arc, BTreeMap, BatchManifest, ClaimBinding, Coin, Command, Context, DepositBinding, Digest,
    Engine, Gate, HandoverBinding, IssuanceBinding, LineageHandoverBinding, LineagePolicy, Mutex,
    Oracle, OwnerAuthorization, OwnerAuthorizationPayload, PROOF_BYTES, PathBuf, Proofs,
    RecoverySchedule, Request, Result, ServerShareOpening, SigningBinding, SigningKey, Store,
    TestTip, TransferContext, TransferIntent, ValidatedAllocation, Value, delta_commitment,
    draft_access_commitment, fs, hash, key, number, origin_previous_capability,
    origin_previous_state, origin_refresh_commitment, placeholder_owner_authorization, point,
    policy_commitment, pubkey, public_capability_commitment, random32, refresh_commitment,
    role_digest, test_token,
};

pub(super) struct Harness {
    pub(super) root: PathBuf,
    pub(super) engine: Engine,
    pub(super) gate: Arc<Gate>,
    pub(super) tip: Arc<TestTip>,
    pub(super) oracle: Oracle,
    pub(super) alice: SigningKey,
    pub(super) initial_capability: Digest,
    pub(super) origin_context: TransferContext,
    pub(super) owner_keys: Mutex<BTreeMap<Digest, SigningKey>>,
    pub(super) owner_authorizations: Mutex<BTreeMap<Digest, OwnerAuthorization>>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
impl Harness {
    pub(super) fn new() -> Result<Self> {
        Self::with_test_allocation(true)
    }
    pub(super) fn with_test_allocation(seed: bool) -> Result<Self> {
        let root = std::env::temp_dir().join(format!("zark-core-{}", hex::encode(random32())));
        let origin = key();
        let control = key();
        let alice = key();
        let owner_key = key();
        let initial_capability =
            public_capability_commitment(&[1; 32], &[2; 32], &pubkey(&owner_key))?;
        let gate = Arc::new(Gate::default());
        let tip = Arc::new(TestTip::new());
        let oracle = Oracle::default();
        let policy = LineagePolicy {
            deployment: [1; 32],
            schedule: RecoverySchedule {
                initial: 480,
                gap: 60,
                margin: 6,
            },
            origin_key: pubkey(&origin),
            role_hashes: std::array::from_fn(|i| number(i as u64 + 1)),
        };
        let engine = Engine::open_inner(
            &root.join("db/state.sqlite"),
            &root.join("floor/checkpoint.json"),
            policy,
            Proofs::Test(oracle.clone()),
            gate.clone(),
            tip.clone(),
            control,
            origin,
            false,
        )?;
        let origin_context = TransferIntent {
            start_revision: 0,
            scope: zark_protocol::handoff::OperationScope::Single,
            deployment: [1; 32],
            coin: [2; 32],
            previous_state: origin_previous_state(&[1; 32], &[2; 32])?,
            operation: [3; 32],
            recipient_claim: [4; 32],
        }
        .with_session(pubkey(&alice))?;
        if seed {
            engine.install_validated_allocation(ValidatedAllocation {
                context: origin_context.clone(),
                funding: [5; 32],
                capability: initial_capability,
                server_secret: number(99),
            })?;
        }
        Ok(Self {
            root,
            engine,
            gate,
            tip,
            oracle,
            alice,
            initial_capability,
            origin_context,
            owner_keys: Mutex::new(BTreeMap::from([(initial_capability, owner_key)])),
            owner_authorizations: Mutex::new(BTreeMap::new()),
        })
    }
    pub(super) fn reopen(&self) -> Result<Engine> {
        Engine::open_inner(
            &self.engine.db,
            &self.engine.checkpoint,
            self.engine.policy.clone(),
            Proofs::Test(self.oracle.clone()),
            self.gate.clone(),
            self.tip.clone(),
            self.engine.control.clone(),
            self.engine.origin.clone(),
            false,
        )
    }
    pub(super) fn snapshot(&self) -> Result<(Coin, u64)> {
        self.snapshot_for(&[2; 32])
    }
    pub(super) fn snapshot_for(&self, id: &Digest) -> Result<(Coin, u64)> {
        Store::open(&self.engine.db, self.engine.config)?
            .coin(id)?
            .context("coin")
    }
    pub(super) fn fresh_capability(&self, coin: &Digest) -> Result<Digest> {
        let owner = key();
        let capability =
            public_capability_commitment(&self.engine.policy.deployment, coin, &pubkey(&owner))?;
        self.owner_keys.lock().unwrap().insert(capability, owner);
        Ok(capability)
    }
    pub(super) fn acknowledgement(&self, ctx: &TransferContext) -> Result<Command> {
        let coin = self.snapshot_for(&ctx.coin)?.0;
        let record = coin
            .pending
            .as_ref()
            .context("pending")?
            .issued_transfer
            .as_ref()
            .context("issued")?;
        Ok(Command::AcknowledgeTransfer {
            state: coin.state,
            issuance_identity: record.identity()?,
        })
    }
    pub(super) fn request(
        &self,
        ctx: &TransferContext,
        mut command: Command,
        key: &SigningKey,
    ) -> Result<Request> {
        match &mut command {
            Command::AcceptOrigin {
                state,
                issuance_identity,
            } if *state == [0; 32] && *issuance_identity == [0; 32] => {
                let coin = self.snapshot_for(&ctx.coin)?.0;
                *state = coin.state;
                *issuance_identity = coin
                    .pending
                    .as_ref()
                    .context("origin pending")?
                    .issued_origin
                    .as_ref()
                    .context("issued origin")?
                    .identity()?;
            }
            Command::Reserve {
                owner_authorization,
            }
            | Command::BatchReserve {
                owner_authorization,
                ..
            } => {
                let coin = self.snapshot_for(&ctx.coin)?.0;
                let keys = self.owner_keys.lock().unwrap();
                let owner = keys.get(&coin.capability).context("test owner key")?;
                let digest = OwnerAuthorizationPayload::reservation(ctx)?.digest()?;
                let mut saved = self.owner_authorizations.lock().unwrap();
                *owner_authorization = saved
                    .entry(digest)
                    .or_insert(OwnerAuthorization::sign_reservation(
                        ctx,
                        &owner.to_bytes().into(),
                    )?)
                    .clone();
            }
            Command::ExitPrepare {
                owner_authorization,
                funding,
                server_share,
                exit,
                blinding,
                ..
            } => {
                let coin = self.snapshot_for(&ctx.coin)?.0;
                let keys = self.owner_keys.lock().unwrap();
                let owner = keys.get(&coin.capability).context("test owner key")?;
                let digest =
                    OwnerAuthorizationPayload::exit(ctx, funding, server_share, exit, blinding)?
                        .digest()?;
                let mut saved = self.owner_authorizations.lock().unwrap();
                *owner_authorization = saved
                    .entry(digest)
                    .or_insert(OwnerAuthorization::sign_exit(
                        ctx,
                        funding,
                        server_share,
                        exit,
                        blinding,
                        &owner.to_bytes().into(),
                    )?)
                    .clone();
            }
            _ => {}
        }
        let mut request = Request::sign(ctx.clone(), command.clone(), key)?;
        if command.proof().is_some() {
            let (coin, _) = self.snapshot_for(&ctx.coin)?;
            let spec = self.engine.plan(&coin, &request)?.context("spec")?;
            let mut proof = vec![0; PROOF_BYTES];
            proof[..32].copy_from_slice(&hash(&[&spec.expected]));
            proof[32..64].copy_from_slice(&role_digest(spec.relation));
            match &mut command {
                Command::BatchReady { proof: p, .. }
                | Command::Handover { proof: p, .. }
                | Command::Issue { proof: p, .. }
                | Command::ExitIssue { proof: p, .. }
                | Command::IssueDeposit { proof: p, .. } => *p = proof,
                _ => unreachable!(),
            }
            request = Request::sign(ctx.clone(), command, key)?;
        }
        Ok(request)
    }
    pub(super) fn send(
        &self,
        ctx: &TransferContext,
        command: Command,
        key: &SigningKey,
    ) -> Result<Value> {
        self.engine.handle(&self.request(ctx, command, key)?)
    }
    pub(super) fn prepare_issue(&self, ctx: &TransferContext, key: &SigningKey) -> Result<Request> {
        self.prepare_issue_as(ctx, key, None)
    }
    pub(super) fn prepare_issue_as(
        &self,
        ctx: &TransferContext,
        key: &SigningKey,
        batch: Option<&BatchManifest>,
    ) -> Result<Request> {
        self.send(
            ctx,
            Command::Prepare {
                recovery: random32(),
                blinding: random32(),
            },
            key,
        )?;
        let (coin, _) = self.snapshot_for(&ctx.coin)?;
        let p = coin.pending.as_ref().unwrap();
        let draft = if p.origin {
            coin.server_secret
        } else {
            p.draft_secret.unwrap()
        };
        let draft_server = point(draft)?.try_into().unwrap();
        let (previous, next, refresh) = if p.origin {
            (
                origin_previous_capability(&coin.deployment, &coin.coin)?,
                coin.capability,
                origin_refresh_commitment(ctx, &coin.funding, &draft_server)?,
            )
        } else {
            let h = HandoverBinding::decode(p.handover.as_ref().unwrap())?;
            let c = ClaimBinding::decode(p.claim.as_ref().unwrap())?;
            (
                coin.capability,
                c.next_capability,
                refresh_commitment(
                    ctx,
                    &h.mask,
                    &h.masked_share,
                    &h.bridge,
                    &c.delta,
                    &draft_server,
                )?,
            )
        };
        let outer = IssuanceBinding {
            signing: SigningBinding {
                context: ctx.clone(),
                funding: coin.funding,
                refresh_commitment: refresh,
                previous_capability: previous,
                next_capability: next,
                recovery: p.recovery.unwrap(),
                nonce_commitment: p.blinding.unwrap(),
                draft_server,
                server_nonce: p.nonce_point.clone().unwrap().try_into().unwrap(),
                blinded_challenge: number(7),
            },
            policy: policy_commitment(self.engine.policy.schedule)?,
            origin_key: self.engine.policy.origin_key,
            role_hashes: self.engine.policy.role_hashes,
        };
        let statement = outer.encode()?;
        let command = if let Some(manifest) = batch {
            Command::BatchReady {
                manifest: manifest.clone(),
                observed_tip: [42; 32],
                statement,
                proof: vec![0; PROOF_BYTES],
            }
        } else if p.origin {
            Command::IssueDeposit {
                statement: DepositBinding {
                    authorization: outer,
                    bootstrap: zark_protocol::bootstrap::BootstrapBinding::decode(
                        &coin.bootstrap.as_ref().unwrap().binding_bytes()?,
                    )?,
                }
                .encode()?,
                proof: vec![0; PROOF_BYTES],
            }
        } else {
            Command::Issue {
                statement,
                proof: vec![0; PROOF_BYTES],
            }
        };
        self.request(ctx, command, key)
    }
    pub(super) fn origin(&self) -> Result<()> {
        let req = self.prepare_issue(&self.origin_context, &self.alice)?;
        self.engine.handle(&req)?;
        self.send(
            &self.origin_context,
            Command::AcceptOrigin {
                state: [0; 32],
                issuance_identity: [0; 32],
            },
            &self.alice,
        )?;
        Ok(())
    }
    pub(super) fn extra_origin(&self, coin: Digest) -> Result<(TransferContext, SigningKey)> {
        let owner = key();
        let context = TransferIntent {
            start_revision: 0,
            scope: zark_protocol::handoff::OperationScope::Single,
            deployment: self.engine.policy.deployment,
            coin,
            previous_state: origin_previous_state(&self.engine.policy.deployment, &coin)?,
            operation: random32(),
            recipient_claim: random32(),
        }
        .with_session(pubkey(&owner))?;
        self.engine
            .install_validated_allocation(ValidatedAllocation {
                context: context.clone(),
                funding: [23; 32],
                capability: self.fresh_capability(&coin)?,
                server_secret: number(101),
            })?;
        let issue = self.prepare_issue(&context, &owner)?;
        self.engine.handle(&issue)?;
        self.send(
            &context,
            Command::AcceptOrigin {
                state: [0; 32],
                issuance_identity: [0; 32],
            },
            &owner,
        )?;
        Ok((context, owner))
    }
    pub(super) fn transfer_contexts_for(
        &self,
        id: &Digest,
    ) -> Result<(TransferContext, SigningKey, TransferContext, SigningKey)> {
        let sender_key = key();
        let recipient_key = key();
        let (coin, revision) = self.snapshot_for(id)?;
        let intent = TransferIntent {
            start_revision: revision,
            scope: zark_protocol::handoff::OperationScope::Single,
            deployment: coin.deployment,
            coin: coin.coin,
            previous_state: coin.state,
            operation: random32(),
            recipient_claim: random32(),
        };
        Ok((
            intent.with_session(pubkey(&sender_key))?,
            sender_key,
            intent.with_session(pubkey(&recipient_key))?,
            recipient_key,
        ))
    }
    pub(super) fn transfer_contexts(
        &self,
    ) -> Result<(TransferContext, SigningKey, TransferContext, SigningKey)> {
        self.transfer_contexts_for(&[2; 32])
    }
    pub(super) fn handover(&self, ctx: &TransferContext, key: &SigningKey) -> Result<Request> {
        self.send(
            ctx,
            Command::Reserve {
                owner_authorization: placeholder_owner_authorization(),
            },
            key,
        )?;
        let (coin, _) = self.snapshot_for(&ctx.coin)?;
        let p = coin.pending.as_ref().unwrap();
        let h = HandoverBinding {
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
            policy: policy_commitment(self.engine.policy.schedule)?,
            draft_access: draft_access_commitment(&ctx.intent(), &test_token(ctx))?,
        };
        let outer = LineageHandoverBinding {
            handover: h,
            origin_key: self.engine.policy.origin_key,
            role_hashes: self.engine.policy.role_hashes,
        };
        let req = self.request(
            ctx,
            Command::Handover {
                statement: outer.encode()?,
                predecessor: coin.owner_kind,
                proof: vec![0; PROOF_BYTES],
            },
            key,
        )?;
        self.engine.handle(&req)?;
        Ok(req)
    }
    pub(super) fn claim(&self, ctx: &TransferContext, key: &SigningKey) -> Result<Request> {
        let (coin, _) = self.snapshot_for(&ctx.coin)?;
        let p = coin.pending.as_ref().unwrap();
        let h = HandoverBinding::decode(p.handover.as_ref().unwrap())?;
        let delta = number(11);
        let delta_salt = random32();
        let claim = ClaimBinding {
            context: ctx.clone(),
            mask: h.mask,
            masked_share: h.masked_share,
            bridge: h.bridge,
            delta: delta_commitment(ctx, &delta, &delta_salt)?,
            next_capability: self.fresh_capability(&ctx.coin)?,
        };
        let req = self.request(
            ctx,
            Command::ProposeRecipient {
                statement: claim.encode()?,
                token: test_token(ctx),
                delta,
                delta_salt,
            },
            key,
        )?;
        self.engine.handle(&req)?;
        Ok(req)
    }
}
