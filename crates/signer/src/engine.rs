//! Durable Zark signer state, revision-bound issuance and exact response replay.
//!
//! Bootstrap generates one share controlling both outputs. One combined deposit
//! proof authorizes atomic activation/recovery release. There is no share-import API. Bitcoin
//! backing and maturity remain honest-client checks, not a signer permission bit.
mod batch;
mod bootstrap;
mod cancellation;
mod persistence;
mod planning;
mod responses;
mod state;
#[cfg(test)]
mod test_allocation;
mod transitions;
mod validation;
mod verification;

#[cfg(test)]
use batch::batch_now;
use state::{Coin, Exit, Pending, Phase};
#[cfg(test)]
use test_allocation::ValidatedAllocation;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, ensure};
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use zark_protocol::{
    batch::Manifest as BatchManifest,
    certificate::{IssuedOriginRecord, IssuedTransferRecord, PredecessorKind},
    deposit::DepositBinding,
    exit as exit_protocol,
    handoff::{
        ClaimBinding, Digest, HandoverBinding, ServerShareOpening, SigningBinding, StateOpening,
        TransferContext, delta_commitment, draft_access_commitment, issuance_commitment,
        mask_commitment, origin_previous_capability, origin_previous_state,
        origin_refresh_commitment, policy_commitment, refresh_commitment,
    },
    hash,
    head::{Head, Phase as HeadPhase},
    lineage::{
        DEPOSIT_AUTHORIZATION, IssuanceBinding, LineageBinding, LineageHandoverBinding,
        LineagePolicy, RECEIVER_AUTHORIZATION,
    },
    point_bytes,
    proof::{PinnedVerifier, Relation},
    random_scalar, random32, scalar,
    session::Purpose,
};
use zeroize::Zeroize;

use persistence::{BatchPhase, Checkpoint, Store};
pub use zark_protocol::wire::{Command, Request};

/// Trusted service admission policy; never selected by the request. This may
/// check credentials, rate limits and queue budgets before expensive proving.
/// Already-admitted continuations and recovery operations do not require an
/// unexpired credential; their frozen state, session and proofs authorize them.
pub trait Admission: Send + Sync {
    fn authorize(&self, context: &TransferContext) -> Result<()>;
}

/// Authenticated view of the active Bitcoin tip. Batch readiness is tied to
/// one tip so a recovery confirmed while peers wait cannot be hidden from the
/// final signer commit. This source must fail closed when the node is stale.
pub trait BatchTip: Send + Sync {
    fn current_tip(&self) -> Result<Digest>;
}

#[allow(
    clippy::large_enum_variant,
    reason = "The bounded verifier is owned directly; the smaller proof oracle exists only in tests"
)]
enum Proofs {
    Real(PinnedVerifier),
    #[cfg(test)]
    Test(tests::Oracle),
}
struct ProofSpec {
    relation: Relation,
    expected: Vec<u8>,
}
struct Seal {
    revision: u64,
    generation: u64,
    request: Digest,
    statement: Option<(Relation, Digest)>,
}

/// No HTTP listener, migration or recovery-chain
/// polling is supplied by this core.
pub struct Engine {
    db: PathBuf,
    checkpoint: PathBuf,
    policy: LineagePolicy,
    config: Digest,
    verifier: Proofs,
    admission: Arc<dyn Admission>,
    batch_tip: Arc<dyn BatchTip>,
    control: SigningKey,
    origin: SigningKey,
    #[cfg(test)]
    fault: std::sync::Mutex<Option<tests::Fault>>,
    #[cfg(test)]
    batch_clock: Arc<std::sync::atomic::AtomicU64>,
}
impl Engine {
    /// Public deployment identity for the isolated mailbox service.
    pub fn deployment(&self) -> Digest {
        self.policy.deployment
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "security-critical signer inputs remain explicit at the open boundary"
    )]
    pub fn open(
        db: &Path,
        checkpoint: &Path,
        policy: LineagePolicy,
        verifier: PinnedVerifier,
        admission: Arc<dyn Admission>,
        batch_tip: Arc<dyn BatchTip>,
        control: SigningKey,
        origin: SigningKey,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            policy,
            Proofs::Real(verifier),
            admission,
            batch_tip,
            control,
            origin,
            false,
        )
    }

    /// Explicit operator recovery after inspecting an interrupted DB-commit /
    /// checkpoint-publication gap. Refuses missing floors, rollback, and more
    /// than one unpublished commit. Ordinary startup never calls this method.
    #[allow(
        clippy::too_many_arguments,
        reason = "security-critical signer inputs remain explicit at the repair boundary"
    )]
    pub fn repair_and_open(
        db: &Path,
        checkpoint: &Path,
        policy: LineagePolicy,
        verifier: PinnedVerifier,
        admission: Arc<dyn Admission>,
        batch_tip: Arc<dyn BatchTip>,
        control: SigningKey,
        origin: SigningKey,
    ) -> Result<Self> {
        Self::open_inner(
            db,
            checkpoint,
            policy,
            Proofs::Real(verifier),
            admission,
            batch_tip,
            control,
            origin,
            true,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Opening explicitly binds both persistence paths, proof/admission policies, separate keys and repair mode"
    )]
    fn open_inner(
        db: &Path,
        checkpoint: &Path,
        policy: LineagePolicy,
        verifier: Proofs,
        admission: Arc<dyn Admission>,
        batch_tip: Arc<dyn BatchTip>,
        control: SigningKey,
        origin: SigningKey,
        repair: bool,
    ) -> Result<Self> {
        policy.validate()?;
        if repair {
            ensure!(
                db.is_file() && checkpoint.is_file(),
                "explicit repair requires existing database and checkpoint"
            );
        }
        let origin_public: Digest = origin.verifying_key().to_bytes().into();
        ensure!(
            origin_public == policy.origin_key,
            "origin signing key does not match pinned policy"
        );
        let control_public: Digest = control.verifying_key().to_bytes().into();
        ensure!(
            control_public != origin_public,
            "head and origin signing keys must be separate"
        );
        let mut pins = Vec::new();
        for value in &policy.role_hashes {
            pins.extend(value);
        }
        let config = hash(&[
            b"ZARK/private-engine/config/v1",
            &policy.deployment,
            &policy_commitment(policy.schedule)?,
            &origin_public,
            &control_public,
            &pins,
        ]);
        let engine = Self {
            db: db.into(),
            checkpoint: checkpoint.into(),
            policy,
            config,
            verifier,
            admission,
            batch_tip,
            control,
            origin,
            #[cfg(test)]
            fault: std::sync::Mutex::new(None),
            #[cfg(test)]
            batch_clock: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        let _lock = persistence::lock(&engine.db, &engine.checkpoint)?;
        let store = Store::open(&engine.db, engine.config)?;
        store.validate(&engine.policy)?;
        if repair {
            store.repair_checkpoint(&engine.checkpoint)?;
        }
        store.verify_checkpoint(&engine.checkpoint)?;
        Ok(engine)
    }

    /// Repairs only one explicitly inspected interrupted checkpoint publication.
    /// Requests never repair a mismatch automatically or roll authority backward.
    pub fn repair_interrupted_checkpoint(&self) -> Result<()> {
        let _lock = persistence::lock(&self.db, &self.checkpoint)?;
        let store = Store::open(&self.db, self.config)?;
        store.validate(&self.policy)?;
        store.repair_checkpoint(&self.checkpoint)
    }

    pub fn handle(&self, request: &Request) -> Result<Value> {
        self.handle_guarded(request, || Ok(()))
    }

    /// Hosted callers bind credential/deadline checks to this exact request.
    /// Credential expiry may exempt admitted continuations and recovery, but
    /// bounded request deadlines and session authentication still apply.
    pub fn handle_guarded(
        &self,
        request: &Request,
        guard: impl Fn() -> Result<()>,
    ) -> Result<Value> {
        let _timing =
            zark_protocol::timing::Span::new(zark_protocol::timing::Phase::SignerProcessing);
        let digest = request.authenticate()?;
        guard()?;
        ensure!(
            request.context.deployment == self.policy.deployment,
            "request deployment mismatch"
        );
        if matches!(request.command, Command::CancelTransfer {}) {
            return self.cancel_transfer(request, digest, &guard);
        }
        if let Command::BatchReady { manifest, .. } = &request.command {
            return self.batch_ready(request, manifest, digest, &guard);
        }
        if let Command::BatchAbort { manifest } = &request.command {
            return self.batch_abort(request, manifest, &guard);
        }
        let new_activity = matches!(
            request.command,
            Command::BootstrapAllocate {}
                | Command::Reserve { .. }
                | Command::BatchReserve { .. }
                | Command::ExitPrepare { .. }
        );
        if new_activity {
            self.admission.authorize(&request.context)?;
        }
        let (coin, revision, generation, spec) = {
            let _timing =
                zark_protocol::timing::Span::new(zark_protocol::timing::Phase::SignerPlan);
            let _lock = persistence::lock_guarded(&self.db, &self.checkpoint, &guard)?;
            let store = Store::open(&self.db, self.config)?;
            let floor = store.verify_checkpoint(&self.checkpoint)?;
            let saved = store.coin(&request.context.coin)?;
            if saved.is_none() && matches!(request.command, Command::BootstrapAllocate {}) {
                let mut store = store;
                return self.allocate_bootstrap(&mut store, &floor, request, digest, &guard);
            }
            let (coin, revision) = saved.context("unknown private coin")?;
            coin.validate(&self.policy)?;
            guard()?;
            ensure!(
                !store.operation_cancelled(&request.context.coin, &request.context.operation)?,
                "transfer was cancelled"
            );
            if let Some(id) =
                store.batch_for_operation(&request.context.coin, &request.context.operation)?
            {
                let batch = store.batch(&id)?.context("missing batch")?;
                ensure!(batch.phase != BatchPhase::Aborted, "batch was aborted");
            }
            if let Some(response) = self.read_response(&store, &coin, revision, &floor, request)? {
                return Ok(response);
            }
            if let Some(response) = store.replay(request, digest)? {
                return Ok(response);
            }
            store.admit_operation(request)?;
            if matches!(
                request.command,
                Command::Reserve { .. }
                    | Command::BatchReserve { .. }
                    | Command::ExitPrepare { .. }
            ) {
                ensure!(
                    request.context.start_revision == revision,
                    "start authorization has stale revision"
                );
                ensure!(
                    !store.operation_exists(&request.context.coin, &request.context.operation)?,
                    "operation was already used"
                );
            }
            if let Command::BatchReserve { manifest, .. } = &request.command {
                self.check_batch_reserve(&store, manifest, request, revision)?;
            }
            if matches!(
                request.command,
                Command::Handover { .. }
                    | Command::ProposeRecipient { .. }
                    | Command::Prepare { .. }
            ) {
                self.check_batch_step(&store, &coin)?;
            }
            let spec = self.plan(&coin, request)?;
            (coin, revision, floor.generation, spec)
        };
        let seal = Seal {
            revision,
            generation,
            request: digest,
            statement: spec.as_ref().map(|s| (s.relation, hash(&[&s.expected]))),
        };
        if let Some(spec) = &spec {
            let _timing =
                zark_protocol::timing::Span::new(zark_protocol::timing::Phase::SignerVerification);
            self.verify(
                spec,
                request.command.proof().context("missing relation proof")?,
                &|| {
                    guard()?;
                    if new_activity {
                        self.admission.authorize(&request.context)?;
                    }
                    Ok(())
                },
            )?;
        }
        #[cfg(test)]
        if spec.is_none()
            && let Proofs::Test(oracle) = &self.verifier
        {
            oracle.after_native_authorization()?;
        }
        drop(coin);
        #[cfg(test)]
        self.trip(tests::Fault::AfterVerification)?;
        let _timing = zark_protocol::timing::Span::new(zark_protocol::timing::Phase::SignerCommit);
        let _lock = persistence::lock_guarded(&self.db, &self.checkpoint, &guard)?;
        let mut store = Store::open(&self.db, self.config)?;
        let floor = store.verify_checkpoint(&self.checkpoint)?;
        let (current, current_revision) = store
            .coin(&request.context.coin)?
            .context("coin disappeared")?;
        ensure!(
            current_revision == seal.revision && floor.generation == seal.generation,
            "stale verified revision; retry exact request"
        );
        ensure!(
            request.authenticate()? == seal.request,
            "verified request changed"
        );
        if new_activity {
            self.admission.authorize(&request.context)?;
        }
        if matches!(
            request.command,
            Command::Reserve { .. } | Command::BatchReserve { .. } | Command::ExitPrepare { .. }
        ) {
            ensure!(
                request.context.start_revision == current_revision,
                "start authorization has stale revision"
            );
        }
        let current_spec = self.plan(&current, request)?;
        if let Command::BatchReserve { manifest, .. } = &request.command {
            self.check_batch_reserve(&store, manifest, request, current_revision)?;
        }
        if matches!(
            request.command,
            Command::Handover { .. } | Command::ProposeRecipient { .. } | Command::Prepare { .. }
        ) {
            self.check_batch_step(&store, &current)?;
        }
        ensure!(
            current_spec
                .as_ref()
                .map(|s| (s.relation, hash(&[&s.expected])))
                == seal.statement,
            "verified statement changed"
        );
        let (next, response, purge_mask) = self.apply(current, request)?;
        next.validate(&self.policy)?;
        #[cfg(test)]
        self.trip(tests::Fault::BeforeCommit)?;
        guard()?;
        store.commit(
            &next,
            current_revision,
            request,
            digest,
            &response,
            purge_mask,
            &floor,
            match &request.command {
                Command::BatchReserve { manifest, .. } => {
                    Some((manifest, manifest.index(&request.context, true)?))
                }
                _ => None,
            },
        )?;
        #[cfg(test)]
        self.trip(tests::Fault::AfterCommit)?;
        store.publish(&self.checkpoint)?;
        #[cfg(test)]
        self.trip(tests::Fault::AfterCheckpoint)?;
        Ok(response)
    }
}

fn nonzero(value: Digest) -> Result<()> {
    ensure!(value != [0; 32], "zero private protocol field");
    Ok(())
}

fn nonzero_random() -> Digest {
    loop {
        let value = random32();
        if value != [0; 32] {
            return value;
        }
    }
}
fn point(secret: Digest) -> Result<Vec<u8>> {
    Ok(point_bytes(ProjectivePoint::GENERATOR * scalar(&secret)?)?.to_vec())
}
fn sender(p: &Pending, ctx: &TransferContext) -> Result<()> {
    ensure!(
        p.sender.as_ref() == Some(ctx),
        "sender session or intent mismatch"
    );
    Ok(())
}
fn recipient(p: &Pending, ctx: &TransferContext) -> Result<()> {
    ensure!(
        p.recipient.as_ref() == Some(ctx),
        "recipient session or intent mismatch"
    );
    Ok(())
}
