//! Durable owner-side joint-parent bootstrap. No external funding transaction
//! is published by this journal before both Bitcoin signatures and the actual
//! initial lineage certificate have been verified and saved.
mod acceptance;
mod funding;
mod issuance;
mod outgoing;
mod persistence;
mod witness;
use persistence::{check_directory, lock, validate};

use anyhow::{Context, Result, ensure};
use bitcoin::{ScriptBuf, Transaction};
use k256::{Scalar, schnorr::SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};
use zark_protocol::{
    handoff::{Digest, TransferContext, origin_previous_state, policy_commitment},
    lineage::LineagePolicy,
    local::ProcessLock,
    random32, scalar,
    wire::{Command, Request},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const FILE: &str = "origin-operation.json";
const LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Allocation {
    parent: Vec<u8>,
    active: Vec<u8>,
    salt: Digest,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Funding {
    raw: String,
    vout: u32,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Issued {
    partial: Digest,
    binding: Digest,
    state: Digest,
    capability: Digest,
    identity: Digest,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Accepted {
    origin_signature: Vec<u8>,
    activation_partial: Digest,
    activation_binding: Digest,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Certificate {
    statement: String,
    proof: String,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Outgoing {
    Transfer {
        directory: String,
        staging: String,
        recipient: String,
    },
    Exit {
        directory: String,
        staging: String,
        destination: Digest,
        fee: u64,
    },
}
#[derive(Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Requests {
    allocate: String,
    prepare: Option<String>,
    authorize: Option<String>,
    recovery: Option<String>,
    issue: Option<String>,
    accept: Option<String>,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    #[zeroize(skip)]
    context: TransferContext,
    policy: Digest,
    origin: Digest,
    roles: [Digest; 6],
    parent_user: Digest,
    active_user: Digest,
    capability: Digest,
    payout: Digest,
    session: Digest,
    amount: u64,
    activation_fee: u64,
    recovery_fee: u64,
    allocation: Option<Allocation>,
    funding: Option<Funding>,
    parent_nonce: Option<Vec<u8>>,
    parent_authorized: bool,
    recovery_nonce: Option<Vec<u8>>,
    issued: Option<Issued>,
    accepted: Option<Accepted>,
    certificate: Option<Certificate>,
    acknowledged: bool,
    funding_broadcast: bool,
    outgoing: Option<Outgoing>,
    requests: Requests,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginPhase {
    AllocatedRequest,
    Allocated,
    FundingFrozen,
    ParentPrepared,
    ParentHeld,
    RecoveryPrepared,
    RecoveryComplete,
    ParentReleased,
    Ready,
    FundingBroadcast,
}
#[derive(Clone, Copy)]
enum Slot {
    Prepare,
    Authorize,
    Recovery,
    Issue,
    Accept,
}

/// Trusted policy comes from the authenticated deployment, not signer responses.
/// Advisory file locks serialize cooperating processes; they are not a sandbox.
pub struct OriginJournal {
    directory: PathBuf,
    record: Record,
    policy: LineagePolicy,
    _lock: ProcessLock,
}

impl OriginJournal {
    pub fn create(
        directory: &Path,
        policy: &LineagePolicy,
        amount: u64,
        activation_fee: u64,
        recovery_fee: u64,
    ) -> Result<Self> {
        policy.validate()?;
        bounds(amount, activation_fee, recovery_fee)?;
        let session = SigningKey::from_bytes(&fresh_scalar())?;
        let coin = nonzero_random();
        let context = TransferContext {
            deployment: policy.deployment,
            coin,
            previous_state: origin_previous_state(&policy.deployment, &coin)?,
            operation: nonzero_random(),
            recipient_claim: nonzero_random(),
            session_auth: session.verifying_key().to_bytes().into(),
            start_revision: 0,
            scope: zark_protocol::handoff::OperationScope::Single,
        };
        let allocate = Request::sign(context.clone(), Command::BootstrapAllocate {}, &session)?;
        let user = fresh_scalar();
        let mut requests = Requests::default();
        requests.allocate = hex::encode(&*allocate.encode()?);
        let record = Record {
            schema: "zark-origin".into(),
            version: 3,
            context,
            policy: policy_commitment(policy.schedule)?,
            origin: policy.origin_key,
            roles: policy.role_hashes,
            parent_user: user,
            active_user: user,
            capability: zark_protocol::owner_auth::generate_secret(),
            payout: fresh_scalar(),
            session: session.to_bytes().into(),
            amount,
            activation_fee,
            recovery_fee,
            allocation: None,
            funding: None,
            parent_nonce: None,
            parent_authorized: false,
            recovery_nonce: None,
            issued: None,
            accepted: None,
            certificate: None,
            acknowledged: false,
            funding_broadcast: false,
            outgoing: None,
            requests,
        };
        validate(&record, policy)?;
        check_directory(directory.parent().context("origin parent")?)?;
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        fs::File::open(directory.parent().unwrap())?.sync_all()?;
        let lock = lock(directory)?;
        let journal = Self {
            directory: directory.into(),
            record,
            policy: policy.clone(),
            _lock: lock,
        };
        journal.persist()?;
        Ok(journal)
    }

    pub fn context(&self) -> &TransferContext {
        &self.record.context
    }
    /// Bind CLI metadata to the existing native journal without changing it.
    pub(crate) fn require_parameters(
        &self,
        amount: u64,
        activation_fee: u64,
        recovery_fee: u64,
    ) -> Result<()> {
        ensure!(
            (
                self.record.amount,
                self.record.activation_fee,
                self.record.recovery_fee
            ) == (amount, activation_fee, recovery_fee),
            "origin metadata differs from native journal parameters"
        );
        Ok(())
    }

    /// Resume hints only; retrieval still verifies the saved request/proof and
    /// exact returned contribution. A saved request does not imply issuance.
    pub fn has_issuance_request(&self) -> bool {
        self.record.requests.issue.is_some()
    }
    pub fn has_acceptance_request(&self) -> bool {
        self.record.requests.accept.is_some()
    }
    pub fn phase(&self) -> OriginPhase {
        if self.record.funding_broadcast {
            OriginPhase::FundingBroadcast
        } else if self.record.certificate.is_some() {
            OriginPhase::Ready
        } else if self.record.accepted.is_some() {
            OriginPhase::ParentReleased
        } else if self.record.issued.is_some() {
            OriginPhase::RecoveryComplete
        } else if self.record.recovery_nonce.is_some() {
            OriginPhase::RecoveryPrepared
        } else if self.record.parent_authorized {
            OriginPhase::ParentHeld
        } else if self.record.parent_nonce.is_some() {
            OriginPhase::ParentPrepared
        } else if self.record.funding.is_some() {
            OriginPhase::FundingFrozen
        } else if self.record.allocation.is_some() {
            OriginPhase::Allocated
        } else {
            OriginPhase::AllocatedRequest
        }
    }
}

fn bounds(amount: u64, activation: u64, recovery: u64) -> Result<()> {
    ensure!(
        amount <= 2_100_000_000_000_000
            && activation > 0
            && activation <= 10000
            && recovery > 0
            && recovery <= 10000
            && amount > activation + recovery + 330,
        "invalid origin amount or fees"
    );
    Ok(())
}
fn check_funding(tx: &Transaction, vout: u32, amount: u64, script: &ScriptBuf) -> Result<()> {
    ensure!(
        !tx.input.is_empty()
            && tx
                .input
                .iter()
                .all(|i| i.script_sig.is_empty() && !i.witness.is_empty()),
        "external funding must be fully signed native-witness inputs"
    );
    let output = tx
        .output
        .get(vout as usize)
        .context("external funding output missing")?;
    ensure!(
        output.value.to_sat() == amount && output.script_pubkey == *script,
        "external funding output mismatch"
    );
    Ok(())
}
fn exact_fields(value: &Value, names: &[&str]) -> Result<()> {
    let map = value.as_object().context("invalid origin response")?;
    ensure!(
        map.len() == names.len() && names.iter().all(|n| map.contains_key(*n)),
        "unexpected origin response fields"
    );
    Ok(())
}
fn response_bytes<const N: usize>(value: &Value, name: &str) -> Result<[u8; N]> {
    let bytes: Vec<u8> = serde_json::from_value(
        value
            .get(name)
            .context("missing origin response field")?
            .clone(),
    )
    .map_err(|_| anyhow::anyhow!("invalid origin response bytes"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("origin response byte length"))
}
fn decode(value: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(value.len() <= max * 2, "oversized origin encoding");
    let bytes = hex::decode(value)?;
    ensure!(hex::encode(&bytes) == value, "noncanonical origin encoding");
    Ok(bytes)
}
fn fresh_scalar() -> Digest {
    loop {
        let value = random32();
        if scalar(&value).is_ok_and(|s| s != Scalar::ZERO) {
            return value;
        }
    }
}
fn nonzero_random() -> Digest {
    loop {
        let value = random32();
        if value != [0; 32] {
            return value;
        }
    }
}
fn field(out: &mut String, name: &str, bytes: &[u8]) -> Result<()> {
    use std::fmt::Write;
    writeln!(out, "{name} = {}", serde_json::to_string(bytes)?)?;
    Ok(())
}
#[cfg(test)]
#[path = "origin/tests.rs"]
mod tests;
