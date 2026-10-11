use super::persistence::*;
use super::*;
use crate::freshness::SignerClient;
use anyhow::{Result, ensure};
use bitcoin::{OutPoint, ScriptBuf, Transaction};
use k256::{Scalar, schnorr::SigningKey};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::PathBuf,
};
use zark_protocol::{
    bootstrap::BootstrapBinding,
    certificate::IssuedOriginRecord,
    deposit::DepositBinding,
    handoff::Digest,
    lineage::LineagePolicy,
    proof::PROOF_BYTES,
    random32, scalar,
    wire::{Command, Request},
};
use zeroize::Zeroizing;

use bitcoin::{
    Amount, Sequence, TxIn, TxOut, Witness, absolute::LockTime, hashes::Hash, transaction::Version,
};
use std::cell::{Cell, RefCell};
use zark_protocol::point_bytes;
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("zark-origin-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn policy() -> LineagePolicy {
    let mut roles = [[0; 32]; 6];
    for (i, r) in roles.iter_mut().enumerate() {
        r[31] = (i + 1) as u8;
    }
    LineagePolicy {
        deployment: [19; 32],
        schedule: zark_protocol::handoff::RecoverySchedule {
            initial: 480,
            gap: 60,
            margin: 6,
        },
        origin_key: SigningKey::from_bytes(&[23; 32])
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into(),
        role_hashes: roles,
    }
}
fn point_of(n: u64) -> Vec<u8> {
    point_bytes(k256::ProjectivePoint::GENERATOR * Scalar::from(n))
        .unwrap()
        .to_vec()
}
struct Server {
    first_lost: Cell<bool>,
    allocation_wire: RefCell<Option<Vec<u8>>>,
    prepare_wire: RefCell<Option<Vec<u8>>>,
    nonce: Cell<u64>,
}
impl Server {
    fn new(lost: bool) -> Self {
        Self {
            first_lost: Cell::new(lost),
            allocation_wire: RefCell::new(None),
            prepare_wire: RefCell::new(None),
            nonce: Cell::new(47),
        }
    }
}
impl SignerClient for Server {
    fn request(&self, r: &Request) -> Result<Value> {
        r.authenticate()?;
        match &r.command {
            Command::BootstrapFreeze { statement } => {
                BootstrapBinding::decode(statement)?;
                return Ok(serde_json::json!({"frozen":true,"activation_held":true}));
            }
            Command::Prepare { .. } => {
                return Ok(
                    serde_json::json!({"server_nonce":point_of(59),"draft_server":point_of(41),"server_salt":vec![31u8;32]}),
                );
            }
            _ => {}
        }
        let (saved, response) = match &r.command {
            Command::BootstrapAllocate {} => (
                &self.allocation_wire,
                serde_json::json!({"parent_server":point_of(41),"active_server":point_of(41),"active_server_salt":vec![31u8;32]}),
            ),
            Command::BootstrapPrepare { .. } => (
                &self.prepare_wire,
                serde_json::json!({"parent_nonce":point_of(self.nonce.get())}),
            ),
            _ => anyhow::bail!("test transport received an unauthorized later-stage command"),
        };
        let encoded = r.encode()?.to_vec();
        let previous = saved.borrow().clone();
        if let Some(old) = previous {
            ensure!(old == encoded, "request replay changed");
        } else {
            *saved.borrow_mut() = Some(encoded);
        }
        if self.first_lost.replace(false) {
            anyhow::bail!("synthetic lost response after remote commit");
        }
        Ok(response)
    }
}

#[test]
fn deposit_witness_directly_contains_both_drafts_without_intermediate_proofs() -> Result<()> {
    let home = Home::new();
    let policy = policy();
    let server = Server::new(false);
    let path = home.0.join("single-proof-origin");
    let mut journal = OriginJournal::create(&path, &policy, 100_000, 1000, 1000)?;
    let script = journal.allocate(&server)?;
    journal.bind_funding(&funding(script), 0)?;
    journal.prepare_parent(&server)?;
    assert!(journal.prepare_recovery(&server).is_err());
    journal.freeze_parent(&server)?;
    journal.prepare_recovery(&server)?;
    let witness = home.0.join("deposit.toml");
    journal.write_deposit_witness(&witness)?;
    let saved = fs::read(&witness)?;
    let fields: toml::Value = toml::from_str(std::str::from_utf8(&saved)?)?;
    assert_eq!(
        fields["statement"].as_array().unwrap().len(),
        DepositBinding::ENCODED_LEN
    );
    assert!(
        fields
            .as_table()
            .unwrap()
            .keys()
            .all(|name| !name.ends_with("_proof") && !name.ends_with("_vk"))
    );
    for field in [
        "user",
        "alpha",
        "beta",
        "destination",
        "parent_alpha",
        "parent_beta",
        "parent_txid",
        "activation_fee",
        "initial",
    ] {
        assert!(fields.get(field).is_some(), "missing {field}");
    }
    assert!(!journal.has_issuance_request());
    assert!(
        journal
            .export_recovery(&home.0.join("premature.json"))
            .is_err()
    );
    drop(journal);
    let journal = OriginJournal::open(&path, &policy)?;
    journal.write_deposit_witness(&home.0.join("resumed.toml"))?;
    assert_eq!(saved, fs::read(home.0.join("resumed.toml"))?);
    Ok(())
}
fn funding(script: ScriptBuf) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([11; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1; 64]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: script,
        }],
    }
}

#[test]
fn deposit_request_and_atomic_receipt_reopen_before_acknowledgement() -> Result<()> {
    let home = Home::new();
    let policy = policy();
    let server = Server::new(false);
    let path = home.0.join("issued-origin");
    let mut journal = OriginJournal::create(&path, &policy, 100_000, 1000, 1000)?;
    let script = journal.allocate(&server)?;
    journal.bind_funding(&funding(script), 0)?;
    journal.prepare_parent(&server)?;
    journal.freeze_parent(&server)?;
    journal.prepare_recovery(&server)?;
    let binding = journal.deposit_binding()?;
    // This storage-cut-point fixture does not claim to verify a ZK proof.
    // It exercises reopening the exact frozen request before its response.
    let request = journal.freeze(
        Slot::Issue,
        Command::IssueDeposit {
            statement: binding.encode()?,
            proof: vec![0; PROOF_BYTES],
        },
    )?;
    let saved_request = journal.record.requests.issue.clone();
    drop(journal);
    let mut journal = OriginJournal::open(&path, &policy)?;
    assert_eq!(journal.record.requests.issue, saved_request);
    assert!(journal.record.issued.is_none());

    // Complete both real Bitcoin signatures, then save the atomic issuance
    // receipt without an acknowledgement: this is the next restart boundary.
    let partial: Digest = (Scalar::from(59u64)
        + scalar(&binding.authorization.signing.blinded_challenge)? * Scalar::from(41u64))
    .to_bytes()
    .into();
    let activation_partial: Digest = (Scalar::from(47u64)
        + scalar(&binding.bootstrap.blinded_challenge)? * Scalar::from(41u64))
    .to_bytes()
    .into();
    let mut recovery = journal.ensure_recovery()?;
    recovery.finish(
        &journal.record.context,
        binding.authorization.signing.server_nonce,
        partial,
    )?;
    let activation = journal.ensure_bootstrap()?.finish(
        &journal.record.context,
        binding.bootstrap.parent_nonce,
        activation_partial,
    )?;
    recovery.attach_completed_activation(&activation)?;
    let lineage = journal.lineage_binding(&recovery)?;
    drop(recovery);
    let origin_signature = SigningKey::from_bytes(&[23; 32])?
        .sign_raw(&lineage.origin_message()?, &[0; 32])?
        .to_bytes()
        .to_vec();
    let identity = IssuedOriginRecord::from_request(
        &request,
        &binding,
        partial,
        activation_partial,
        journal.allocation()?.salt,
        lineage.state,
        origin_signature.clone(),
    )?
    .identity()?;
    journal.record.issued = Some(Issued {
        partial,
        binding: binding.digest()?,
        state: lineage.state,
        capability: binding.authorization.signing.next_capability,
        identity,
    });
    journal.record.accepted = Some(Accepted {
        activation_partial,
        activation_binding: binding.bootstrap.digest()?,
        origin_signature,
    });
    journal.persist()?;
    drop(journal);
    let mut journal = OriginJournal::open(&path, &policy)?;
    assert_eq!(journal.record.issued.as_ref().unwrap().identity, identity);
    assert!(!journal.record.acknowledged);
    assert!(journal.record.requests.accept.is_none());
    assert!(journal.record.certificate.is_none());
    journal.require_attached()?;
    journal.record.issued.as_mut().unwrap().identity[0] ^= 1;
    journal.persist()?;
    drop(journal);
    assert!(OriginJournal::open(&path, &policy).is_err());
    Ok(())
}
#[test]
fn keys_and_exact_allocation_survive_lost_response_before_parent_script() -> Result<()> {
    let home = Home::new();
    let p = policy();
    let server = Server::new(true);
    let path = home.0.join("origin");
    let mut j = OriginJournal::create(&path, &p, 100_000, 1000, 1000)?;
    assert_eq!(j.phase(), OriginPhase::AllocatedRequest);
    assert!(j.parent_script().is_err());
    assert!(j.allocate(&server).is_err());
    let context = j.context().clone();
    drop(j);
    let mut j = OriginJournal::open(&path, &p)?;
    assert_eq!(j.context(), &context);
    let script = j.allocate(&server)?;
    assert!(!script.is_empty());
    assert_eq!(j.phase(), OriginPhase::Allocated);
    drop(j);
    let j = OriginJournal::open(&path, &p)?;
    assert_eq!(j.parent_script()?, script);
    assert_eq!(fs::metadata(path.join(FILE))?.mode() & 0o777, 0o600);
    let mut wrong = policy();
    wrong.deployment = [20; 32];
    drop(j);
    assert!(OriginJournal::open(&path, &wrong).is_err());
    Ok(())
}
#[test]
fn external_funding_and_parent_nonce_freeze_before_any_recovery() -> Result<()> {
    let home = Home::new();
    let p = policy();
    let server = Server::new(false);
    let path = home.0.join("origin");
    let mut j = OriginJournal::create(&path, &p, 100_000, 1000, 1000)?;
    let script = j.allocate(&server)?;
    let tx = funding(script);
    let mut unsigned = tx.clone();
    unsigned.input[0].witness = Witness::new();
    assert!(j.bind_funding(&unsigned, 0).is_err());
    let mut wrong = tx.clone();
    wrong.output[0].value = Amount::from_sat(99_999);
    assert!(j.bind_funding(&wrong, 0).is_err());
    j.bind_funding(&tx, 0)?;
    assert_eq!(j.phase(), OriginPhase::FundingFrozen);
    let bound = j.prepare_parent(&server)?.public_inputs()?;
    assert_eq!(j.phase(), OriginPhase::ParentPrepared);
    assert!(j.deposit_public_inputs().is_err());
    assert!(j.export_recovery(&home.0.join("premature.json")).is_err());
    assert!(j.bind_funding(&tx, 0).is_err());
    drop(j);
    let mut j = OriginJournal::open(&path, &p)?;
    assert_eq!(j.prepare_parent(&server)?.public_inputs()?, bound);
    server.nonce.set(53);
    assert!(j.prepare_parent(&server).is_err());
    assert_eq!(j.bootstrap_binding()?.public_inputs()?, bound);
    let mut witness = Zeroizing::new(String::new());
    j.ensure_bootstrap()?
        .append_authorization_witness(&mut witness)?;
    write_private(&home.0.join("bootstrap.toml"), witness.as_bytes())?;
    assert_eq!(
        fs::metadata(home.0.join("bootstrap.toml"))?.mode() & 0o777,
        0o600
    );
    drop(j);
    fs::rename(path.join("activation"), home.0.join("retained-activation"))?;
    assert!(OriginJournal::open(&path, &p).is_err());
    assert!(!path.join("activation").exists());
    fs::rename(home.0.join("retained-activation"), path.join("activation"))?;
    drop(OriginJournal::open(&path, &p)?);
    Ok(())
}
#[test]
fn journal_rejects_skipped_publication_gate_and_linked_private_record() -> Result<()> {
    let home = Home::new();
    let p = policy();
    let path = home.0.join("origin");
    let j = OriginJournal::create(&path, &p, 100_000, 1000, 1000)?;
    drop(j);
    let raw = fs::read(path.join(FILE))?;
    let mut changed: Value = serde_json::from_slice(&raw)?;
    changed["funding_broadcast"] = Value::Bool(true);
    fs::write(path.join(FILE), serde_json::to_vec(&changed)?)?;
    assert!(OriginJournal::open(&path, &p).is_err());
    let mut changed: Value = serde_json::from_slice(&raw)?;
    changed["outgoing"] = serde_json::json!({"kind":"exit","directory":home.0.join("exit"),"staging":home.0.join("stage"),"destination":vec![9u8;32],"fee":1000});
    fs::write(path.join(FILE), serde_json::to_vec(&changed)?)?;
    assert!(OriginJournal::open(&path, &p).is_err());
    fs::write(path.join(FILE), &raw)?;
    fs::hard_link(path.join(FILE), home.0.join("linked.json"))?;
    assert!(OriginJournal::open(&path, &p).is_err());
    Ok(())
}
#[test]
fn prepared_request_must_match_saved_private_commitments_after_lost_response() -> Result<()> {
    let home = Home::new();
    let p = policy();
    let server = Server::new(false);
    let path = home.0.join("origin");
    let mut j = OriginJournal::create(&path, &p, 100_000, 1000, 1000)?;
    let tx = funding(j.allocate(&server)?);
    j.bind_funding(&tx, 0)?;
    server.first_lost.set(true);
    assert!(j.prepare_parent(&server).is_err());
    assert_eq!(j.phase(), OriginPhase::FundingFrozen);
    let original = j.record.requests.prepare.clone().unwrap();
    let Command::BootstrapPrepare {
        parent_funding,
        active_funding,
        capability,
        mut blinding,
    } = j.saved(&original)?.command
    else {
        unreachable!()
    };
    blinding[0] ^= 1;
    // Even a syntactically authentic request must agree with the one local
    // salted draft. This does not model a hostile process with all secrets.
    let changed = j.sign(Command::BootstrapPrepare {
        parent_funding,
        active_funding,
        capability,
        blinding,
    })?;
    j.record.requests.prepare = Some(hex::encode(&*changed.encode()?));
    j.persist()?;
    drop(j);
    assert!(OriginJournal::open(&path, &p).is_err());
    let mut raw: Value = serde_json::from_slice(&fs::read(path.join(FILE))?)?;
    raw["requests"]["prepare"] = Value::String(original);
    fs::write(path.join(FILE), serde_json::to_vec(&raw)?)?;
    let mut j = OriginJournal::open(&path, &p)?;
    j.prepare_parent(&server)?;
    Ok(())
}
