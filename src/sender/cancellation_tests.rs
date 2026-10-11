//! Synthetic native journals only. The lineage bytes are deliberately not ZK
//! proofs; these tests never invoke a prover or pinned proof verifier.
use super::*;
use crate::{freshness::SignerClient, recovery::RecoveryDraft, types::Input};
use anyhow::{Result, ensure};
use bitcoin::consensus::serialize;
use k256::schnorr::SigningKey;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    batch::Manifest as BatchManifest,
    certificate::{OwnerCertificate, PredecessorKind},
    handoff::{
        Digest, RecoveryDelay, TransferContext, capability_commitment, recipient_claim_commitment,
    },
    lineage::{LineageBinding, LineagePolicy},
    owner_auth::OwnerAuthorization,
    random32,
    wire::{Command, Request},
};

use crate::{
    bitcoin::{activation, attach_signature, sighash},
    recovery::RecoveryParameters,
    signing::{Blinding, FundingKey},
};
use bitcoin::{OutPoint, Txid, hashes::Hash};
use k256::{ProjectivePoint, Scalar};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use zark_protocol::{
    handoff::{RecoverySchedule, policy_commitment},
    point_bytes,
    proof::PROOF_BYTES,
    scalar,
};

struct Home(PathBuf);
impl Home {
    fn new() -> Result<Self> {
        let root =
            std::env::temp_dir().join(format!("zark-cancel-journal-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        Ok(Self(root))
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn number(n: u64) -> Digest {
    Scalar::from(n).to_bytes().into()
}
fn point(n: u64) -> Result<[u8; 64]> {
    point_bytes(ProjectivePoint::GENERATOR * Scalar::from(n))
}
fn key(n: u64) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(&number(n))?)
}

fn fixture(home: &Home) -> Result<SenderDraft> {
    let deployment = [9; 32];
    let coin = [8; 32];
    let capability = key(43)?.to_bytes().into();
    let policy = LineagePolicy {
        deployment,
        schedule: RecoverySchedule {
            initial: 480,
            gap: 60,
            margin: 6,
        },
        origin_key: key(53)?.verifying_key().to_bytes().into(),
        role_hashes: std::array::from_fn(|i| number(i as u64 + 1)),
    };
    let recovery_context = TransferContext {
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment,
        coin,
        previous_state: [7; 32],
        operation: [6; 32],
        recipient_claim: [5; 32],
        session_auth: key(41)?.verifying_key().to_bytes().into(),
    };
    let deposit = FundingKey::new(
        ProjectivePoint::GENERATOR * Scalar::from(21u64),
        Scalar::from(31u64),
    )?;
    let active = FundingKey::new(
        ProjectivePoint::GENERATOR * Scalar::from(23u64),
        Scalar::from(7u64),
    )?;
    let parent = Input {
        deployment: hex::encode(deployment),
        id: hex::encode([10; 32]),
        funding_salt: hex::encode([11; 32]),
        internal_point: hex::encode(point_bytes(deposit.internal)?),
        txid: Txid::from_byte_array([12; 32]).to_string(),
        vout: 0,
        amount: 100_000,
    };
    let mut tx = activation(
        OutPoint::new(Txid::from_byte_array([12; 32]), 0),
        100_000,
        &[(99_000, active.xonly()?)],
        0,
    )?;
    let blind = Blinding::default();
    let server = ProjectivePoint::GENERATOR * Scalar::from(21u64);
    let nonce = ProjectivePoint::GENERATOR * Scalar::from(17u64);
    let session = blind.bind(
        &deposit,
        server,
        nonce,
        sighash(&tx, 100_000, deposit.xonly()?)?,
    )?;
    let signature = blind.finish(
        &deposit,
        &session,
        server,
        nonce,
        Scalar::from(17u64) + session.challenge * Scalar::from(21u64),
    )?;
    attach_signature(&mut tx, 100_000, deposit.xonly()?, &signature)?;
    let backing = Input {
        deployment: hex::encode(deployment),
        id: hex::encode(coin),
        funding_salt: hex::encode([19; 32]),
        internal_point: hex::encode(point_bytes(active.internal)?),
        txid: tx.compute_txid().to_string(),
        vout: 0,
        amount: 99_000,
    };
    let recovery_path = home.0.join("owner-recovery");
    let mut recovery = RecoveryDraft::create(
        &recovery_path,
        RecoveryParameters {
            context: recovery_context.clone(),
            backing: backing.clone(),
            activation_input: parent.clone(),
            activation: tx.clone(),
            draft_server: point(23)?,
            refresh_commitment: [20; 32],
            previous_capability: [21; 32],
            next_capability: capability_commitment(&deployment, &coin, &capability)?,
            schedule: policy.schedule,
            previous_delay: RecoveryDelay::from_sequence(480)?,
            next_delay: RecoveryDelay::from_sequence(420)?,
            fee: 1000,
        },
        &number(7),
        &number(37),
    )?;
    let binding = recovery.bind_server_nonce(&recovery_context, point(29)?)?;
    let partial = Scalar::from(29u64) + scalar(&binding.blinded_challenge)? * Scalar::from(23u64);
    recovery.finish(&recovery_context, point(29)?, partial.to_bytes().into())?;
    let state = recovery.own_state(&[31; 32], policy_commitment(policy.schedule)?)?;
    let cert = LineageBinding {
        deployment,
        coin,
        funding: state.funding,
        state: state.commitment()?,
        policy: state.policy,
        origin_key: policy.origin_key,
        role_hashes: policy.role_hashes,
    };
    let compressed = |n| -> Result<[u8; 33]> {
        let mut bytes = [2; 33];
        bytes[1..].copy_from_slice(&key(n)?.verifying_key().to_bytes());
        Ok(bytes)
    };
    let recipient = ReceivingAddress::new(
        AddressNetwork::Test,
        deployment,
        compressed(59)?,
        compressed(61)?,
    )?;
    let sender = key(67)?;
    let context = TransferContext {
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment,
        coin,
        previous_state: cert.state,
        operation: [70; 32],
        recipient_claim: recipient_claim_commitment(
            &deployment,
            &coin,
            &[70; 32],
            &recipient.claim_key()[1..].try_into()?,
            &[71; 32],
        )?,
        session_auth: sender.verifying_key().to_bytes().into(),
    };
    let reservation = Request::sign(
        context.clone(),
        Command::Reserve {
            owner_authorization: OwnerAuthorization::sign_reservation(&context, &capability)?,
        },
        &sender,
    )?;
    let masked = recovery.masked_user(&number(73))?;
    drop(recovery);
    let directory = home.0.join("sender");
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let mut draft = SenderDraft {
        _lock: lock(&directory)?,
        directory,
        policy,
        record: Record {
            schema: "zark-sender-operation".into(),
            version: 3,
            context,
            recovery_context,
            recovery_path,
            backing,
            activation_input: parent,
            activation: hex::encode(serialize(&tx)),
            certificate: hex::encode(
                &*OwnerCertificate::TransferIssued {
                    authorization: zark_protocol::lineage::IssuanceBinding {
                        signing: binding,
                        policy: cert.policy,
                        origin_key: cert.origin_key,
                        role_hashes: cert.role_hashes,
                    }
                    .encode()?,
                    proof: vec![0; PROOF_BYTES],
                    partial: partial.to_bytes().into(),
                    server_salt: [31; 32],
                }
                .encode_private()?,
            ),
            server_salt: [31; 32],
            capability,
            token: [80; 32],
            session: sender.to_bytes().into(),
            recipient: recipient.encode(),
            claim_salt: [71; 32],
            masked_salt: [74; 32],
            bridge_salt: [75; 32],
            reservation: Some(hex::encode(&*reservation.encode()?)),
            batch: None,
            mask: Some(Mask {
                mask: number(73),
                salt: [76; 32],
                masked,
            }),
            handover: None,
            offer: None,
            offer_digest: None,
            completion: None,
            cancellation: None,
            retired: false,
            aborted: false,
        },
    };
    let handover = draft.handover_binding_unchecked(&draft.recovery()?)?;
    let request = Request::sign(
        draft.record.context.clone(),
        Command::Handover {
            predecessor: PredecessorKind::Transfer,
            statement: handover.encode()?,
            proof: vec![0; PROOF_BYTES],
        },
        &sender,
    )?;
    draft.record.handover = Some(hex::encode(&*request.encode()?));
    let offer = b"synthetic ciphertext cache, not a peer offer";
    draft.record.offer = Some(hex::encode(offer));
    draft.record.offer_digest = Some(saved_offer_digest(&draft.record.context, offer)?);
    let complete = Request::sign(
        draft.record.context.clone(),
        Command::CompleteSender {},
        &sender,
    )?;
    draft.record.completion = Some(hex::encode(&*complete.encode()?));
    draft.persist()?;
    Ok(draft)
}

struct Server {
    lose: Cell<bool>,
    wire: RefCell<Option<Vec<u8>>>,
    response: Option<Value>,
}
impl Server {
    fn new(lose: bool) -> Self {
        Self {
            lose: Cell::new(lose),
            wire: RefCell::new(None),
            response: None,
        }
    }
}
impl SignerClient for Server {
    fn request(&self, request: &Request) -> Result<Value> {
        request.authenticate()?;
        ensure!(
            matches!(request.command, Command::CancelTransfer {}),
            "unexpected test command"
        );
        let bytes = request.encode()?.to_vec();
        let mut wire = self.wire.borrow_mut();
        if let Some(previous) = wire.as_ref() {
            ensure!(*previous == bytes, "cancellation retry changed");
        } else {
            *wire = Some(bytes);
        }
        if self.lose.replace(false) {
            anyhow::bail!("synthetic loss after signer cancellation committed");
        }
        Ok(self
            .response
            .clone()
            .unwrap_or_else(|| json!({"cancelled":true,"operation":request.context.operation})))
    }
}

#[test]
fn cancellation_survives_lost_reply_cleans_pending_material_and_preserves_recovery() -> Result<()> {
    let home = Home::new()?;
    let mut draft = fixture(&home)?;
    let policy = draft.policy.clone();
    let directory = draft.directory.clone();
    let recovery_path = draft.record.recovery_path.join("recovery-draft.json");
    let recovery_bytes = fs::read(&recovery_path)?;
    let server = Server::new(true);
    assert!(draft.cancel_transfer(&server).is_err());
    assert!(draft.record.cancellation.is_some());
    assert!(!draft.is_aborted());
    let journal_bytes = fs::read(directory.join(FILE))?;
    drop(draft);
    let mut draft = SenderDraft::open(&directory, &policy)?;
    assert_eq!(journal_bytes, fs::read(directory.join(FILE))?);
    draft.cancel_transfer(&server)?;
    drop(draft);
    let mut draft = SenderDraft::open(&directory, &policy)?;
    assert!(draft.is_aborted());
    assert!(!draft.record.retired);
    assert!(draft.record.mask.is_none());
    assert!(draft.record.reservation.is_none());
    assert!(draft.record.handover.is_none());
    assert!(draft.record.offer.is_none());
    assert!(draft.record.offer_digest.is_none());
    assert!(draft.record.completion.is_none());
    assert!(draft.offer_bytes().is_err());
    assert!(draft.complete(&server).is_err());
    draft.cancel_transfer(&server)?;
    assert_eq!(recovery_bytes, fs::read(recovery_path)?);
    draft.recovery()?.completed_transaction()?;
    Ok(())
}

#[test]
fn wrong_or_malformed_receipts_do_not_cancel_local_journal() -> Result<()> {
    let home = Home::new()?;
    let mut draft = fixture(&home)?;
    for response in [
        json!({"cancelled":true,"operation":vec![99;32]}),
        json!({"cancelled":false,"operation":draft.context().operation}),
        json!({"cancelled":true}),
        json!({"cancelled":true,"operation":draft.context().operation,"extra":true}),
    ] {
        let mut server = Server::new(false);
        server.response = Some(response);
        assert!(draft.cancel_transfer(&server).is_err());
        assert!(!draft.is_aborted());
        let persisted: Record = serde_json::from_slice(&fs::read(draft.directory.join(FILE))?)?;
        assert!(!persisted.aborted && persisted.mask.is_some() && persisted.offer.is_some());
    }
    Ok(())
}

#[test]
fn batch_and_retired_senders_never_send_ordinary_cancellation() -> Result<()> {
    let home = Home::new()?;
    let mut draft = fixture(&home)?;
    let server = Server::new(false);
    draft.record.retired = true;
    draft.persist()?;
    assert!(draft.cancel_transfer(&server).is_err());
    assert!(server.wire.borrow().is_none());
    draft.record.retired = false;
    // The rejection precedes manifest processing; use a synthetic batch marker.
    let member = zark_protocol::batch::Member {
        coin: draft.context().coin,
        previous_state: draft.context().previous_state,
        operation: draft.context().operation,
        recipient_claim: draft.context().recipient_claim,
        sender_session: draft.context().session_auth,
        revision: 1,
    };
    let mut other = member.clone();
    other.coin = [99; 32];
    other.operation = [98; 32];
    draft.record.batch = Some(BatchManifest {
        id: [90; 32],
        deployment: draft.context().deployment,
        expires_at: 1,
        members: vec![member, other],
    });
    assert!(draft.cancel_transfer(&server).is_err());
    assert!(server.wire.borrow().is_none());
    Ok(())
}

#[test]
fn saved_session_signature_cannot_replace_owner_or_predecessor_authority() -> Result<()> {
    for wrong_predecessor in [false, true] {
        let home = Home::new()?;
        let mut draft = fixture(&home)?;
        let context = draft.context().clone();
        let command = if wrong_predecessor {
            Command::Handover {
                predecessor: PredecessorKind::Origin,
                statement: draft
                    .handover_binding_unchecked(&draft.recovery()?)?
                    .encode()?,
                proof: vec![0; PROOF_BYTES],
            }
        } else {
            Command::Reserve {
                owner_authorization: OwnerAuthorization::sign_reservation(
                    &context,
                    &key(79)?.to_bytes().into(),
                )?,
            }
        };
        let request = Request::sign(
            context,
            command,
            &SigningKey::from_bytes(&draft.record.session)?,
        )?;
        let encoded = hex::encode(&*request.encode()?);
        if wrong_predecessor {
            draft.record.handover = Some(encoded);
        } else {
            draft.record.reservation = Some(encoded);
        }
        assert!(draft.validate().is_err());
    }
    Ok(())
}
