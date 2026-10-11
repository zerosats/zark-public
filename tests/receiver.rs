//! No synthetic proof is treated as valid. These tests qualify durable pending
//! state and fail-closed authorization; actual lineage fixtures qualify later phases.
#[path = "offer.rs"]
mod native_offer;
use k256::{ProjectivePoint, Scalar};
use native_offer::{Home, fixture, unavailable_verifier};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
};
use zark_protocol::point_bytes;
use zark_wallet::{
    envelope::encrypt_offer,
    invitation::InvitationStatus,
    receiver::{ReceiverJournal, ReceiverPhase},
};
use zeroize::Zeroizing;

#[test]
fn pending_offer_keeps_same_recipient_keys_and_binding_across_restart() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    let wire = encrypt_offer(&address, &context, &offer.encode().unwrap()).unwrap();
    let dir = home.0.join("operation");
    let journal =
        ReceiverJournal::prepare(&dir, &invitation, &context, wire.as_bytes(), &policy).unwrap();
    assert_eq!(journal.phase(), ReceiverPhase::PendingOffer);
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    let claim = journal.claim_binding().unwrap().encode().unwrap();
    let saved_context = journal.context().clone();
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let file = dir.join("recipient-operation.json");
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = Zeroizing::new(fs::read(&file).unwrap());
    assert!(ReceiverJournal::open(&dir, &invitation, &context, &policy).is_err());
    assert!(
        ReceiverJournal::prepare(&dir, &invitation, &context, wire.as_bytes(), &policy).is_err()
    );
    drop(journal);
    let reopened = ReceiverJournal::open(&dir, &invitation, &context, &policy).unwrap();
    assert!(reopened.context() == &saved_context);
    assert_eq!(reopened.claim_binding().unwrap().encode().unwrap(), claim);
    assert!(fs::read(&file).unwrap() == *before);
    assert!(reopened.recipient_claim_request().is_err());
    assert!(
        invitation
            .write_receiver_authorization_witness(
                &reopened,
                &unavailable_verifier(&home, &policy),
                &home.0.join("verify"),
                &home.0.join("Claim.toml")
            )
            .is_err()
    );
    assert!(!home.0.join("Claim.toml").exists());
}

#[test]
fn amount_expectation_uses_validated_gross_value_and_does_not_reserve_invitation() {
    let home = Home::new();
    let invitation = home.invitation("amount-receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    let wire = encrypt_offer(&address, &context, &offer.encode().unwrap()).unwrap();
    let dir = home.0.join("amount-operation");
    let journal =
        ReceiverJournal::prepare(&dir, &invitation, &context, wire.as_bytes(), &policy).unwrap();
    let before = Zeroizing::new(fs::read(dir.join("recipient-operation.json")).unwrap());
    // The fixture has 100,000 sats in the parent and 99,000 in recovery backing.
    journal.require_expected_amount(100_000).unwrap();
    for amount in [0, 99_000, 100_001] {
        assert!(journal.require_expected_amount(amount).is_err());
    }
    assert_eq!(journal.phase(), ReceiverPhase::PendingOffer);
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    assert!(journal.recipient_claim_request().is_err());
    assert!(fs::read(dir.join("recipient-operation.json")).unwrap() == *before);
    drop(journal);
    let reopened = ReceiverJournal::open(&dir, &invitation, &context, &policy).unwrap();
    reopened.require_expected_amount(100_000).unwrap();
    assert!(reopened.require_expected_amount(99_000).is_err());
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
}

#[test]
fn unavailable_actual_proof_cannot_authorize_reserve_or_emit_claim_or_draft() {
    let home = Home::new();
    let mut invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    let verifier = unavailable_verifier(&home, &policy);
    let wire = encrypt_offer(&address, &context, &offer.encode().unwrap()).unwrap();
    let dir = home.0.join("operation");
    let mut journal =
        ReceiverJournal::prepare(&dir, &invitation, &context, wire.as_bytes(), &policy).unwrap();
    let before = Zeroizing::new(fs::read(dir.join("recipient-operation.json")).unwrap());
    assert!(
        journal
            .authorize_and_reserve(&mut invitation, &verifier, &home.0.join("verify"))
            .is_err()
    );
    assert_eq!(journal.phase(), ReceiverPhase::PendingOffer);
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    assert!(journal.freeze_claim_request().is_err());
    assert!(
        journal
            .freeze_draft(&json!({"draft_server":
                point_bytes(ProjectivePoint::GENERATOR * Scalar::from(23u64)).unwrap().to_vec(),
                "server_salt": vec![1; 32]}))
            .is_err()
    );
    assert!(fs::read(dir.join("recipient-operation.json")).unwrap() == *before);
}

#[test]
fn corrupt_secret_context_or_offer_cannot_be_reopened_as_valid_state() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    let wire = encrypt_offer(&address, &context, &offer.encode().unwrap()).unwrap();
    let dir = home.0.join("operation");
    let journal =
        ReceiverJournal::prepare(&dir, &invitation, &context, wire.as_bytes(), &policy).unwrap();
    drop(journal);
    let file = dir.join("recipient-operation.json");
    let original: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    for case in 0..13 {
        let mut record = original.clone();
        match case {
            0 => record["version"] = json!(2),
            1 => record["user"] = json!(vec![0; 32]),
            2 => record["capability"] = json!(vec![0; 32]),
            3 => record["session"] = json!(vec![0; 32]),
            4 => record["delta"] = json!(vec![255; 32]),
            5 => record["delta_salt"] = json!(vec![0; 32]),
            6 => record["server_salt"] = json!(vec![0; 32]),
            7 => record["invitation_id"] = json!(vec![0; 32]),
            8 => record["context"]["operation"] = json!(vec![0; 32]),
            9 => record["offer"] = json!("00"),
            10 => record["envelope"] = json!("00"),
            11 => record["stage"]["unknown"] = json!(true),
            12 => record["history"] = json!([]),
            _ => unreachable!(),
        }
        fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            ReceiverJournal::open(&dir, &invitation, &context, &policy).is_err(),
            "record case {case}"
        );
    }
    fs::write(&file, serde_json::to_vec(&original).unwrap()).unwrap();
    let other = home.invitation("other");
    assert!(ReceiverJournal::open(&dir, &other, &context, &policy).is_err());
    let mut other_context = context.clone();
    other_context.coin = [2; 32];
    assert!(ReceiverJournal::open(&dir, &invitation, &other_context, &policy).is_err());
    fs::write(&file, b"{\"stage\":").unwrap();
    assert!(ReceiverJournal::open(&dir, &invitation, &context, &policy).is_err());
}

#[test]
fn saved_authorized_label_does_not_replace_actual_reverification() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    let wire = encrypt_offer(&address, &context, &offer.encode().unwrap()).unwrap();
    let dir = home.0.join("operation");
    let journal =
        ReceiverJournal::prepare(&dir, &invitation, &context, wire.as_bytes(), &policy).unwrap();
    drop(journal);
    let file = dir.join("recipient-operation.json");
    let mut record: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    record["stage"] = json!({"phase":"authorized"});
    fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
    let reopened = ReceiverJournal::open(&dir, &invitation, &context, &policy).unwrap();
    assert_eq!(reopened.phase(), ReceiverPhase::Authorized);
    assert!(reopened.recipient_claim_request().is_err());
    assert!(
        invitation
            .write_receiver_authorization_witness(
                &reopened,
                &unavailable_verifier(&home, &policy),
                &home.0.join("verify"),
                &home.0.join("Claim.toml")
            )
            .is_err()
    );
}

#[test]
fn unsafe_paths_and_interrupted_creation_fail_closed_without_new_keys() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    let wire = encrypt_offer(&address, &context, &offer.encode().unwrap()).unwrap();
    let dir = home.0.join("operation");
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    assert!(
        ReceiverJournal::prepare(&dir, &invitation, &context, wire.as_bytes(), &policy).is_err()
    );
    assert!(ReceiverJournal::open(&dir, &invitation, &context, &policy).is_err());
    fs::remove_dir_all(&dir).unwrap();
    let journal =
        ReceiverJournal::prepare(&dir, &invitation, &context, wire.as_bytes(), &policy).unwrap();
    drop(journal);
    let file = dir.join("recipient-operation.json");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ReceiverJournal::open(&dir, &invitation, &context, &policy).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&file, dir.join("saved.json")).unwrap();
    symlink(dir.join("saved.json"), &file).unwrap();
    assert!(ReceiverJournal::open(&dir, &invitation, &context, &policy).is_err());
}
