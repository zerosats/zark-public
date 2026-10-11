//! Synthetic local storage only; no wallet, signer, node, or proving tools.
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};
use zark_protocol::{address::AddressNetwork, local::ProcessLock, random32};
use zark_wallet::invitation::{
    InvitationStatus, LocalInvitation, MAX_OFFER_BYTES, ReservationResult,
};

const DEPLOYMENT: [u8; 32] = [23; 32];
const COIN: [u8; 32] = [41; 32];
const OPERATION: [u8; 32] = [42; 32];

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("zark-invite-test-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn invitation(&self) -> PathBuf {
        self.0.join("invitation")
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create(path: &Path) -> LocalInvitation {
    LocalInvitation::create(path, AddressNetwork::Test, DEPLOYMENT).unwrap()
}

fn open(path: &Path) -> LocalInvitation {
    LocalInvitation::open(path, AddressNetwork::Test, DEPLOYMENT).unwrap()
}

fn record(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path.join("invitation.json")).unwrap()).unwrap()
}

fn replace_record(path: &Path, value: &Value) {
    // Mutation is confined to synthetic test records. Never include their
    // contents in assertion/debug output, even when an assertion fails.
    fs::write(
        path.join("invitation.json"),
        serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
}

#[test]
fn swap_peer_signatures_bind_sender_recipient_and_all_terms() {
    let a = Home::new();
    let b = Home::new();
    let c = Home::new();
    let sender = create(&a.invitation());
    let recipient = create(&b.invitation());
    let stranger = create(&c.invitation());
    let source = sender.public_address().unwrap();
    let destination = recipient.public_address().unwrap().encode();
    let message = json!({"kind":"swap-terms","payload":{"offer":"offer-1","amountSat":45000,"coins":["a","b"]}});
    let signature = sender.sign_peer_message(&destination, &message).unwrap();
    let verify = zark_protocol::mail::verify_peer_message;
    verify(&source, &destination, &message, &signature).unwrap();
    let mut changed = message.clone();
    changed["payload"]["amountSat"] = 15000.into();
    assert!(verify(&source, &destination, &changed, &signature).is_err());
    changed = message.clone();
    changed["payload"]["coins"] = json!(["b", "a"]);
    assert!(verify(&source, &destination, &changed, &signature).is_err());
    assert!(
        verify(
            &source,
            &stranger.public_address().unwrap().encode(),
            &message,
            &signature
        )
        .is_err()
    );
    assert!(
        verify(
            &stranger.public_address().unwrap(),
            &destination,
            &message,
            &signature
        )
        .is_err()
    );
    let registration = sender.mail_registration(&"aa".repeat(32), 1000).unwrap();
    assert!(verify(&source, &destination, &message, &registration).is_err());
    assert_eq!(sender.status(), InvitationStatus::Fresh);
    assert_eq!(recipient.status(), InvitationStatus::Fresh);
}

#[test]
fn private_creation_reopens_the_same_keys_without_a_second_address_file() {
    let home = Home::new();
    let path = home.invitation();
    let invitation = create(&path);
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    let address = invitation.public_address().unwrap();
    let encoded = address.encode();
    assert!(encoded.starts_with("tzark1p"));
    assert_ne!(address.envelope_key()[1..], address.claim_key()[1..]);
    assert_eq!(address.claim_key()[0], 2);
    let id = invitation.invitation_id();
    assert_ne!(id, [0; 32]);
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o700);
    assert_eq!(mode(&path.join("invitation.json")), 0o600);
    assert_eq!(mode(&path.join("invitation.lock")), 0o600);
    assert_eq!(fs::read_dir(&path).unwrap().count(), 2);
    let before = fs::read(path.join("invitation.json")).unwrap();
    drop(invitation);
    let reopened = create(&path);
    assert!(reopened.public_address().unwrap().encode() == encoded);
    assert!(reopened.invitation_id() == id);
    assert!(fs::read(path.join("invitation.json")).unwrap() == before);
    let other = create(&home.0.join("other"));
    let other_address = other.public_address().unwrap();
    assert!(other_address.envelope_key() != address.envelope_key());
    assert!(other_address.claim_key() != address.claim_key());
    assert!(other.invitation_id() != id);
}

#[test]
fn exact_reservation_survives_reopen_and_rejects_every_conflicting_binding() {
    let home = Home::new();
    let path = home.invitation();
    let mut invitation = create(&path);
    let offer = br#"{"offer":"synthetic opaque handoff"}"#;
    assert_eq!(
        invitation.reserve(COIN, OPERATION, offer).unwrap(),
        ReservationResult::Reserved
    );
    assert_eq!(invitation.status(), InvitationStatus::Reserved);
    let committed = fs::read(path.join("invitation.json")).unwrap();
    drop(invitation);
    let mut invitation = open(&path);
    assert_eq!(invitation.status(), InvitationStatus::Reserved);
    assert_eq!(
        invitation.reserve(COIN, OPERATION, offer).unwrap(),
        ReservationResult::AlreadyReserved
    );
    for (coin, operation, changed_offer) in [
        ([40; 32], OPERATION, &offer[..]),
        (COIN, [43; 32], &offer[..]),
        (COIN, OPERATION, &b"changed offer"[..]),
        (
            COIN,
            OPERATION,
            &b" {\"offer\":\"synthetic opaque handoff\"}"[..],
        ),
    ] {
        assert!(invitation.reserve(coin, operation, changed_offer).is_err());
        assert!(fs::read(path.join("invitation.json")).unwrap() == committed);
    }
}

#[test]
fn reservation_digest_is_bound_to_independent_invitation_identity() {
    let home = Home::new();
    let first_path = home.invitation();
    let second_path = home.0.join("second");
    let mut first = create(&first_path);
    let mut second = create(&second_path);
    first
        .reserve(COIN, OPERATION, b"same exact public fixture offer")
        .unwrap();
    second
        .reserve(COIN, OPERATION, b"same exact public fixture offer")
        .unwrap();
    let first_record = record(&first_path);
    let second_record = record(&second_path);
    assert!(first_record["state"]["offer_digest"] != second_record["state"]["offer_digest"]);
}

#[test]
fn invalid_context_or_unbounded_input_never_reserves_or_creates_keys() {
    let home = Home::new();
    let path = home.invitation();
    assert!(LocalInvitation::create(&path, AddressNetwork::MainnetReserved, DEPLOYMENT).is_err());
    assert!(LocalInvitation::create(&path, AddressNetwork::Test, [0; 32]).is_err());
    assert!(!path.exists());
    let mut invitation = create(&path);
    let before = fs::read(path.join("invitation.json")).unwrap();
    assert!(invitation.reserve([0; 32], OPERATION, b"offer").is_err());
    assert!(invitation.reserve(COIN, [0; 32], b"offer").is_err());
    assert!(invitation.reserve(COIN, OPERATION, b"").is_err());
    assert!(
        invitation
            .reserve(COIN, OPERATION, &vec![0; MAX_OFFER_BYTES + 1])
            .is_err()
    );
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    assert!(fs::read(path.join("invitation.json")).unwrap() == before);
    drop(invitation);
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, [24; 32]).is_err());
    assert!(LocalInvitation::create(&path, AddressNetwork::Test, [24; 32]).is_err());
    assert!(fs::read(path.join("invitation.json")).unwrap() == before);
}

#[test]
fn interrupted_creation_fails_closed_but_committed_record_ignores_orphan_temp() {
    let home = Home::new();
    let incomplete = home.0.join("incomplete");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&incomplete)
        .unwrap();
    fs::write(
        incomplete.join(".write-interrupted"),
        b"incomplete synthetic bytes",
    )
    .unwrap();
    assert!(LocalInvitation::create(&incomplete, AddressNetwork::Test, DEPLOYMENT).is_err());
    assert!(!incomplete.join("invitation.json").exists());
    assert!(incomplete.join(".write-interrupted").exists());
    let path = home.invitation();
    let mut invitation = create(&path);
    invitation.reserve(COIN, OPERATION, b"offer").unwrap();
    let address = invitation.public_address().unwrap().encode();
    drop(invitation);
    fs::write(path.join(".write-interrupted"), b"not a committed record").unwrap();
    let mut reopened = open(&path);
    assert!(reopened.public_address().unwrap().encode() == address);
    assert_eq!(reopened.status(), InvitationStatus::Reserved);
    assert_eq!(
        reopened.reserve(COIN, OPERATION, b"offer").unwrap(),
        ReservationResult::AlreadyReserved
    );
    assert!(path.join(".write-interrupted").exists());
}

#[test]
fn corrupted_partial_or_unknown_private_records_are_not_repaired() {
    let home = Home::new();
    let path = home.invitation();
    drop(create(&path));
    let original = record(&path);
    let mut variants = Vec::new();
    let zeros = [0u8; 32];
    let ones = [1u8; 32];
    let invalid_scalar = [255u8; 32];
    for field in [
        "schema",
        "version",
        "network",
        "deployment",
        "invitation_id",
        "envelope_secret",
        "claim_secret",
        "state",
    ] {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        variants.push(missing);
    }
    for (field, replacement) in [
        ("version", json!(2)),
        ("schema", json!("other-schema")),
        ("network", json!("mainnet")),
        ("unknown", json!(true)),
        ("invitation_id", json!(zeros)),
        ("envelope_secret", json!(zeros)),
        ("claim_secret", json!(invalid_scalar)),
        (
            "state",
            json!({"phase":"reserved","coin":zeros,"operation":OPERATION,"offer_digest":ones}),
        ),
        ("state", json!({"phase":"fresh","unknown":true})),
    ] {
        let mut changed = original.clone();
        changed[field] = replacement;
        variants.push(changed);
    }
    for (index, changed) in variants.into_iter().enumerate() {
        replace_record(&path, &changed);
        let before = fs::read(path.join("invitation.json")).unwrap();
        assert!(
            LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err(),
            "corrupt fixture {index}"
        );
        assert!(LocalInvitation::create(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
        assert!(fs::read(path.join("invitation.json")).unwrap() == before);
    }
    fs::write(path.join("invitation.json"), b"{\"schema\":").unwrap();
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
    fs::write(path.join("invitation.json"), vec![b' '; 8193]).unwrap();
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
}

#[test]
fn symlinks_hardlinks_and_permissive_paths_are_rejected() {
    let home = Home::new();
    let path = home.invitation();
    drop(create(&path));
    let link = home.0.join("directory-link");
    symlink(&path, &link).unwrap();
    assert!(LocalInvitation::open(&link, AddressNetwork::Test, DEPLOYMENT).is_err());
    let record_path = path.join("invitation.json");
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
    let extra_link = home.0.join("hardlink");
    fs::hard_link(&record_path, &extra_link).unwrap();
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
    fs::remove_file(&extra_link).unwrap();
    fs::rename(&record_path, &extra_link).unwrap();
    symlink(&extra_link, &record_path).unwrap();
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
    fs::remove_file(&record_path).unwrap();
    fs::rename(&extra_link, &record_path).unwrap();
    fs::rename(&record_path, &extra_link).unwrap();
    let fifo_path = std::ffi::CString::new(record_path.to_str().unwrap()).unwrap();
    // SAFETY: the CString remains valid throughout this call in our test dir.
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
    fs::remove_file(&record_path).unwrap();
    fs::rename(&extra_link, &record_path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let lock_path = path.join("invitation.lock");
    fs::rename(&lock_path, &extra_link).unwrap();
    symlink(&extra_link, &lock_path).unwrap();
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
}

#[test]
fn process_lock_excludes_competing_reservations_until_guard_is_dropped() {
    let home = Home::new();
    let path = home.invitation();
    let mut first = create(&path);
    let path_clone = path.clone();
    let barrier = Arc::new(Barrier::new(2));
    let other_barrier = Arc::clone(&barrier);
    let contender = thread::spawn(move || {
        other_barrier.wait();
        LocalInvitation::open(&path_clone, AddressNetwork::Test, DEPLOYMENT).is_err()
    });
    barrier.wait();
    assert!(contender.join().unwrap());
    first.reserve(COIN, OPERATION, b"first offer").unwrap();
    drop(first);
    let lock = ProcessLock::acquire(&path.join("invitation.lock")).unwrap();
    assert!(LocalInvitation::open(&path, AddressNetwork::Test, DEPLOYMENT).is_err());
    drop(lock);
    let mut next = open(&path);
    assert!(next.reserve(COIN, [43; 32], b"second offer").is_err());
    assert_eq!(
        next.reserve(COIN, OPERATION, b"first offer").unwrap(),
        ReservationResult::AlreadyReserved
    );
}
