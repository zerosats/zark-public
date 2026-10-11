//! Synthetic, local, isolated transport tests. No wallet/node/signer is opened.
use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    random32,
};
use zark_wallet::{
    envelope::{MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES, OfferContext, encrypt_offer},
    invitation::{InvitationStatus, LocalInvitation, ReservationResult},
};
use zeroize::Zeroizing;

const DEPLOYMENT: [u8; 32] = [91; 32];
const PAYLOAD: &[u8] = b"synthetic private transfer offer, not proof of ownership";

#[test]
fn delivery_envelope_hides_all_coordination_and_binds_address_id_and_role() {
    let home = Home::new();
    let invitation = home.invitation("mail");
    let other = home.invitation("other-mail");
    let address = invitation.public_address().unwrap();
    let payload = br#"{"kind":"coin","payload":{"coin":"private-coin-id","amountSat":123456,"manifest":"private-swap"}}"#;
    let encrypted =
        zark_wallet::envelope::encrypt_message(&address, "delivery-1", payload).unwrap();
    let wire = hex::decode(&encrypted).unwrap();
    for secret in [b"private-coin-id".as_slice(), b"123456", b"private-swap"] {
        assert!(!wire.windows(secret.len()).any(|w| w == secret));
    }
    assert_eq!(
        &*invitation
            .decrypt_message("delivery-1", &encrypted)
            .unwrap(),
        payload
    );
    assert!(
        invitation
            .decrypt_message("delivery-2", &encrypted)
            .is_err()
    );
    assert!(other.decrypt_message("delivery-1", &encrypted).is_err());
    let offer = encrypt_offer(&address, &context(), payload).unwrap();
    assert!(
        invitation
            .decrypt_message("delivery-1", &hex::encode(offer.as_bytes()))
            .is_err()
    );
    assert!(invitation.decrypt_offer(&context(), &wire).is_err());
    let altered = alter(&wire, |v| flip_hex(&mut v.ciphertext, 0));
    assert!(
        invitation
            .decrypt_message("delivery-1", &hex::encode(altered))
            .is_err()
    );
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    let token_hash = hex::encode(zark_protocol::hash(&[b"test-token"]));
    let signature = invitation.mail_registration(&token_hash, 60_000).unwrap();
    zark_protocol::mail::verify_registration(&address, &token_hash, 60_000, &signature).unwrap();
    assert!(
        zark_protocol::mail::verify_registration(&address, &token_hash, 60_001, &signature)
            .is_err()
    );
    assert!(
        zark_protocol::mail::verify_registration(
            &other.public_address().unwrap(),
            &token_hash,
            60_000,
            &signature
        )
        .is_err()
    );
}

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("zark-envelope-test-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn invitation(&self, name: &str) -> LocalInvitation {
        LocalInvitation::create(&self.0.join(name), AddressNetwork::Test, DEPLOYMENT).unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context() -> OfferContext {
    OfferContext {
        deployment: DEPLOYMENT,
        coin: [92; 32],
        operation: [93; 32],
    }
}

// Field order deliberately matches the canonical transport encoder, so changing
// a field reaches cryptographic authentication instead of failing JSON order.
#[derive(Serialize, Deserialize)]
struct Wire {
    version: u8,
    ephemeral_key: String,
    nonce: String,
    ciphertext: String,
}
fn alter(bytes: &[u8], edit: impl FnOnce(&mut Wire)) -> Vec<u8> {
    let mut wire: Wire = serde_json::from_slice(bytes).unwrap();
    edit(&mut wire);
    serde_json::to_vec(&wire).unwrap()
}
fn flip_hex(value: &mut String, index: usize) {
    let mut bytes = value.as_bytes().to_vec();
    bytes[index] = if bytes[index] == b'0' { b'1' } else { b'0' };
    *value = String::from_utf8(bytes).unwrap();
}

#[test]
fn randomized_envelopes_decrypt_and_exact_retry_survives_reopen() {
    let home = Home::new();
    let mut invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let sealed = encrypt_offer(&address, &context(), PAYLOAD).unwrap();
    let different = encrypt_offer(&address, &context(), PAYLOAD).unwrap();
    assert!(sealed.as_bytes() != different.as_bytes());
    assert!(
        !sealed
            .as_bytes()
            .windows(PAYLOAD.len())
            .any(|window| window == PAYLOAD)
    );
    let first: Wire = serde_json::from_slice(sealed.as_bytes()).unwrap();
    let second: Wire = serde_json::from_slice(different.as_bytes()).unwrap();
    assert_ne!(first.ephemeral_key, second.ephemeral_key);
    assert_ne!(first.nonce, second.nonce);
    let received = invitation
        .decrypt_offer(&context(), sealed.as_bytes())
        .unwrap();
    assert!(received.plaintext() == PAYLOAD); // Do not print private plaintext.
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    // Storage reservation is a separate action after the future proof gate.
    assert_eq!(
        invitation
            .reserve(context().coin, context().operation, sealed.as_bytes())
            .unwrap(),
        ReservationResult::Reserved
    );
    drop(received);
    drop(invitation);
    let mut reopened = home.invitation("receiver");
    let retry = reopened
        .decrypt_offer(&context(), sealed.as_bytes())
        .unwrap();
    assert!(retry.plaintext() == PAYLOAD);
    assert_eq!(
        reopened
            .reserve(context().coin, context().operation, sealed.as_bytes())
            .unwrap(),
        ReservationResult::AlreadyReserved
    );
    drop(retry);
    let saved = Zeroizing::new(fs::read(home.0.join("receiver/invitation.json")).unwrap());
    assert!(
        reopened
            .decrypt_offer(&context(), different.as_bytes())
            .is_ok()
    );
    assert!(
        reopened
            .reserve(context().coin, context().operation, different.as_bytes())
            .is_err()
    );
    assert!(fs::read(home.0.join("receiver/invitation.json")).unwrap() == *saved);
    // Even a separately authenticated valid offer for another operation cannot
    // acquire a second use of the same recipient keys.
    let mut other = context();
    other.operation = [94; 32];
    let other_wire = encrypt_offer(&address, &other, PAYLOAD).unwrap();
    assert!(
        reopened
            .decrypt_offer(&other, other_wire.as_bytes())
            .is_ok()
    );
    assert!(
        reopened
            .reserve(other.coin, other.operation, other_wire.as_bytes())
            .is_err()
    );
}

#[test]
fn every_ciphertext_byte_and_public_header_tamper_leaves_invitation_fresh() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let sealed = encrypt_offer(&address, &context(), PAYLOAD).unwrap();
    let saved = Zeroizing::new(fs::read(home.0.join("receiver/invitation.json")).unwrap());
    let wire: Wire = serde_json::from_slice(sealed.as_bytes()).unwrap();
    for byte in 0..wire.ciphertext.len() / 2 {
        let tampered = alter(sealed.as_bytes(), |w| flip_hex(&mut w.ciphertext, byte * 2));
        assert!(invitation.decrypt_offer(&context(), &tampered).is_err());
    }
    let other = encrypt_offer(&address, &context(), PAYLOAD).unwrap();
    let other: Wire = serde_json::from_slice(other.as_bytes()).unwrap();
    let changed_public = alter(sealed.as_bytes(), |w| w.ephemeral_key = other.ephemeral_key);
    let changed_nonce = alter(sealed.as_bytes(), |w| flip_hex(&mut w.nonce, 0));
    for bytes in [&changed_public, &changed_nonce] {
        assert!(invitation.decrypt_offer(&context(), bytes).is_err());
    }
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    assert!(fs::read(home.0.join("receiver/invitation.json")).unwrap() == *saved);
    assert!(
        invitation
            .decrypt_offer(&context(), sealed.as_bytes())
            .is_ok()
    );
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
}

#[test]
fn recipient_full_address_and_expected_context_are_authenticated() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let wrong_recipient = home.invitation("wrong");
    let address = invitation.public_address().unwrap();
    let sealed = encrypt_offer(&address, &context(), PAYLOAD).unwrap();
    assert!(
        wrong_recipient
            .decrypt_offer(&context(), sealed.as_bytes())
            .is_err()
    );
    assert_eq!(wrong_recipient.status(), InvitationStatus::Fresh);
    for field in 0..3 {
        let mut other = context();
        match field {
            0 => other.deployment = [99; 32],
            1 => other.coin = [99; 32],
            _ => other.operation = [99; 32],
        }
        assert!(invitation.decrypt_offer(&other, sealed.as_bytes()).is_err());
    }
    // Keep the very same envelope key, but change the independent claim key.
    // ECDH alone would agree; including the full address in AD must reject it.
    let altered_address = ReceivingAddress::new(
        AddressNetwork::Test,
        DEPLOYMENT,
        *address.envelope_key(),
        *wrong_recipient.public_address().unwrap().claim_key(),
    )
    .unwrap();
    let wrong_claim = encrypt_offer(&altered_address, &context(), PAYLOAD).unwrap();
    assert!(
        invitation
            .decrypt_offer(&context(), wrong_claim.as_bytes())
            .is_err()
    );
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    let mainnet = ReceivingAddress::new(
        AddressNetwork::MainnetReserved,
        DEPLOYMENT,
        *address.envelope_key(),
        *address.claim_key(),
    )
    .unwrap();
    assert!(encrypt_offer(&mainnet, &context(), PAYLOAD).is_err());
    for field in 0..3 {
        let mut zero = context();
        match field {
            0 => zero.deployment = [0; 32],
            1 => zero.coin = [0; 32],
            _ => zero.operation = [0; 32],
        }
        assert!(encrypt_offer(&address, &zero, PAYLOAD).is_err());
    }
}

#[test]
fn malformed_or_noncanonical_wire_rejected_before_reservation() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let sealed = encrypt_offer(&invitation.public_address().unwrap(), &context(), PAYLOAD).unwrap();
    let mut bad = vec![
        Vec::new(),
        b"null".to_vec(),
        b"{}".to_vec(),
        vec![b' '; MAX_ENVELOPE_BYTES + 1],
    ];
    bad.push(alter(sealed.as_bytes(), |w| w.version = 0));
    bad.push(alter(sealed.as_bytes(), |w| w.version = 2));
    bad.push(alter(sealed.as_bytes(), |w| {
        w.ephemeral_key = format!("02{}", "ff".repeat(32))
    }));
    bad.push(alter(sealed.as_bytes(), |w| {
        w.ephemeral_key.replace_range(0..2, "04")
    }));
    bad.push(alter(sealed.as_bytes(), |w| {
        w.ephemeral_key = w.ephemeral_key.to_uppercase()
    }));
    bad.push(alter(sealed.as_bytes(), |w| {
        w.nonce.pop();
    }));
    bad.push(alter(sealed.as_bytes(), |w| {
        w.nonce.replace_range(0..1, "g")
    }));
    bad.push(alter(sealed.as_bytes(), |w| w.ciphertext = "00".repeat(16)));
    bad.push(alter(sealed.as_bytes(), |w| {
        w.ciphertext.pop();
    }));
    bad.push(alter(sealed.as_bytes(), |w| {
        w.ciphertext.replace_range(0..1, "A")
    }));
    bad.push(alter(sealed.as_bytes(), |w| {
        w.ciphertext.push_str("00");
    }));
    let text = std::str::from_utf8(sealed.as_bytes()).unwrap();
    bad.push(format!("{text}\n").into_bytes());
    bad.push(text.replacen("{", "{\"extra\":1,", 1).into_bytes());
    bad.push(text.replacen("{", "{\"version\":1,", 1).into_bytes());
    bad.push(
        text.replacen("\"version\"", "\"\\u0076ersion\"", 1)
            .into_bytes(),
    );
    let value: serde_json::Value = serde_json::from_slice(sealed.as_bytes()).unwrap();
    bad.push(serde_json::to_vec_pretty(&value).unwrap());
    for bytes in bad {
        assert!(invitation.decrypt_offer(&context(), &bytes).is_err());
    }
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
}

#[test]
fn plaintext_and_ciphertext_size_limits_agree_at_boundary() {
    let home = Home::new();
    let mut invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    assert!(encrypt_offer(&address, &context(), b"").is_err());
    assert!(encrypt_offer(&address, &context(), &vec![0; MAX_PLAINTEXT_BYTES + 1]).is_err());
    let plaintext = Zeroizing::new(vec![0x51; MAX_PLAINTEXT_BYTES]);
    let sealed = encrypt_offer(&address, &context(), &plaintext).unwrap();
    assert!(sealed.as_bytes().len() <= MAX_ENVELOPE_BYTES);
    let received = invitation
        .decrypt_offer(&context(), sealed.as_bytes())
        .unwrap();
    assert!(received.plaintext() == plaintext.as_slice());
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    // Storage reservation is a separate action after the future proof gate.
    assert_eq!(
        invitation
            .reserve(context().coin, context().operation, sealed.as_bytes())
            .unwrap(),
        ReservationResult::Reserved
    );
}
