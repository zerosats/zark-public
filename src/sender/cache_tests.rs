use super::*;
use k256::schnorr::SigningKey;
use zark_protocol::{
    handoff::{Digest, OperationScope, TransferContext},
    wire::{Command, Request},
};

use zark_protocol::scalar;

fn context(key: &SigningKey) -> TransferContext {
    TransferContext {
        start_revision: 1,
        scope: OperationScope::Single,
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
    }
}

#[test]
fn rejects_negated_session_scalar_with_same_bip340_public_key() {
    let key = SigningKey::from_bytes(&[7; 32]).unwrap();
    let context = context(&key);
    let normalized: Digest = key.to_bytes().into();
    validate_session(&normalized, &context).unwrap();
    let negated: Digest = (-scalar(&normalized).unwrap()).to_bytes().into();
    assert_eq!(
        SigningKey::from_bytes(&negated)
            .unwrap()
            .verifying_key()
            .to_bytes(),
        key.verifying_key().to_bytes()
    );
    assert!(validate_session(&negated, &context).is_err());
}

#[test]
fn completion_cache_preserves_exact_wire_and_rejects_other_operation_or_role() {
    let key = SigningKey::from_bytes(&[7; 32]).unwrap();
    let context = context(&key);
    let request = Request::sign(context.clone(), Command::CompleteSender {}, &key).unwrap();
    let wire = request.encode().unwrap();
    let saved = hex::encode(&*wire);
    assert_eq!(
        *cached_completion(&context, &saved)
            .unwrap()
            .encode()
            .unwrap(),
        *wire
    );
    let mut other = context.clone();
    other.operation = [8; 32];
    assert!(cached_completion(&other, &saved).is_err());
    let wrong = Request::sign(
        context.clone(),
        Command::Prepare {
            recovery: [9; 32],
            blinding: [10; 32],
        },
        &key,
    )
    .unwrap();
    assert!(cached_completion(&context, &hex::encode(&*wrong.encode().unwrap())).is_err());
    let mut corrupt = wire.to_vec();
    let last = corrupt.len() - 2;
    corrupt[last] ^= 1;
    assert!(cached_completion(&context, &hex::encode(corrupt)).is_err());
}

#[test]
fn ciphertext_cache_rejects_partial_replacement_and_cross_operation_reuse() {
    let key = SigningKey::from_bytes(&[7; 32]).unwrap();
    let context = context(&key);
    // Local corruption detection only: these are not an authenticated offer.
    let bytes = b"synthetic encrypted wire";
    let wire = hex::encode(bytes);
    let digest = saved_offer_digest(&context, bytes).unwrap();
    validate_offer_cache(&context, Some(&wire), Some(&digest)).unwrap();
    validate_offer_cache(&context, None, None).unwrap();
    assert!(validate_offer_cache(&context, Some(&wire), None).is_err());
    assert!(validate_offer_cache(&context, None, Some(&digest)).is_err());
    assert!(
        validate_offer_cache(
            &context,
            Some(&hex::encode(b"changed encrypted wire")),
            Some(&digest)
        )
        .is_err()
    );
    let mut other = context;
    other.operation = [8; 32];
    assert!(validate_offer_cache(&other, Some(&wire), Some(&digest)).is_err());
}
