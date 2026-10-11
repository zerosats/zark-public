use anyhow::Result;
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use zark_protocol::{
    certificate::{IssuedTransferRecord, OwnerCertificate},
    handoff::{
        OperationScope, SigningBinding, TransferContext, capability_commitment,
        draft_access_commitment,
    },
    lineage::IssuanceBinding,
    owner_auth::{OwnerAuthorization, normalized_key},
    point_bytes,
    proof::PROOF_BYTES,
    scalar,
    wire::{Command, Request},
};

fn context() -> Result<(TransferContext, SigningKey)> {
    let key = SigningKey::from_bytes(&[7; 32])?;
    Ok((
        TransferContext {
            deployment: [1; 32],
            coin: [2; 32],
            previous_state: [3; 32],
            operation: [4; 32],
            recipient_claim: [5; 32],
            session_auth: key.verifying_key().to_bytes().into(),
            start_revision: 7,
            scope: OperationScope::Single,
        },
        key,
    ))
}

#[test]
fn owner_authority_rejects_stolen_session_replays_and_negated_secrets() -> Result<()> {
    let (context, session) = context()?;
    let secret: [u8; 32] = SigningKey::from_bytes(&[9; 32])?.to_bytes().into();
    let cap = capability_commitment(&context.deployment, &context.coin, &secret)?;
    let auth = OwnerAuthorization::sign_reservation(&context, &secret)?;
    auth.verify_reservation(&context, &cap)?;
    assert!(normalized_key(&(-scalar(&secret)?).to_bytes().into()).is_err());
    assert!(OwnerAuthorization::sign_reservation(&context, &session.to_bytes().into()).is_err());
    for field in 0..8 {
        let mut changed = context.clone();
        match field {
            0 => changed.deployment[0] ^= 1,
            1 => changed.coin[0] ^= 1,
            2 => changed.previous_state[0] ^= 1,
            3 => changed.operation[0] ^= 1,
            4 => changed.recipient_claim[0] ^= 1,
            5 => {
                changed.session_auth = SigningKey::from_bytes(&[8; 32])?
                    .verifying_key()
                    .to_bytes()
                    .into()
            }
            6 => changed.start_revision += 1,
            _ => {
                changed.scope = OperationScope::Batch {
                    manifest_digest: [8; 32],
                }
            }
        }
        assert!(auth.verify_reservation(&changed, &cap).is_err());
    }
    let mut exit_context = context.clone();
    exit_context.recipient_claim =
        zark_protocol::exit::intent(&context.deployment, &context.coin, &context.operation)?;
    assert!(
        auth.verify_exit(
            &exit_context,
            &cap,
            &[10; 32],
            &[11; 32],
            &[12; 32],
            &[13; 32]
        )
        .is_err()
    );
    let exit_auth = OwnerAuthorization::sign_exit(
        &exit_context,
        &[10; 32],
        &[11; 32],
        &[12; 32],
        &[13; 32],
        &secret,
    )?;
    exit_auth.verify_exit(
        &exit_context,
        &cap,
        &[10; 32],
        &[11; 32],
        &[12; 32],
        &[13; 32],
    )?;
    assert!(
        exit_auth
            .verify_exit(
                &exit_context,
                &cap,
                &[10; 32],
                &[11; 32],
                &[12; 32],
                &[14; 32]
            )
            .is_err()
    );
    assert!(OwnerAuthorization::sign_reservation(&exit_context, &secret).is_err());
    Ok(())
}

#[test]
fn provisional_token_binds_frozen_intent_but_not_later_session() -> Result<()> {
    let (context, _) = context()?;
    let token = [17; 32];
    let original = draft_access_commitment(&context.intent(), &token)?;
    assert!(draft_access_commitment(&context.intent(), &[0; 32]).is_err());
    assert_ne!(
        original,
        draft_access_commitment(&context.intent(), &[18; 32])?
    );
    let mut changed = context.clone();
    changed.session_auth = SigningKey::from_bytes(&[8; 32])?
        .verifying_key()
        .to_bytes()
        .into();
    assert_eq!(
        original,
        draft_access_commitment(&changed.intent(), &token)?
    );
    changed.start_revision += 1;
    assert_ne!(
        original,
        draft_access_commitment(&changed.intent(), &token)?
    );
    changed = context;
    changed.scope = OperationScope::Batch {
        manifest_digest: [19; 32],
    };
    assert_ne!(
        original,
        draft_access_commitment(&changed.intent(), &token)?
    );
    let mut encoded = changed.encode()?;
    encoded[204] = 0;
    assert!(TransferContext::decode(&encoded).is_err());
    Ok(())
}

#[test]
fn composite_native_response_and_exact_ack_identity_reject_substitution() -> Result<()> {
    let (context, session) = context()?;
    let mut roles = [[0; 32]; zark_protocol::lineage::ROLE_COUNT];
    for (i, role) in roles.iter_mut().enumerate() {
        role[31] = (i + 1) as u8;
    }
    let authorization = IssuanceBinding {
        signing: SigningBinding {
            context: context.clone(),
            funding: [6; 32],
            refresh_commitment: [7; 32],
            previous_capability: [8; 32],
            next_capability: [9; 32],
            recovery: [10; 32],
            nonce_commitment: [11; 32],
            draft_server: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(12u64))?,
            server_nonce: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(13u64))?,
            blinded_challenge: Scalar::from(14u64).to_bytes().into(),
        },
        policy: [15; 32],
        origin_key: SigningKey::from_bytes(&[16; 32])?
            .verifying_key()
            .to_bytes()
            .into(),
        role_hashes: roles,
    };
    // Synthetic bytes exercise native reconstruction only, never proof authority.
    let proof = vec![0; PROOF_BYTES];
    let partial: [u8; 32] = Scalar::from(13u64 + 14 * 12).to_bytes().into();
    let cert = OwnerCertificate::TransferIssued {
        authorization: authorization.encode()?,
        proof: proof.clone(),
        partial,
        server_salt: [17; 32],
    };
    let state = cert.lineage_binding()?.state;
    let encoded = cert.encode_private()?;
    assert_eq!(
        OwnerCertificate::decode_private(&encoded)?
            .lineage_binding()?
            .state,
        state
    );
    let mut trailing = encoded.to_vec();
    trailing.push(b' ');
    assert!(OwnerCertificate::decode_private(&trailing).is_err());
    let bad = OwnerCertificate::TransferIssued {
        authorization: authorization.encode()?,
        proof: proof.clone(),
        partial: Scalar::ONE.to_bytes().into(),
        server_salt: [17; 32],
    };
    assert!(bad.lineage_binding().is_err());
    let request = Request::sign(
        context,
        Command::Issue {
            statement: authorization.encode()?,
            proof,
        },
        &session,
    )?;
    let record =
        IssuedTransferRecord::from_request(&request, &authorization, partial, [17; 32], state)?;
    let identity = record.identity()?;
    for field in 0..10 {
        let mut changed = record.clone();
        match field {
            0 => changed.request_digest[0] ^= 1,
            1 => changed.statement_digest[0] ^= 1,
            2 => changed.proof_digest[0] ^= 1,
            3 => changed.signing_digest[0] ^= 1,
            4 => changed.partial[31] ^= 1,
            5 => changed.server_salt[0] ^= 1,
            6 => changed.state[0] ^= 1,
            7 => changed.capability[0] ^= 1,
            8 => changed.receiver_role_hash[31] += 1,
            _ => changed.context.start_revision += 1,
        }
        assert_ne!(identity, changed.identity()?);
    }
    assert!(
        IssuedTransferRecord::from_request(&request, &authorization, partial, [18; 32], state)
            .is_err()
    );
    assert!(
        IssuedTransferRecord::from_request(&request, &authorization, partial, [17; 32], [18; 32])
            .is_err()
    );
    Ok(())
}
