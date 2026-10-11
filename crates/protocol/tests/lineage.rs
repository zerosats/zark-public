use anyhow::Result;
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use zark_protocol::{
    handoff::HandoverBinding,
    handoff::{
        RecoverySchedule, SigningBinding, TransferContext, origin_previous_capability,
        origin_previous_state, origin_refresh_commitment, policy_commitment,
    },
    lineage::{IssuanceBinding, LineageBinding, LineageHandoverBinding, LineagePolicy},
    point_bytes,
};

#[test]
fn exact_six_role_encodings_and_origin_bindings() -> Result<()> {
    let key = SigningKey::from_bytes(&[7; 32])?;
    let origin = key.verifying_key().to_bytes().into();
    let mut roles = [[0; 32]; zark_protocol::lineage::ROLE_COUNT];
    for (i, role) in roles.iter_mut().enumerate() {
        role[31] = (i + 1) as u8;
    }
    let schedule = RecoverySchedule {
        initial: 480,
        gap: 60,
        margin: 6,
    };
    let policy = policy_commitment(schedule)?;
    let config = LineagePolicy {
        deployment: [9; 32],
        schedule,
        origin_key: origin,
        role_hashes: roles,
    };
    let mut base = LineageBinding {
        deployment: [9; 32],
        coin: [8; 32],
        funding: [6; 32],
        state: [5; 32],
        policy,
        origin_key: origin,
        role_hashes: roles,
    };
    assert_eq!(base.encode()?.len(), 388);
    assert_eq!(
        LineageBinding::decode(&base.encode()?)?.encode()?,
        base.encode()?
    );
    assert!(LineageBinding::decode(&base.encode()?[..387]).is_err());
    config.require(
        &base.deployment,
        &base.policy,
        &base.origin_key,
        &base.role_hashes,
    )?;
    let sig = key.sign_raw(&base.origin_message()?, &[0; 32])?.to_bytes();
    base.verify_origin_attestation(&sig)?;
    base.state[0] ^= 1;
    assert!(base.verify_origin_attestation(&sig).is_err());
    base.state[0] ^= 1;
    let old = origin_previous_state(&base.deployment, &base.coin)?;
    let cap = origin_previous_capability(&base.deployment, &base.coin)?;
    assert_ne!(old, cap);
    let mut context = TransferContext {
        deployment: base.deployment,
        coin: base.coin,
        previous_state: old,
        operation: [4; 32],
        recipient_claim: [3; 32],
        session_auth: origin,
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
    };
    let server = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(11u64))?;
    let refresh = origin_refresh_commitment(&context, &base.funding, &server)?;
    let mut changed = context.clone();
    changed.operation[0] ^= 1;
    assert_ne!(
        origin_refresh_commitment(&changed, &base.funding, &server)?,
        refresh
    );
    context.previous_state[0] ^= 1;
    assert!(origin_refresh_commitment(&context, &base.funding, &server).is_err());
    context.previous_state = old;
    let handover = LineageHandoverBinding {
        handover: HandoverBinding {
            intent: context.intent(),
            funding: [1; 32],
            mask: [2; 32],
            masked_share: [3; 32],
            bridge: [4; 32],
            previous_capability: [5; 32],
            server_share: [6; 32],
            policy,
            draft_access: [11; 32],
        },
        origin_key: origin,
        role_hashes: roles,
    };
    assert_eq!(handover.encode()?.len(), 685);
    assert_eq!(
        LineageHandoverBinding::decode(&handover.encode()?)?.encode()?,
        handover.encode()?
    );
    let issuance = IssuanceBinding {
        signing: SigningBinding {
            context,
            funding: base.funding,
            refresh_commitment: refresh,
            previous_capability: cap,
            next_capability: [2; 32],
            recovery: [3; 32],
            nonce_commitment: [4; 32],
            draft_server: server,
            server_nonce: server,
            blinded_challenge: [0; 32],
        },
        policy,
        origin_key: origin,
        role_hashes: roles,
    };
    assert_eq!(issuance.encode()?.len(), 877);
    assert_eq!(
        IssuanceBinding::decode(&issuance.encode()?)?.encode()?,
        issuance.encode()?
    );
    let mut malformed = issuance.encode()?;
    malformed[590] ^= 1;
    assert!(IssuanceBinding::decode(&malformed).is_err());
    malformed = issuance.encode()?;
    malformed[0] = 7;
    assert!(IssuanceBinding::decode(&malformed).is_err());
    let mut swapped = roles;
    swapped.swap(4, 2);
    assert!(
        config
            .require(&base.deployment, &policy, &origin, &swapped)
            .is_err()
    );
    swapped[5] = swapped[4];
    base.role_hashes = swapped;
    assert!(base.encode().is_err());
    Ok(())
}
