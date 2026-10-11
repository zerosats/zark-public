use anyhow::Result;
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use zark_protocol::{
    handoff::{
        ClaimBinding, FundingOpening, HandoverBinding, RecoveryDelay, RecoveryOpening,
        RecoverySchedule, ServerShareOpening, SigningBinding, StateOpening, TransferContext,
        TransferIntent, blinding_commitment, bridge_commitment, capability_commitment,
        delta_commitment, issuance_commitment, mask_commitment, masked_share_commitment,
        policy_commitment, recipient_claim_commitment, refresh_commitment,
    },
    point_bytes,
};

fn auth_key() -> [u8; 32] {
    SigningKey::from_bytes(&[7; 32])
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into()
}

fn context() -> TransferContext {
    TransferContext {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: auth_key(),
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
    }
}

fn binding() -> Result<SigningBinding> {
    Ok(SigningBinding {
        context: context(),
        funding: [6; 32],
        refresh_commitment: [14; 32],
        previous_capability: [7; 32],
        next_capability: [8; 32],
        recovery: [9; 32],
        nonce_commitment: [10; 32],
        draft_server: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(11_u64))?,
        server_nonce: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(12_u64))?,
        blinded_challenge: Scalar::from(13_u64).to_bytes().into(),
    })
}

#[test]
fn context_rejects_cross_domain_and_unknown_private_fields() -> Result<()> {
    let good = context();
    assert_eq!(good.encode()?.len(), TransferContext::ENCODED_LEN);
    good.require_domain(&[1; 32], &[2; 32])?;
    assert!(good.require_domain(&[99; 32], &[2; 32]).is_err());
    assert!(good.require_domain(&[1; 32], &[99; 32]).is_err());
    let value = serde_json::to_value(&good)?;
    assert_eq!(value.as_object().unwrap().len(), 8);
    for field in [
        "history",
        "epochs",
        "payout",
        "address",
        "user_share",
        "transaction",
    ] {
        let mut altered = value.clone();
        altered[field] = serde_json::json!("private-canary");
        assert!(serde_json::from_value::<TransferContext>(altered).is_err());
    }
    for field in [
        "deployment",
        "coin",
        "previous_state",
        "operation",
        "recipient_claim",
    ] {
        let mut changed = value.clone();
        changed[field] = serde_json::json!([42; 32].to_vec());
        let changed: TransferContext = serde_json::from_value(changed)?;
        assert_ne!(changed.digest()?, good.digest()?);
    }
    let mut invalid = good.clone();
    invalid.session_auth = SigningKey::from_bytes(&[8; 32])?
        .verifying_key()
        .to_bytes()
        .into();
    assert_ne!(invalid.digest()?, good.digest()?);
    assert_eq!(invalid.intent_digest()?, good.intent_digest()?);
    invalid.session_auth = [0xff; 32];
    assert!(invalid.encode().is_err());
    invalid = good;
    invalid.operation = [0; 32];
    assert!(invalid.encode().is_err());
    Ok(())
}

#[test]
fn sender_intent_is_constructible_without_a_receiver_session() -> Result<()> {
    let intent = context().intent();
    assert_eq!(intent.encode()?.len(), TransferIntent::ENCODED_LEN);
    let encoded = context().encode()?;
    assert_eq!(
        intent.encode()?,
        [&encoded[..164], &encoded[196..]].concat()
    );
    assert_eq!(intent.with_session(auth_key())?, context());
    assert_eq!(intent.digest()?, context().intent_digest()?);
    assert!(intent.with_session([0; 32]).is_err());
    assert!(intent.with_session([0xff; 32]).is_err());
    let mut wire = serde_json::to_value(&intent)?;
    wire["session_auth"] = serde_json::json!(auth_key().to_vec());
    assert!(serde_json::from_value::<TransferIntent>(wire).is_err());
    Ok(())
}

#[test]
fn private_state_binds_all_subcommitments_and_recursive_hash_is_canonical() -> Result<()> {
    let server = ServerShareOpening {
        deployment: [1; 32],
        coin: [2; 32],
        salt: [3; 32],
        server: point_bytes(ProjectivePoint::GENERATOR)?,
    }
    .commitment()?;
    let make_state = || StateOpening {
        deployment: [1; 32],
        coin: [2; 32],
        funding: [3; 32],
        capability: [4; 32],
        recovery: [5; 32],
        server_share: server,
        policy: [6; 32],
        issuance: [7; 32],
    };
    let original = make_state().commitment()?;
    for field in 0..8 {
        let mut changed = make_state();
        match field {
            0 => changed.deployment[0] ^= 1,
            1 => changed.coin[0] ^= 1,
            2 => changed.funding[0] ^= 1,
            3 => changed.capability[0] ^= 1,
            4 => changed.recovery[0] ^= 1,
            5 => changed.server_share[0] ^= 1,
            6 => changed.policy[0] ^= 1,
            _ => changed.issuance[0] ^= 1,
        }
        assert_ne!(changed.commitment()?, original);
    }
    let binding = binding()?;
    let digest = issuance_commitment(&binding.digest()?, &[0; 32])?;
    assert_ne!(
        digest,
        issuance_commitment(&binding.digest()?, &Scalar::ONE.to_bytes().into())?
    );
    assert!(issuance_commitment(&binding.digest()?, &[0xff; 32]).is_err());
    let handover = HandoverBinding {
        draft_access: [11; 32],
        intent: context().intent(),
        funding: [3; 32],
        mask: [4; 32],
        masked_share: [5; 32],
        bridge: [6; 32],
        previous_capability: [7; 32],
        server_share: server,
        policy: [8; 32],
    };
    assert_eq!(handover.encode()?.len(), 461);
    assert_ne!(handover.digest()?, original);
    Ok(())
}

#[test]
fn recovery_openings_bind_actual_key_value_payout_and_blinding() -> Result<()> {
    let ctx = context();
    let mut funding = FundingOpening {
        deployment: ctx.deployment,
        coin: ctx.coin,
        salt: [19; 32],
        txid: [20; 32],
        vout: 0,
        amount: 100_000,
        internal_point: point_bytes(ProjectivePoint::GENERATOR)?,
    };
    let f = funding.commitment()?;
    funding.amount -= 1;
    assert_ne!(funding.commitment()?, f);
    funding.amount += 1;
    funding.vout = 1;
    assert_ne!(funding.commitment()?, f);
    funding.vout = 0;
    funding.internal_point = point_bytes(-ProjectivePoint::GENERATOR)?;
    assert!(funding.commitment().is_err());
    funding.internal_point = point_bytes(ProjectivePoint::GENERATOR)?;
    assert_eq!(funding.commitment()?, f);
    funding.amount = 0;
    assert!(funding.commitment().is_err());
    let mut recovery = RecoveryOpening {
        deployment: ctx.deployment,
        coin: ctx.coin,
        funding: f,
        salt: [21; 32],
        payout: auth_key(),
        fee: 1000,
        delay: RecoveryDelay::from_sequence(900)?,
    };
    let b = recovery.commitment()?;
    recovery.delay = RecoveryDelay::from_sequence(901)?;
    assert_ne!(recovery.commitment()?, b);
    recovery.delay = RecoveryDelay::from_sequence(900)?;
    recovery.payout = [0xff; 32];
    assert!(recovery.commitment().is_err());
    recovery.payout = auth_key();
    recovery.fee = 0;
    assert!(recovery.commitment().is_err());
    let alpha = Scalar::from(33_u64).to_bytes().into();
    let beta = Scalar::from(34_u64).to_bytes().into();
    let n = blinding_commitment(&ctx, &f, &b, &alpha, &beta, &[22; 32])?;
    assert_ne!(
        n,
        blinding_commitment(&ctx, &f, &b, &beta, &alpha, &[22; 32])?
    );
    assert!(blinding_commitment(&ctx, &f, &b, &[0; 32], &beta, &[22; 32]).is_err());
    assert!(blinding_commitment(&ctx, &f, &b, &[0xff; 32], &beta, &[22; 32]).is_err());
    assert!(blinding_commitment(&ctx, &f, &b, &alpha, &beta, &[0; 32]).is_err());
    Ok(())
}

#[test]
fn refresh_commitments_separate_roles_and_bind_recipient_context() -> Result<()> {
    let ctx = context();
    let intent = ctx.intent();
    let value = Scalar::from(33_u64).to_bytes().into();
    let salt = [23; 32];
    let mask = mask_commitment(&intent, &value, &salt)?;
    let masked = masked_share_commitment(&intent, &value, &salt)?;
    let delta = delta_commitment(&ctx, &value, &salt)?;
    assert_ne!(mask, masked);
    assert_ne!(mask, delta);
    assert_ne!(masked, delta);
    assert!(mask_commitment(&intent, &[0; 32], &salt).is_err());
    assert!(masked_share_commitment(&intent, &[0; 32], &salt).is_err());
    delta_commitment(&ctx, &[0; 32], &salt)?; // Legitimate zero delta is canonical.
    assert!(delta_commitment(&ctx, &[0xff; 32], &salt).is_err());
    let policy = policy_commitment(schedule())?;
    let bridge = bridge_commitment(
        &intent,
        &[24; 32],
        schedule().delay_after(0)?,
        &policy,
        &salt,
    )?;
    assert_ne!(
        bridge,
        bridge_commitment(
            &intent,
            &[24; 32],
            schedule().delay_after(1)?,
            &policy,
            &salt
        )?
    );
    let server = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(35_u64))?;
    let refresh = refresh_commitment(&ctx, &mask, &masked, &bridge, &delta, &server)?;
    let mut changed = ctx.clone();
    changed.session_auth = SigningKey::from_bytes(&[8; 32])?
        .verifying_key()
        .to_bytes()
        .into();
    assert_eq!(changed.intent_digest()?, ctx.intent_digest()?);
    assert_ne!(delta, delta_commitment(&changed, &value, &salt)?);
    assert_ne!(
        refresh,
        refresh_commitment(&changed, &mask, &masked, &bridge, &delta, &server)?
    );
    let claim = ClaimBinding {
        context: ctx,
        mask,
        masked_share: masked,
        bridge,
        delta,
        next_capability: [25; 32],
    };
    assert_eq!(claim.encode()?.len(), ClaimBinding::ENCODED_LEN);
    assert_ne!(claim.digest()?, refresh);
    Ok(())
}

#[test]
fn commitments_are_domain_separated_and_bind_each_identity() -> Result<()> {
    let (deployment, coin, operation, salt) = ([1; 32], [2; 32], [4; 32], [5; 32]);
    let owner: [u8; 32] = SigningKey::from_bytes(&salt)?.to_bytes().into();
    let other_owner: [u8; 32] = SigningKey::from_bytes(&[6; 32])?.to_bytes().into();
    let cap = capability_commitment(&deployment, &coin, &owner)?;
    assert_ne!(cap, salt);
    assert_ne!(cap, capability_commitment(&[2; 32], &coin, &owner)?);
    assert_ne!(cap, capability_commitment(&deployment, &[3; 32], &owner)?);
    assert_ne!(
        cap,
        capability_commitment(&deployment, &coin, &other_owner)?
    );
    assert!(capability_commitment(&deployment, &coin, &[0; 32]).is_err());
    let claim = recipient_claim_commitment(&deployment, &coin, &operation, &auth_key(), &salt)?;
    assert_ne!(claim, cap);
    assert_ne!(
        claim,
        recipient_claim_commitment(&deployment, &coin, &[9; 32], &auth_key(), &salt)?
    );
    assert_ne!(
        claim,
        recipient_claim_commitment(&deployment, &coin, &operation, &auth_key(), &[9; 32])?
    );
    assert!(
        recipient_claim_commitment(&deployment, &coin, &operation, &[0xff; 32], &salt).is_err()
    );
    Ok(())
}

#[test]
fn signing_binding_rejects_noncanonical_points_scalars_and_capability_reuse() -> Result<()> {
    let original = binding()?;
    assert_eq!(original.encode()?.len(), SigningBinding::ENCODED_LEN);
    for field in 0..9 {
        let mut altered = binding()?;
        match field {
            0 => altered.funding = [90; 32],
            1 => altered.previous_capability = [90; 32],
            2 => altered.next_capability = [90; 32],
            3 => altered.recovery = [90; 32],
            4 => altered.nonce_commitment = [90; 32],
            5 => {
                altered.draft_server =
                    point_bytes(ProjectivePoint::GENERATOR * Scalar::from(90_u64))?
            }
            6 => {
                altered.server_nonce =
                    point_bytes(ProjectivePoint::GENERATOR * Scalar::from(90_u64))?
            }
            7 => altered.blinded_challenge = Scalar::from(90_u64).to_bytes().into(),
            _ => altered.refresh_commitment = [90; 32],
        }
        assert_ne!(altered.digest()?, original.digest()?);
    }
    let mut altered = binding()?;
    altered.next_capability = altered.previous_capability;
    assert!(altered.encode().is_err());
    altered = binding()?;
    altered.draft_server = [0; 64];
    assert!(altered.encode().is_err());
    altered = binding()?;
    altered.server_nonce = [0; 64];
    assert!(altered.encode().is_err());
    altered = binding()?;
    altered.blinded_challenge = [0xff; 32];
    assert!(altered.encode().is_err());
    Ok(())
}

fn schedule() -> RecoverySchedule {
    RecoverySchedule {
        initial: 1000,
        gap: 100,
        margin: 20,
    }
}

#[test]
fn block_sequences_cannot_disable_or_change_relative_lock_units() -> Result<()> {
    for sequence in 1..=65535 {
        assert_eq!(RecoveryDelay::from_sequence(sequence)?.blocks(), sequence);
    }
    for sequence in [0, 65536, u32::MAX, (1 << 22) | 100, (1 << 31) | 100] {
        assert!(RecoveryDelay::from_sequence(sequence).is_err());
    }
    for bit in 16..32 {
        assert!(RecoveryDelay::from_sequence((1 << bit) | 100).is_err());
    }
    Ok(())
}

#[test]
fn exact_decrement_and_finite_ownership_budget_are_enforced() -> Result<()> {
    let p = schedule();
    let (alice, bob, carol) = (p.delay_after(0)?, p.delay_after(1)?, p.delay_after(2)?);
    assert_eq!(
        (alice.blocks(), bob.blocks(), carol.blocks()),
        (1000, 900, 800)
    );
    p.check_transition(alice, bob)?;
    p.check_transition(bob, carol)?;
    for index in 0..7 {
        let previous = p.delay_after(index)?;
        let next = p.delay_after(index + 1)?;
        assert_eq!(previous.blocks(), 1000 - index * 100);
        p.check_transition(previous, next)?;
    }
    let final_owner = p.delay_after(7)?;
    assert_eq!(final_owner.blocks(), 300);
    assert!(p.delay_after(8).is_err());
    assert!(
        p.check_transition(final_owner, RecoveryDelay::from_sequence(200)?)
            .is_err()
    );
    for wrong in [899, 901, 1000, 1100] {
        assert!(
            p.check_transition(alice, RecoveryDelay::from_sequence(wrong)?)
                .is_err()
        );
    }
    assert!(
        p.check_transition(
            RecoveryDelay::from_sequence(999)?,
            RecoveryDelay::from_sequence(899)?
        )
        .is_err()
    );
    for invalid in [
        RecoverySchedule { initial: 200, ..p },
        RecoverySchedule { initial: 719, ..p },
        RecoverySchedule {
            initial: u32::MAX,
            ..p
        },
        RecoverySchedule { gap: 0, ..p },
        RecoverySchedule { gap: u32::MAX, ..p },
        RecoverySchedule { margin: 0, ..p },
        RecoverySchedule { margin: 100, ..p },
    ] {
        assert!(invalid.delay_after(0).is_err());
    }
    RecoverySchedule { initial: 720, ..p }.validate()?;
    Ok(())
}

#[test]
fn bip68_first_eligible_block_and_late_transfer_boundaries() -> Result<()> {
    let p = schedule();
    let (bob, carol) = (p.delay_after(1)?, p.delay_after(2)?);
    // Activation at 100, Carol's 800-block recovery first valid at 900;
    // Bob's older 900-block recovery first valid at 1000.
    let window = p.confirmed_transfer_window(bob, carol, 100, 150, 2)?;
    assert_eq!(window.next_maturity, 900);
    assert_eq!(window.previous_maturity, 1000);
    assert_eq!(window.earliest_next_confirmation, 900);
    assert_eq!(window.last_required_confirmation, 901);
    assert_eq!(window.remaining_margin, 99);
    // At tip 978, confirmations in blocks 979 and 980 leave the 20-block margin.
    assert_eq!(
        p.confirmed_transfer_window(bob, carol, 100, 978, 2)?
            .remaining_margin,
        20
    );
    assert!(
        p.confirmed_transfer_window(bob, carol, 100, 979, 2)
            .is_err()
    );
    assert!(
        p.confirmed_transfer_window(bob, carol, 100, 999, 1)
            .is_err()
    );
    assert!(
        p.confirmed_transfer_window(bob, carol, 100, 1000, 1)
            .is_err()
    );
    assert!(p.confirmed_transfer_window(bob, carol, 100, 99, 1).is_err());
    assert!(
        p.confirmed_transfer_window(bob, carol, 100, 150, 0)
            .is_err()
    );
    // Checked in u64: neither height nor confirmation arithmetic may wrap.
    assert!(
        p.confirmed_transfer_window(bob, carol, 100, 150, u32::MAX)
            .is_err()
    );
    let high = p.confirmed_transfer_window(bob, carol, u32::MAX - 10, u32::MAX, 1)?;
    assert!(high.previous_maturity > u64::from(u32::MAX));
    Ok(())
}

#[test]
fn chain_snapshot_change_requires_rechecking_the_window() -> Result<()> {
    let p = schedule();
    let (bob, carol) = (p.delay_after(1)?, p.delay_after(2)?);
    p.confirmed_transfer_window(bob, carol, 100, 978, 2)?;
    // Tip advancement after authorization makes ordinary acceptance unsafe.
    assert!(
        p.confirmed_transfer_window(bob, carol, 100, 980, 2)
            .is_err()
    );
    // A changed activation confirmation height must be reflected, not cached.
    assert!(p.confirmed_transfer_window(bob, carol, 95, 978, 2).is_err());
    Ok(())
}
