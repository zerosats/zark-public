//! Domain-separated commitments and origin sentinels.
use super::{
    Digest, INITIAL_OWNER_LIMIT, PROTOCOL_VERSION, RecoveryDelay, RecoverySchedule,
    TransferContext, TransferIntent, nonzero,
};
use crate::{point, scalar};
use anyhow::{Result, ensure};

/// Distinct bootstrap sentinels, not a fabricated predecessor state or an
/// ownership capability. Only the separately verified origin issuance path may
/// consume them; normal sender reservation/handover proofs cannot open them.
pub fn origin_previous_state(deployment: &Digest, coin: &Digest) -> Result<Digest> {
    nonzero(deployment)?;
    nonzero(coin)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/origin-predecessor/v1",
        &PROTOCOL_VERSION.to_le_bytes(),
        deployment,
        coin,
    ]))
}

pub fn origin_previous_capability(deployment: &Digest, coin: &Digest) -> Result<Digest> {
    nonzero(deployment)?;
    nonzero(coin)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/origin-capability/v1",
        &PROTOCOL_VERSION.to_le_bytes(),
        deployment,
        coin,
    ]))
}

/// Bootstrap has no preceding mask/delta refresh. Bind its separately allocated
/// server share and funding to the exact initial recipient session instead.
pub fn origin_refresh_commitment(
    context: &TransferContext,
    funding: &Digest,
    server: &[u8; 64],
) -> Result<Digest> {
    nonzero(funding)?;
    point(server)?;
    ensure!(
        context.previous_state == origin_previous_state(&context.deployment, &context.coin)?,
        "origin predecessor mismatch"
    );
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/origin-refresh/v1",
        &context.encode()?,
        funding,
        server,
    ]))
}
/// Commit to the canonical public key of an independently generated owner key.
/// The secret must be normalized, not an arbitrary preimage or retry key.
pub fn capability_commitment(
    deployment: &Digest,
    coin: &Digest,
    capability: &Digest,
) -> Result<Digest> {
    nonzero(deployment)?;
    nonzero(coin)?;
    let key = crate::owner_auth::normalized_key(capability)?;
    crate::owner_auth::public_capability_commitment(
        deployment,
        coin,
        &key.verifying_key().to_bytes().into(),
    )
}

/// One operation's confidential draft-admission token; never issuance authority.
pub fn draft_access_commitment(intent: &TransferIntent, token: &Digest) -> Result<Digest> {
    nonzero(token)?;
    ensure!(
        intent.start_revision > 0,
        "draft access requires accepted revision"
    );
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/draft-access/v1",
        &intent.encode()?,
        token,
    ]))
}

/// These fields are opened only inside the receiver's proof. Do not send the
/// address key or salt to the signer in a claim request.
pub fn recipient_claim_commitment(
    deployment: &Digest,
    coin: &Digest,
    operation: &Digest,
    address_claim_key: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    for value in [deployment, coin, operation, address_claim_key, salt] {
        nonzero(value)?;
    }
    k256::schnorr::VerifyingKey::from_bytes(address_claim_key)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/recipient/v1",
        &PROTOCOL_VERSION.to_le_bytes(),
        deployment,
        coin,
        operation,
        address_claim_key,
        salt,
    ]))
}

fn hidden_scalar_commitment(
    domain: &[u8],
    binding: &[u8],
    value: &Digest,
    salt: &Digest,
    require_nonzero: bool,
) -> Result<Digest> {
    scalar(value)?;
    if require_nonzero {
        nonzero(value)?;
    }
    nonzero(salt)?;
    Ok(crate::application_hash::hash(&[
        domain, binding, value, salt,
    ]))
}

/// Opening is restricted to signer and sender. Never send it to the receiver.
pub fn mask_commitment(intent: &TransferIntent, mask: &Digest, salt: &Digest) -> Result<Digest> {
    hidden_scalar_commitment(
        b"ZARK/private-handoff/mask/v1",
        &intent.digest()?,
        mask,
        salt,
        true,
    )
}

/// Opening is restricted to sender and receiver. Never send it to the signer.
pub fn masked_share_commitment(
    intent: &TransferIntent,
    masked_share: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    hidden_scalar_commitment(
        b"ZARK/private-handoff/masked-share/v1",
        &intent.digest()?,
        masked_share,
        salt,
        true,
    )
}

/// Opening is restricted to receiver and signer. The sender knows the masked
/// share and would recover the receiver's private share if it learned delta.
pub fn delta_commitment(
    context: &TransferContext,
    delta: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    hidden_scalar_commitment(
        b"ZARK/private-handoff/delta/v1",
        &context.encode()?,
        delta,
        salt,
        false,
    )
}

/// A policy commitment does not hide the public deployment recovery parameters.
pub fn policy_commitment(schedule: RecoverySchedule) -> Result<Digest> {
    schedule.validate()?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/policy/v1",
        &PROTOCOL_VERSION.to_le_bytes(),
        &schedule.initial.to_le_bytes(),
        &schedule.gap.to_le_bytes(),
        &schedule.margin.to_le_bytes(),
        &INITIAL_OWNER_LIMIT.to_le_bytes(),
    ]))
}

/// Common predecessor facts that a sender relation must authenticate against its
/// private certificate. Hashing a claimed delay alone does not authenticate it.
pub fn bridge_commitment(
    intent: &TransferIntent,
    funding: &Digest,
    previous_delay: RecoveryDelay,
    policy: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    for value in [funding, policy, salt] {
        nonzero(value)?;
    }
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/bridge/v1",
        &intent.digest()?,
        funding,
        &previous_delay.blocks().to_le_bytes(),
        policy,
        salt,
    ]))
}

/// The signer reconstructs this from verified, stored commitments and its actual
/// computed draft point; a caller-selected digest is not a verified refresh.
pub fn refresh_commitment(
    context: &TransferContext,
    mask: &Digest,
    masked_share: &Digest,
    bridge: &Digest,
    delta: &Digest,
    draft_server: &[u8; 64],
) -> Result<Digest> {
    for value in [mask, masked_share, bridge, delta] {
        nonzero(value)?;
    }
    point(draft_server)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/refresh/v1",
        &context.encode()?,
        mask,
        masked_share,
        bridge,
        delta,
        draft_server,
    ]))
}

pub fn issuance_commitment(binding_digest: &Digest, partial: &Digest) -> Result<Digest> {
    nonzero(binding_digest)?;
    scalar(partial)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/issuance/v1",
        binding_digest,
        partial,
    ]))
}

/// Must be durably fixed before the server releases its nonce. Alpha, beta and
/// salt remain private witnesses; this helper itself proves no signing relation.
pub fn blinding_commitment(
    context: &TransferContext,
    funding: &Digest,
    recovery: &Digest,
    alpha: &Digest,
    beta: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    for value in [funding, recovery, alpha, beta, salt] {
        nonzero(value)?;
    }
    scalar(alpha)?;
    scalar(beta)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/nonce/v1",
        &context.encode()?,
        funding,
        recovery,
        alpha,
        beta,
        salt,
    ]))
}
