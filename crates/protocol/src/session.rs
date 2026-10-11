//! Cheap authentication for independently generated private-handoff sessions.
//!
//! This proves possession of a session key, not ownership of a coin. Reservation
//! or recipient-claim proof binds that key to its allowed role; admission limits,
//! current-state checks, freshness and exact replay remain separate obligations.
use crate::{
    handoff::{Digest, TransferContext},
    hash, random32,
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    SenderReservation = 1,
    SenderHandover = 2,
    RecipientProposal = 3,
    RecoveryPreparation = 4,
    RecoveryIssuance = 5,
    OriginAcceptance = 6,
    SenderCompletion = 7,
    IssuedResponseRecovery = 8,
    SignerHead = 9,
    ExitPreparation = 10,
    ExitIssuance = 11,
    ExitResponseRecovery = 12,
    BootstrapAllocation = 13,
    BootstrapPreparation = 14,
    BootstrapFreeze = 15,
    BootstrapResponseRecovery = 16,
    BatchReservation = 17,
    BatchReadiness = 18,
    BatchAbort = 19,
    TransferCancellation = 20,
    TransferAcknowledgement = 21,
    DepositIssuance = 22,
}

fn message(context: &TransferContext, purpose: Purpose, request_digest: &Digest) -> Result<Digest> {
    ensure!(*request_digest != [0; 32], "empty session request digest");
    Ok(hash(&[
        b"ZARK/private-handoff/session-request/v1",
        &context.encode()?,
        &[purpose as u8],
        request_digest,
    ]))
}

/// The request digest covers the exact canonical body, including all proofs and
/// openings delivered to this role. The caller durably saves that body for retry.
pub fn sign_request(
    key: &SigningKey,
    context: &TransferContext,
    purpose: Purpose,
    request_digest: &Digest,
) -> Result<[u8; 64]> {
    let public: Digest = key.verifying_key().to_bytes().into();
    ensure!(
        public == context.session_auth,
        "session signing key mismatch"
    );
    Ok(key
        .sign_raw(&message(context, purpose, request_digest)?, &random32())?
        .to_bytes())
}

/// The handler chooses the expected purpose and reconstructs the body digest;
/// neither a caller-selected role nor a bare matching operation ID authorizes
/// access to a private response cache. This check never replaces the role proof.
pub fn verify_request(
    context: &TransferContext,
    expected_purpose: Purpose,
    expected_request_digest: &Digest,
    signature: &[u8; 64],
) -> Result<()> {
    VerifyingKey::from_bytes(&context.session_auth)?.verify_raw(
        &message(context, expected_purpose, expected_request_digest)?,
        &Signature::try_from(signature.as_slice())?,
    )?;
    Ok(())
}
