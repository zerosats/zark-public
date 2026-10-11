//! Domain-separated cooperative-exit commitments. A well-formed commitment is
//! not authority to sign; the composed exit proof and current server phase are
//! checked before irreversible signature release.
use crate::{
    handoff::{Digest, FundingOpening, PROTOCOL_VERSION, TransferContext},
    point, scalar,
};
use anyhow::{Result, ensure};
use k256::schnorr::VerifyingKey;

fn nonzero(value: &Digest) -> Result<()> {
    ensure!(*value != [0; 32], "empty exit binding");
    Ok(())
}

pub fn intent(deployment: &Digest, coin: &Digest, operation: &Digest) -> Result<Digest> {
    for value in [deployment, coin, operation] {
        nonzero(value)?;
    }
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/exit-intent/v1",
        &PROTOCOL_VERSION.to_le_bytes(),
        deployment,
        coin,
        operation,
    ]))
}

pub fn validate_context(context: &TransferContext) -> Result<()> {
    context.encode()?;
    ensure!(
        context.recipient_claim == intent(&context.deployment, &context.coin, &context.operation)?
            && context.start_revision > 0
            && context.scope == crate::handoff::OperationScope::Single,
        "exit intent mismatch"
    );
    Ok(())
}

pub fn terminal_capability(context: &TransferContext) -> Result<Digest> {
    validate_context(context)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/exit-capability/v1",
        &context.encode()?,
    ]))
}

pub fn share_commitment(
    context: &TransferContext,
    funding: &Digest,
    server: &[u8; 64],
) -> Result<Digest> {
    validate_context(context)?;
    nonzero(funding)?;
    point(server)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/exit-share/v1",
        &context.encode()?,
        funding,
        server,
    ]))
}

pub struct ExitOpening {
    pub deployment: Digest,
    pub coin: Digest,
    pub funding: Digest,
    pub salt: Digest,
    pub destination: Digest,
    pub fee: u64,
}

impl ExitOpening {
    pub fn commitment(&self) -> Result<Digest> {
        for value in [
            &self.deployment,
            &self.coin,
            &self.funding,
            &self.salt,
            &self.destination,
        ] {
            nonzero(value)?;
        }
        VerifyingKey::from_bytes(&self.destination)?;
        ensure!(self.fee > 0 && self.fee <= 10_000, "exit fee bounds");
        Ok(crate::application_hash::hash(&[
            b"ZARK/private-handoff/exit/v1",
            &PROTOCOL_VERSION.to_le_bytes(),
            &self.deployment,
            &self.coin,
            &self.funding,
            &self.salt,
            &self.destination,
            &self.fee.to_le_bytes(),
        ]))
    }

    pub fn require_funding(&self, funding: &FundingOpening) -> Result<()> {
        ensure!(
            self.deployment == funding.deployment
                && self.coin == funding.coin
                && self.funding == funding.commitment()?,
            "exit funding mismatch"
        );
        self.commitment()?;
        ensure!(funding.amount > self.fee + 330, "exit output amount");
        Ok(())
    }
}

pub fn nonce_commitment(
    context: &TransferContext,
    funding: &Digest,
    exit: &Digest,
    alpha: &Digest,
    beta: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    validate_context(context)?;
    for value in [funding, exit, alpha, beta, salt] {
        nonzero(value)?;
    }
    scalar(alpha)?;
    scalar(beta)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/exit-nonce/v1",
        &context.encode()?,
        funding,
        exit,
        alpha,
        beta,
        salt,
    ]))
}
