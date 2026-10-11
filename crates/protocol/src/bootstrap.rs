//! Blind authorization of the one permitted joint-parent activation.
//!
//! This binding is verified inside the single deposit authorization. Both
//! nonce responses are issued atomically only after that proof passes. The
//! owner completes and saves both transactions before funding is published.
use crate::{
    handoff::{Digest, TransferContext, origin_previous_state},
    point, scalar,
};
use anyhow::{Result, ensure};
use k256::Scalar;

pub const ENCODED_LEN: usize = TransferContext::ENCODED_LEN + 352;
pub const PUBLIC_BYTES: usize = ENCODED_LEN + 32;

pub fn validate_context(context: &TransferContext) -> Result<()> {
    context.encode()?;
    ensure!(
        context.previous_state == origin_previous_state(&context.deployment, &context.coin)?
            && context.start_revision == 0
            && context.scope == crate::handoff::OperationScope::Single,
        "bootstrap requires a fresh origin context"
    );
    Ok(())
}

/// Both server points are allocated and frozen by the service before this
/// statement is constructed. Neither point is a recipient/user share.
pub struct BootstrapBinding {
    pub context: TransferContext,
    pub parent_funding: Digest,
    pub active_funding: Digest,
    pub initial_capability: Digest,
    pub parent_server: [u8; 64],
    pub active_server: [u8; 64],
    pub nonce_commitment: Digest,
    pub parent_nonce: [u8; 64],
    pub blinded_challenge: Digest,
}

impl BootstrapBinding {
    pub const ENCODED_LEN: usize = ENCODED_LEN;
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_context(&self.context)?;
        for v in [
            &self.parent_funding,
            &self.active_funding,
            &self.initial_capability,
            &self.nonce_commitment,
        ] {
            ensure!(*v != [0; 32], "zero bootstrap commitment");
        }
        ensure!(
            self.parent_funding != self.active_funding,
            "distinct bootstrap outputs required"
        );
        point(&self.parent_server)?;
        point(&self.active_server)?;
        point(&self.parent_nonce)?;
        ensure!(
            self.parent_server == self.active_server,
            "deposit and recovery require the same current authority"
        );
        scalar(&self.blinded_challenge)?;
        let mut bytes = self.context.encode()?;
        bytes.extend_from_slice(&self.parent_funding);
        bytes.extend_from_slice(&self.active_funding);
        bytes.extend_from_slice(&self.initial_capability);
        bytes.extend_from_slice(&self.parent_server);
        bytes.extend_from_slice(&self.active_server);
        bytes.extend_from_slice(&self.nonce_commitment);
        bytes.extend_from_slice(&self.parent_nonce);
        bytes.extend_from_slice(&self.blinded_challenge);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == ENCODED_LEN, "bootstrap binding length");
        let value = Self {
            context: TransferContext::decode(&bytes[..237])?,
            parent_funding: bytes[237..269].try_into()?,
            active_funding: bytes[269..301].try_into()?,
            initial_capability: bytes[301..333].try_into()?,
            parent_server: bytes[333..397].try_into()?,
            active_server: bytes[397..461].try_into()?,
            nonce_commitment: bytes[461..493].try_into()?,
            parent_nonce: bytes[493..557].try_into()?,
            blinded_challenge: bytes[557..589].try_into()?,
        };
        ensure!(value.encode()? == bytes, "noncanonical bootstrap binding");
        Ok(value)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(crate::application_hash::hash(&[
            b"ZARK/private-handoff/bootstrap-signing/v1",
            &self.encode()?,
        ]))
    }
    pub fn public_inputs(&self) -> Result<Vec<u8>> {
        let mut bytes = self.encode()?;
        bytes.extend_from_slice(&self.digest()?);
        Ok(bytes)
    }
}

pub fn nonce_commitment(
    context: &TransferContext,
    parent: &Digest,
    active: &Digest,
    capability: &Digest,
    alpha: &Digest,
    beta: &Digest,
    salt: &Digest,
) -> Result<Digest> {
    validate_context(context)?;
    for v in [parent, active, capability, salt] {
        ensure!(*v != [0; 32], "zero bootstrap nonce opening");
    }
    ensure!(parent != active, "distinct bootstrap outputs required");
    ensure!(
        scalar(alpha)? != Scalar::ZERO && scalar(beta)? != Scalar::ZERO,
        "zero bootstrap blinding"
    );
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/bootstrap-nonce/v1",
        &context.encode()?,
        parent,
        active,
        capability,
        alpha,
        beta,
        salt,
    ]))
}
