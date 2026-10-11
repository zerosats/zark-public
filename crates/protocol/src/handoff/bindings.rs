//! Canonical handover, recipient claim and signing statements.
use super::{Digest, TransferContext, TransferIntent, nonzero, part};
use crate::{hash, point, scalar};
use anyhow::{Result, ensure};

/// The sender relation authenticates these openings against its claimed state.
/// A recursive wrapper must additionally prove that state has a valid origin
/// and lineage. No old recovery or server-point opening is public here.
pub struct HandoverBinding {
    pub intent: TransferIntent,
    pub funding: Digest,
    pub mask: Digest,
    pub masked_share: Digest,
    pub bridge: Digest,
    pub previous_capability: Digest,
    pub server_share: Digest,
    pub policy: Digest,
    pub draft_access: Digest,
}

impl HandoverBinding {
    pub const ENCODED_LEN: usize = TransferIntent::ENCODED_LEN + 8 * 32;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "handover binding length");
        let value = Self {
            intent: TransferIntent::decode(&bytes[..205])?,
            funding: part(bytes, 205),
            mask: part(bytes, 237),
            masked_share: part(bytes, 269),
            bridge: part(bytes, 301),
            previous_capability: part(bytes, 333),
            server_share: part(bytes, 365),
            policy: part(bytes, 397),
            draft_access: part(bytes, 429),
        };
        ensure!(value.encode()? == bytes, "noncanonical handover binding");
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.intent.encode()?;
        for value in [
            &self.funding,
            &self.mask,
            &self.masked_share,
            &self.bridge,
            &self.previous_capability,
            &self.server_share,
            &self.policy,
            &self.draft_access,
        ] {
            nonzero(value)?;
            out.extend_from_slice(value);
        }
        Ok(out)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/private-handoff/handover/v1",
            &self.encode()?,
        ]))
    }
}

/// Public inputs to the recipient claim/delta relation. This proof must be
/// checked against an already reserved, authenticated sender handover; it does
/// not itself prove origin, history, a refresh or a Bitcoin recovery signature.
pub struct ClaimBinding {
    pub context: TransferContext,
    pub mask: Digest,
    pub masked_share: Digest,
    pub bridge: Digest,
    pub delta: Digest,
    pub next_capability: Digest,
}

impl ClaimBinding {
    pub const ENCODED_LEN: usize = TransferContext::ENCODED_LEN + 5 * 32;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "claim binding length");
        let value = Self {
            context: TransferContext::decode(&bytes[..237])?,
            mask: part(bytes, 237),
            masked_share: part(bytes, 269),
            bridge: part(bytes, 301),
            delta: part(bytes, 333),
            next_capability: part(bytes, 365),
        };
        ensure!(value.encode()? == bytes, "noncanonical claim binding");
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.context.encode()?;
        for value in [
            &self.mask,
            &self.masked_share,
            &self.bridge,
            &self.delta,
            &self.next_capability,
        ] {
            nonzero(value)?;
            out.extend_from_slice(value);
        }
        Ok(out)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/private-handoff/claim-delta/v1",
            &self.encode()?,
        ]))
    }
}

/// Signer-visible request binding. It contains no recipient Bitcoin share point,
/// raw transaction, payout, address key, or received historical certificate.
/// The signer must reconstruct these values from its persisted operation and
/// verify the corresponding proof; accepting this encoding alone is unsafe.
pub struct SigningBinding {
    pub context: TransferContext,
    pub funding: Digest,
    pub refresh_commitment: Digest,
    pub previous_capability: Digest,
    pub next_capability: Digest,
    pub recovery: Digest,
    pub nonce_commitment: Digest,
    pub draft_server: [u8; 64],
    pub server_nonce: [u8; 64],
    pub blinded_challenge: Digest,
}

impl SigningBinding {
    pub const ENCODED_LEN: usize = TransferContext::ENCODED_LEN + 6 * 32 + 128 + 32;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "signing binding length");
        let value = Self {
            context: TransferContext::decode(&bytes[..237])?,
            funding: part(bytes, 237),
            refresh_commitment: part(bytes, 269),
            previous_capability: part(bytes, 301),
            next_capability: part(bytes, 333),
            recovery: part(bytes, 365),
            nonce_commitment: part(bytes, 397),
            draft_server: part(bytes, 429),
            server_nonce: part(bytes, 493),
            blinded_challenge: part(bytes, 557),
        };
        ensure!(value.encode()? == bytes, "noncanonical signing binding");
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.context.encode()?;
        for value in [
            &self.funding,
            &self.refresh_commitment,
            &self.previous_capability,
            &self.next_capability,
            &self.recovery,
            &self.nonce_commitment,
        ] {
            nonzero(value)?;
            out.extend_from_slice(value);
        }
        ensure!(
            self.previous_capability != self.next_capability,
            "ownership capability was not rotated"
        );
        point(&self.draft_server)?;
        point(&self.server_nonce)?;
        scalar(&self.blinded_challenge)?;
        out.extend_from_slice(&self.draft_server);
        out.extend_from_slice(&self.server_nonce);
        out.extend_from_slice(&self.blinded_challenge);
        Ok(out)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(crate::application_hash::hash(&[
            b"ZARK/private-handoff/signing/v1",
            &self.encode()?,
        ]))
    }
}
