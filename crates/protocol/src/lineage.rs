//! Canonical application-lineage statements. These encodings do not verify a
//! certificate, origin, current authority or Bitcoin chain state by themselves.
use crate::handoff::{
    Digest, HandoverBinding, PROTOCOL_VERSION, RecoverySchedule, SigningBinding, policy_commitment,
    validate_recursive_vk_hash,
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, VerifyingKey};

pub const ROLE_COUNT: usize = 6;
pub const DEPOSIT_AUTHORIZATION: usize = 0;
pub const SENDER_FROM_ORIGIN: usize = 1;
pub const SENDER_FROM_TRANSFER: usize = 2;
pub const RECEIVER_AUTHORIZATION: usize = 3;
pub const EXIT_FROM_ORIGIN: usize = 4;
pub const EXIT_FROM_TRANSFER: usize = 5;

fn validate_config(origin_key: &Digest, roles: &[Digest; ROLE_COUNT]) -> Result<()> {
    VerifyingKey::from_bytes(origin_key)?;
    ensure!(*origin_key != [0; 32], "empty lineage origin key");
    for (i, value) in roles.iter().enumerate() {
        validate_recursive_vk_hash(value)?;
        ensure!(
            !roles[..i].contains(value),
            "duplicate lineage circuit role hash"
        );
    }
    Ok(())
}

/// Loaded from an authenticated deployment, not accepted from the peer's proof.
#[derive(Clone)]
pub struct LineagePolicy {
    pub deployment: Digest,
    pub schedule: RecoverySchedule,
    pub origin_key: Digest,
    pub role_hashes: [Digest; ROLE_COUNT],
}

impl LineagePolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.deployment != [0; 32], "empty lineage deployment");
        self.schedule.validate()?;
        validate_config(&self.origin_key, &self.role_hashes)
    }

    pub fn require(
        &self,
        deployment: &Digest,
        policy: &Digest,
        origin: &Digest,
        roles: &[Digest; ROLE_COUNT],
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            *deployment == self.deployment
                && *policy == policy_commitment(self.schedule)?
                && *origin == self.origin_key
                && *roles == self.role_hashes,
            "lineage deployment, policy, origin or role configuration mismatch"
        );
        Ok(())
    }
}

pub struct LineageBinding {
    pub deployment: Digest,
    pub coin: Digest,
    pub funding: Digest,
    pub state: Digest,
    pub policy: Digest,
    pub origin_key: Digest,
    pub role_hashes: [Digest; ROLE_COUNT],
}

impl LineageBinding {
    pub const ENCODED_LEN: usize = 4 + (6 + ROLE_COUNT) * 32;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == Self::ENCODED_LEN,
            "lineage certificate length"
        );
        let (origin_key, role_hashes) = decode_config(&bytes[164..])?;
        let value = Self {
            deployment: part(bytes, 4),
            coin: part(bytes, 36),
            funding: part(bytes, 68),
            state: part(bytes, 100),
            policy: part(bytes, 132),
            origin_key,
            role_hashes,
        };
        ensure!(value.encode()? == bytes, "noncanonical lineage certificate");
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_config(&self.origin_key, &self.role_hashes)?;
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        for value in [
            &self.deployment,
            &self.coin,
            &self.funding,
            &self.state,
            &self.policy,
            &self.origin_key,
        ] {
            ensure!(*value != [0; 32], "empty lineage statement value");
            out.extend_from_slice(value);
        }
        for value in &self.role_hashes {
            out.extend_from_slice(value);
        }
        Ok(out)
    }

    pub fn origin_message(&self) -> Result<Digest> {
        self.encode()?;
        Ok(crate::application_hash::hash(&[
            b"ZARK/private-handoff/origin/v1",
            &PROTOCOL_VERSION.to_le_bytes(),
            &self.deployment,
            &self.coin,
            &self.funding,
            &self.state,
            &self.policy,
        ]))
    }

    /// A valid origin signature does not replace the initial recovery proof or
    /// permit another origin allocation. The signer must enforce one durable
    /// allocation per coin before exposing its attestation signing key operation.
    pub fn verify_origin_attestation(&self, signature: &[u8; 64]) -> Result<()> {
        VerifyingKey::from_bytes(&self.origin_key)?.verify_raw(
            &self.origin_message()?,
            &Signature::try_from(signature.as_slice())?,
        )?;
        Ok(())
    }
}

pub struct LineageHandoverBinding {
    pub handover: HandoverBinding,
    pub origin_key: Digest,
    pub role_hashes: [Digest; ROLE_COUNT],
}

/// The concrete request checked by the composed origin/transfer relation before
/// a usable signature contribution may be issued. Its role is chosen by the
/// current durable server phase, never by a proof-supplied flag.
pub struct IssuanceBinding {
    pub signing: SigningBinding,
    pub policy: Digest,
    pub origin_key: Digest,
    pub role_hashes: [Digest; ROLE_COUNT],
}

impl IssuanceBinding {
    pub const ENCODED_LEN: usize = SigningBinding::ENCODED_LEN + (3 + ROLE_COUNT) * 32;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "composed issuance length");
        let (origin_key, role_hashes) = decode_config(&bytes[653..])?;
        let value = Self {
            signing: SigningBinding::decode(&bytes[..589])?,
            policy: part(bytes, 621),
            origin_key,
            role_hashes,
        };
        ensure!(value.encode()? == bytes, "noncanonical composed issuance");
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_config(&self.origin_key, &self.role_hashes)?;
        ensure!(self.policy != [0; 32], "empty issuance policy");
        let mut out = self.signing.encode()?;
        out.extend_from_slice(&self.signing.digest()?);
        out.extend_from_slice(&self.policy);
        out.extend_from_slice(&self.origin_key);
        for value in &self.role_hashes {
            out.extend_from_slice(value);
        }
        Ok(out)
    }
}

impl LineageHandoverBinding {
    pub const ENCODED_LEN: usize = HandoverBinding::ENCODED_LEN + (1 + ROLE_COUNT) * 32;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "lineage handover length");
        let (origin_key, role_hashes) = decode_config(&bytes[461..])?;
        let value = Self {
            handover: HandoverBinding::decode(&bytes[..461])?,
            origin_key,
            role_hashes,
        };
        ensure!(value.encode()? == bytes, "noncanonical lineage handover");
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_config(&self.origin_key, &self.role_hashes)?;
        let mut out = self.handover.encode()?;
        out.extend_from_slice(&self.origin_key);
        for value in &self.role_hashes {
            out.extend_from_slice(value);
        }
        Ok(out)
    }
}

fn part(bytes: &[u8], offset: usize) -> Digest {
    let mut value = [0; 32];
    value.copy_from_slice(&bytes[offset..offset + 32]);
    value
}

fn decode_config(bytes: &[u8]) -> Result<(Digest, [Digest; ROLE_COUNT])> {
    ensure!(
        bytes.len() == (1 + ROLE_COUNT) * 32,
        "lineage role configuration length"
    );
    let origin = part(bytes, 0);
    let mut hashes = [[0; 32]; ROLE_COUNT];
    for (i, value) in hashes.iter_mut().enumerate() {
        *value = part(bytes, 32 + i * 32);
    }
    validate_config(&origin, &hashes)?;
    Ok((origin, hashes))
}
