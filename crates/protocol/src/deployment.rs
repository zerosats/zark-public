//! Authenticated deployment and proof-suite configuration.
//!
//! A manifest is trusted only after its digest is authenticated out of band.
//! Files received alongside a proof cannot configure their own verifier.
use crate::{
    assets::{MAX_CIRCUIT_BYTES, MAX_VK_METADATA_BYTES, VK_BYTES, read_bounded},
    handoff::{
        Digest, PROTOCOL_VERSION, RecoverySchedule, policy_commitment, validate_recursive_vk_hash,
    },
    hash, hex32,
    lineage::{LineagePolicy, ROLE_COUNT},
    proof::{ArtifactPin, PinnedVerifier, Relation},
};
use anyhow::{Result, ensure};
use k256::schnorr::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Authenticated signer semantics for the fresh alpha deployment: 2–10-member atomic batches,
/// single-proof atomic deposit issuance, ordinary transfer cancellation, and
/// reserved completion/exit admission.
/// This is independently pinned alongside the v10 proof statement format.
pub const SIGNER_PROTOCOL_VERSION: u32 = 5;

pub const ROLE_NAMES: [&str; 6] = [
    "deposit_authorization",
    "sender_from_origin",
    "sender_from_transfer",
    "receiver_authorization",
    "exit_from_origin",
    "exit_from_transfer",
];
pub const PUBLIC_BYTES: [u32; 6] = [1466, 685, 685, 877, 877, 877];
pub const RELATIONS: [Relation; 6] = [
    Relation::DepositAuthorization,
    Relation::SenderFromOrigin,
    Relation::SenderFromTransfer,
    Relation::ReceiverAuthorization,
    Relation::ExitFromOrigin,
    Relation::ExitFromTransfer,
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolePin {
    pub role: String,
    /// Exact compiled Noir artifact consumed by the local prover.
    pub compiled_artifact_sha256: String,
    /// SHA256 of the exact 115-field binary VK generated in the qualified run.
    pub vk_sha256: String,
    /// Canonical BB field hash of that key, taken from the same qualified run.
    pub recursive_hash: String,
    /// SHA256 pins the complete matching BB JSON key metadata as well.
    pub metadata_sha256: String,
    pub public_bytes: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub protocol_version: u32,
    pub noir_version: String,
    pub bb_version: String,
    pub verifier_target: String,
    pub roles: Vec<RolePin>,
}

fn canonical_nonzero(value: &str) -> Result<Digest> {
    let bytes = hex32(value)?;
    ensure!(
        bytes != [0; 32] && hex::encode(bytes) == value,
        "noncanonical or empty manifest digest"
    );
    Ok(bytes)
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION
                && self.noir_version == "1.0.0-beta.25"
                && self.bb_version == "5.2.0"
                && self.verifier_target == "noir-recursive",
            "unsupported private proof suite"
        );
        ensure!(
            self.roles.len() == ROLE_NAMES.len(),
            "private suite role count"
        );
        let mut hashes = Vec::new();
        for (i, pin) in self.roles.iter().enumerate() {
            ensure!(
                pin.role == ROLE_NAMES[i] && pin.public_bytes == PUBLIC_BYTES[i],
                "private suite role order or ABI"
            );
            canonical_nonzero(&pin.vk_sha256)?;
            canonical_nonzero(&pin.compiled_artifact_sha256)?;
            canonical_nonzero(&pin.metadata_sha256)?;
            let field_hash = canonical_nonzero(&pin.recursive_hash)?;
            validate_recursive_vk_hash(&field_hash)?;
            ensure!(
                !hashes.contains(&field_hash),
                "duplicate private suite role"
            );
            hashes.push(field_hash);
        }
        Ok(())
    }

    pub fn id(&self) -> Result<Digest> {
        self.validate()?;
        // Fixed role order and fixed tool versions above make this unambiguous.
        let mut bytes =
            b"ZARK/private-suite/v1\0noir-1.0.0-beta.25\0bb-5.2.0\0noir-recursive\0".to_vec();
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        for (i, pin) in self.roles.iter().enumerate() {
            bytes.push(i as u8);
            bytes.extend_from_slice(&canonical_nonzero(&pin.compiled_artifact_sha256)?);
            bytes.extend_from_slice(&canonical_nonzero(&pin.vk_sha256)?);
            bytes.extend_from_slice(&canonical_nonzero(&pin.recursive_hash)?);
            bytes.extend_from_slice(&canonical_nonzero(&pin.metadata_sha256)?);
            bytes.extend_from_slice(&pin.public_bytes.to_le_bytes());
        }
        Ok(hash(&[&bytes]))
    }

    pub fn role_hashes(&self) -> Result<[Digest; ROLE_COUNT]> {
        self.validate()?;
        let mut hashes = [[0; 32]; ROLE_COUNT];
        for (out, pin) in hashes.iter_mut().zip(&self.roles) {
            *out = canonical_nonzero(&pin.recursive_hash)?;
        }
        Ok(hashes)
    }

    /// Checks binary/JSON byte equality and pinned metadata. This does not
    /// independently recompute Poseidon2; qualification must derive both from
    /// the same compiled artifact with the pinned BB binary. Recursive circuits
    /// also constrain each supplied key to its authenticated field hash.
    pub fn check_artifacts(&self, directory: &Path) -> Result<Vec<(Relation, ArtifactPin)>> {
        self.validate()?;
        let mut result = Vec::new();
        for (i, pin) in self.roles.iter().enumerate() {
            let compiled = read_bounded(
                &directory.join(&pin.role).join("circuit.json"),
                MAX_CIRCUIT_BYTES,
            )?;
            ensure!(
                hash(&[&compiled]) == canonical_nonzero(&pin.compiled_artifact_sha256)?,
                "private compiled circuit artifact mismatch"
            );
            let path = directory.join(&pin.role).join("vk");
            let binary = read_bounded(&path, VK_BYTES)?;
            ensure!(
                binary.len() == 115 * 32 && hash(&[&binary]) == canonical_nonzero(&pin.vk_sha256)?,
                "private VK artifact mismatch"
            );
            let raw = read_bounded(
                &directory.join(&pin.role).join("vk.json"),
                MAX_VK_METADATA_BYTES,
            )?;
            ensure!(
                raw.len() <= 16_384 && hash(&[&raw]) == canonical_nonzero(&pin.metadata_sha256)?,
                "private VK metadata mismatch"
            );
            let metadata: KeyMetadata = serde_json::from_slice(&raw)?;
            ensure!(
                metadata.vk.len() == 115
                    && metadata.bb_version == self.bb_version
                    && metadata.scheme == "ultra_honk",
                "private VK metadata version, scheme or shape"
            );
            ensure!(
                metadata.hash == format!("0x{}", pin.recursive_hash),
                "private VK recursive hash mismatch"
            );
            let mut fields = Vec::with_capacity(binary.len());
            for value in &metadata.vk {
                let text = value
                    .strip_prefix("0x")
                    .ok_or_else(|| anyhow::anyhow!("VK field encoding"))?;
                let field = hex32(text)?;
                ensure!(hex::encode(field) == text, "noncanonical VK field");
                fields.extend_from_slice(&field);
            }
            ensure!(
                fields == binary,
                "binary and recursive VK metadata disagree"
            );
            let mut count = [0; 32];
            // Eight recursion accumulator fields precede the packed statement.
            count[28..].copy_from_slice(&(pin.public_bytes.div_ceil(31) + 8).to_be_bytes());
            ensure!(binary[32..64] == count, "VK public-input ABI mismatch");
            result.push((
                RELATIONS[i],
                ArtifactPin {
                    path,
                    sha256: canonical_nonzero(&pin.vk_sha256)?,
                },
            ));
        }
        Ok(result)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyMetadata {
    vk: Vec<String>,
    hash: String,
    bb_version: String,
    scheme: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub protocol_version: u32,
    /// Required: old deployment documents must not silently acquire new semantics.
    pub signer_protocol_version: u32,
    pub network: crate::network::Network,
    pub genesis_hash: String,
    pub signet_challenge: String,
    pub initial_delay: u32,
    pub gap: u32,
    pub margin: u32,
    pub origin_key: String,
    pub control_key: String,
    pub suite: String,
}

impl Deployment {
    pub fn schedule(&self) -> RecoverySchedule {
        RecoverySchedule {
            initial: self.initial_delay,
            gap: self.gap,
            margin: self.margin,
        }
    }

    pub fn id(&self) -> Result<Digest> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported private deployment version"
        );
        ensure!(
            self.signer_protocol_version == SIGNER_PROTOCOL_VERSION,
            "unsupported signer protocol version"
        );
        let genesis = canonical_nonzero(&self.genesis_hash)?;
        let challenge = hex::decode(&self.signet_challenge)?;
        ensure!(
            challenge.len() <= 10_000 && hex::encode(&challenge) == self.signet_challenge,
            "noncanonical Signet challenge"
        );
        let tag = match self.network {
            crate::network::Network::Regtest => {
                ensure!(
                    self.genesis_hash == crate::network::REGTEST_GENESIS && challenge.is_empty(),
                    "private regtest identity"
                );
                0
            }
            crate::network::Network::CustomSignet => {
                ensure!(
                    self.genesis_hash != crate::network::REGTEST_GENESIS && !challenge.is_empty(),
                    "private Signet identity"
                );
                1
            }
        };
        let origin = canonical_nonzero(&self.origin_key)?;
        let control = canonical_nonzero(&self.control_key)?;
        VerifyingKey::from_bytes(&origin)?;
        VerifyingKey::from_bytes(&control)?;
        ensure!(
            origin != control,
            "origin and control keys must be independent"
        );
        Ok(hash(&[
            b"ZARK/private-deployment/v2",
            &PROTOCOL_VERSION.to_le_bytes(),
            &self.signer_protocol_version.to_le_bytes(),
            &[tag],
            &genesis,
            &(challenge.len() as u32).to_le_bytes(),
            &challenge,
            &policy_commitment(self.schedule())?,
            &origin,
            &control,
            &canonical_nonzero(&self.suite)?,
        ]))
    }

    pub fn lineage_policy(&self, manifest: &Manifest) -> Result<LineagePolicy> {
        ensure!(
            canonical_nonzero(&self.suite)? == manifest.id()?,
            "private deployment suite mismatch"
        );
        let policy = LineagePolicy {
            deployment: self.id()?,
            schedule: self.schedule(),
            origin_key: canonical_nonzero(&self.origin_key)?,
            role_hashes: manifest.role_hashes()?,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn verifier(
        &self,
        manifest: &Manifest,
        keys: &Path,
        bb: ArtifactPin,
        crs: &Path,
    ) -> Result<PinnedVerifier> {
        let policy = self.lineage_policy(manifest)?;
        PinnedVerifier::new(
            policy.deployment,
            bb,
            crs.to_path_buf(),
            manifest.check_artifacts(keys)?,
        )?
        .with_lineage_policy(policy)
    }
}
