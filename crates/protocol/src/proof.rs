//! Native verification of pinned protocol relations and composed certificates.
//!
//! A verified relation is not a completed ownership certificate or permission to
//! sign. Signing requires the composed role and current state. Registry pins and
//! expected statements come from authenticated local configuration/state, never a proof.
use crate::{
    assets::{AuthenticatedFile, MAX_EXECUTABLE_BYTES, VK_BYTES, read_bounded},
    handoff::Digest,
    hash,
    lineage::{IssuanceBinding, LineageHandoverBinding, LineagePolicy},
    verifier::verify_proof,
};
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Exact pinned BB5.2 ZK UltraHonk proof shape qualified by the protocol suite.
pub const PROOF_BYTES: usize = 458 * 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Relation {
    DepositAuthorization,
    SenderFromOrigin,
    SenderFromTransfer,
    ReceiverAuthorization,
    ExitFromOrigin,
    ExitFromTransfer,
}

/// This checksum must be obtained through the authenticated deployment process.
/// A proof-supplied checksum does not authenticate its own executable or key.
pub struct ArtifactPin {
    pub path: PathBuf,
    pub sha256: Digest,
}

impl ArtifactPin {
    fn authenticate(self) -> Result<AuthenticatedArtifact> {
        ensure!(
            self.sha256 != [0; 32],
            "empty private relation artifact pin"
        );
        let file = AuthenticatedFile::new(&self.path, &self.sha256, MAX_EXECUTABLE_BYTES)?;
        Ok(AuthenticatedArtifact { pin: self, file })
    }
}

struct AuthenticatedArtifact {
    pin: ArtifactPin,
    file: AuthenticatedFile,
}
impl AuthenticatedArtifact {
    fn check(&self) -> Result<()> {
        self.file.check(&self.pin.path)
    }
}

/// Constructed only after successful external verification. Its meaning is
/// limited to `relation()`: for example recovery completion proves an actual
/// signature, but not history, current ownership, live backing or safe maturity.
pub struct VerifiedRelation {
    relation: Relation,
    statement_digest: Digest,
}

impl VerifiedRelation {
    pub fn relation(&self) -> Relation {
        self.relation
    }
    pub fn statement_digest(&self) -> Digest {
        self.statement_digest
    }
}

pub struct PinnedVerifier {
    deployment: Digest,
    bb: AuthenticatedArtifact,
    crs: PathBuf,
    keys: BTreeMap<Relation, AuthenticatedArtifact>,
    lineage_policy: Option<LineagePolicy>,
    // Mathematical verification only, scoped to this immutable deployment,
    // executable and VK registry. Never caches ownership or live chain state.
    verified: Mutex<VecDeque<(Relation, Digest, Digest)>>,
}

impl PinnedVerifier {
    /// Exact authenticated public VK fields for a private recursive witness.
    /// This is not a proof verification result or signing authorization.
    pub fn recursive_key_bytes(&self, relation: Relation) -> Result<Vec<u8>> {
        let pin = self
            .keys
            .get(&relation)
            .ok_or_else(|| anyhow::anyhow!("unregistered recursive role"))?;
        pin.check()?;
        let bytes = read_bounded(&pin.pin.path, VK_BYTES)?;
        ensure!(
            bytes.len() == 115 * 32 && hash(&[&bytes]) == pin.pin.sha256,
            "recursive VK artifact mismatch"
        );
        Ok(bytes)
    }

    pub fn new(
        deployment: Digest,
        bb: ArtifactPin,
        crs: PathBuf,
        keys: impl IntoIterator<Item = (Relation, ArtifactPin)>,
    ) -> Result<Self> {
        ensure!(deployment != [0; 32], "empty private relation deployment");
        let bb = bb.authenticate()?;
        let mut registry = BTreeMap::new();
        for (role, pin) in keys {
            let pin = pin.authenticate()?;
            ensure!(
                registry.insert(role, pin).is_none(),
                "duplicate private relation role"
            );
        }
        ensure!(!registry.is_empty(), "empty private relation registry");
        Ok(Self {
            deployment,
            bb,
            crs,
            keys: registry,
            lineage_policy: None,
            verified: Mutex::new(VecDeque::new()),
        })
    }

    /// The trusted manifest must bind these recursive hashes to the exact binary
    /// VK pins. Configuring a peer's hash array here would defeat authentication.
    pub fn with_lineage_policy(mut self, policy: LineagePolicy) -> Result<Self> {
        ensure!(
            self.lineage_policy.is_none(),
            "lineage policy already configured"
        );
        policy.validate()?;
        ensure!(
            self.deployment == policy.deployment,
            "lineage deployment mismatch"
        );
        for role in crate::deployment::RELATIONS {
            ensure!(self.keys.contains_key(&role), "missing lineage role pin");
        }
        self.lineage_policy = Some(policy);
        Ok(self)
    }

    fn lineage_policy(&self) -> Result<&LineagePolicy> {
        self.lineage_policy
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("lineage policy is not pinned"))
    }

    pub fn sender_handover(
        &self,
        predecessor: crate::certificate::PredecessorKind,
        binding: &LineageHandoverBinding,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedRelation> {
        self.lineage_policy()?.require(
            &binding.handover.intent.deployment,
            &binding.handover.policy,
            &binding.origin_key,
            &binding.role_hashes,
        )?;
        self.verify(
            match predecessor {
                crate::certificate::PredecessorKind::Origin => Relation::SenderFromOrigin,
                crate::certificate::PredecessorKind::Transfer => Relation::SenderFromTransfer,
            },
            &binding.handover.intent.deployment,
            &binding.encode()?,
            proof,
            scratch,
        )
    }

    pub fn receiver_authorization(
        &self,
        binding: &IssuanceBinding,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedRelation> {
        self.lineage_policy()?.require(
            &binding.signing.context.deployment,
            &binding.policy,
            &binding.origin_key,
            &binding.role_hashes,
        )?;
        self.verify(
            Relation::ReceiverAuthorization,
            &binding.signing.context.deployment,
            &binding.encode()?,
            proof,
            scratch,
        )
    }

    pub fn deposit_authorization(
        &self,
        binding: &crate::deposit::DepositBinding,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedRelation> {
        let authorization = &binding.authorization;
        self.lineage_policy()?.require(
            &authorization.signing.context.deployment,
            &authorization.policy,
            &authorization.origin_key,
            &authorization.role_hashes,
        )?;
        self.verify(
            Relation::DepositAuthorization,
            &authorization.signing.context.deployment,
            &binding.encode()?,
            proof,
            scratch,
        )
    }

    pub fn cooperative_exit(
        &self,
        predecessor: crate::certificate::PredecessorKind,
        binding: &IssuanceBinding,
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedRelation> {
        self.lineage_policy()?.require(
            &binding.signing.context.deployment,
            &binding.policy,
            &binding.origin_key,
            &binding.role_hashes,
        )?;
        crate::exit::validate_context(&binding.signing.context)?;
        ensure!(
            binding.signing.next_capability
                == crate::exit::terminal_capability(&binding.signing.context)?
                && binding.signing.refresh_commitment
                    == crate::exit::share_commitment(
                        &binding.signing.context,
                        &binding.signing.funding,
                        &binding.signing.draft_server
                    )?,
            "cooperative exit terminal binding mismatch"
        );
        self.verify(
            match predecessor {
                crate::certificate::PredecessorKind::Origin => Relation::ExitFromOrigin,
                crate::certificate::PredecessorKind::Transfer => Relation::ExitFromTransfer,
            },
            &binding.signing.context.deployment,
            &binding.encode()?,
            proof,
            scratch,
        )
    }

    fn verify(
        &self,
        relation: Relation,
        deployment: &Digest,
        public_bytes: &[u8],
        proof: &[u8],
        scratch: &Path,
    ) -> Result<VerifiedRelation> {
        ensure!(
            *deployment == self.deployment,
            "private relation deployment mismatch"
        );
        ensure!(proof.len() == PROOF_BYTES, "private relation proof length");
        let pin = self
            .keys
            .get(&relation)
            .ok_or_else(|| anyhow::anyhow!("unregistered private relation role"))?;
        // Paths and filesystem ownership must come from trusted configuration.
        // Retained authenticated files check identity AND exact contents on
        // every call, including cache hits, without repeating SHA256 each time.
        {
            let _timing =
                crate::timing::Span::new(crate::timing::Phase::VerifierAssetAuthentication);
            self.bb.check()?;
            pin.check()?;
        }
        let statement_digest = hash(&[public_bytes]);
        let cache_key = (relation, statement_digest, hash(&[proof]));
        if self
            .verified
            .lock()
            .map_err(|_| anyhow::anyhow!("verification cache poisoned"))?
            .contains(&cache_key)
        {
            crate::timing::record(
                crate::timing::Phase::VerificationCacheHit,
                std::time::Duration::ZERO,
            );
            return Ok(VerifiedRelation {
                relation,
                statement_digest,
            });
        }
        let _timing = crate::timing::Span::new(crate::timing::Phase::ExternalVerification);
        verify_proof(
            &self.bb.pin.path,
            &pin.pin.path,
            &self.crs,
            scratch,
            proof,
            public_bytes,
        )?;
        self.bb.check()?;
        pin.check()?;
        // Only successful, exact verification enters this bounded process-local
        // cache. Pin checks above still run on hits, and no lock spans a child.
        let mut verified = self
            .verified
            .lock()
            .map_err(|_| anyhow::anyhow!("verification cache poisoned"))?;
        if verified.len() == 128 {
            verified.pop_front();
        }
        verified.push_back(cache_key);
        Ok(VerifiedRelation {
            relation,
            statement_digest,
        })
    }
}

#[cfg(test)]
mod cache_tests;
