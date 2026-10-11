//! Private ownership certificates anchored to the authenticated deposit issuer.
use crate::{
    deposit::DepositBinding,
    handoff::{Digest, ServerShareOpening, StateOpening, TransferContext, issuance_commitment},
    hash,
    lineage::{DEPOSIT_AUTHORIZATION, IssuanceBinding, LineageBinding, RECEIVER_AUTHORIZATION},
    point,
    proof::{PROOF_BYTES, PinnedVerifier},
    scalar,
    wire::{Command, Request},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredecessorKind {
    Origin,
    Transfer,
}

pub enum OwnerCertificate {
    OriginIssued {
        authorization: Vec<u8>,
        proof: Vec<u8>,
        partial: Digest,
        activation_partial: Digest,
        server_salt: Digest,
        origin_signature: Vec<u8>,
    },
    TransferIssued {
        authorization: Vec<u8>,
        proof: Vec<u8>,
        partial: Digest,
        server_salt: Digest,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PrivateRecord {
    OriginIssued {
        authorization: String,
        proof: String,
        partial: String,
        activation_partial: String,
        server_salt: String,
        origin_signature: String,
    },
    TransferIssued {
        authorization: String,
        proof: String,
        partial: String,
        server_salt: String,
    },
}

pub fn verify_partial(
    server: &[u8; 64],
    nonce: &[u8; 64],
    challenge: &Digest,
    partial: &Digest,
) -> Result<()> {
    ensure!(
        k256::ProjectivePoint::GENERATOR * scalar(partial)?
            == point(nonce)? + point(server)? * scalar(challenge)?,
        "invalid signing response"
    );
    Ok(())
}

/// Reconstructing a state is not proof verification or evidence of signer origin.
pub fn issued_lineage(
    a: &IssuanceBinding,
    partial: Digest,
    server_salt: Digest,
) -> Result<LineageBinding> {
    let s = &a.signing;
    verify_partial(
        &s.draft_server,
        &s.server_nonce,
        &s.blinded_challenge,
        &partial,
    )?;
    let server = ServerShareOpening {
        deployment: s.context.deployment,
        coin: s.context.coin,
        server: s.draft_server,
        salt: server_salt,
    }
    .commitment()?;
    let state = StateOpening {
        deployment: s.context.deployment,
        coin: s.context.coin,
        funding: s.funding,
        capability: s.next_capability,
        recovery: s.recovery,
        server_share: server,
        policy: a.policy,
        issuance: issuance_commitment(&s.digest()?, &partial)?,
    }
    .commitment()?;
    Ok(LineageBinding {
        deployment: s.context.deployment,
        coin: s.context.coin,
        funding: s.funding,
        state,
        policy: a.policy,
        origin_key: a.origin_key,
        role_hashes: a.role_hashes,
    })
}

impl OwnerCertificate {
    pub fn kind(&self) -> PredecessorKind {
        match self {
            Self::OriginIssued { .. } => PredecessorKind::Origin,
            Self::TransferIssued { .. } => PredecessorKind::Transfer,
        }
    }
    /// Native response/attestation checks only; verify() additionally checks the pinned proof.
    pub fn lineage_binding(&self) -> Result<LineageBinding> {
        match self {
            Self::OriginIssued {
                authorization,
                proof,
                partial,
                activation_partial,
                server_salt,
                origin_signature,
            } => {
                ensure!(proof.len() == PROOF_BYTES, "origin proof length");
                let d = DepositBinding::decode(authorization)?;
                let b = &d.bootstrap;
                verify_partial(
                    &b.parent_server,
                    &b.parent_nonce,
                    &b.blinded_challenge,
                    activation_partial,
                )?;
                let lineage = issued_lineage(&d.authorization, *partial, *server_salt)?;
                let signature: [u8; 64] = origin_signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("origin signature length"))?;
                lineage.verify_origin_attestation(&signature)?;
                Ok(lineage)
            }
            Self::TransferIssued {
                authorization,
                proof,
                partial,
                server_salt,
            } => {
                ensure!(proof.len() == PROOF_BYTES, "transfer proof length");
                let a = IssuanceBinding::decode(authorization)?;
                ensure!(
                    a.signing.context.start_revision > 0,
                    "transfer certificate requires transfer revision"
                );
                issued_lineage(&a, *partial, *server_salt)
            }
        }
    }
    pub fn verify(&self, verifier: &PinnedVerifier, scratch: &Path) -> Result<LineageBinding> {
        let binding = self.lineage_binding()?;
        match self {
            Self::OriginIssued {
                authorization,
                proof,
                ..
            } => {
                verifier.deposit_authorization(
                    &DepositBinding::decode(authorization)?,
                    proof,
                    scratch,
                )?;
            }
            Self::TransferIssued {
                authorization,
                proof,
                ..
            } => {
                verifier.receiver_authorization(
                    &IssuanceBinding::decode(authorization)?,
                    proof,
                    scratch,
                )?;
            }
        }
        Ok(binding)
    }
    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.lineage_binding()?;
        let record = match self {
            Self::OriginIssued {
                authorization,
                proof,
                partial,
                activation_partial,
                server_salt,
                origin_signature,
            } => PrivateRecord::OriginIssued {
                authorization: hex::encode(authorization),
                proof: hex::encode(proof),
                partial: hex::encode(partial),
                activation_partial: hex::encode(activation_partial),
                server_salt: hex::encode(server_salt),
                origin_signature: hex::encode(origin_signature),
            },
            Self::TransferIssued {
                authorization,
                proof,
                partial,
                server_salt,
            } => PrivateRecord::TransferIssued {
                authorization: hex::encode(authorization),
                proof: hex::encode(proof),
                partial: hex::encode(partial),
                server_salt: hex::encode(server_salt),
            },
        };
        Ok(Zeroizing::new(serde_json::to_vec(&record)?))
    }
    pub fn decode_private(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 40_000, "private certificate size");
        let record: PrivateRecord = serde_json::from_slice(bytes)?;
        let value = match &record {
            PrivateRecord::OriginIssued {
                authorization,
                proof,
                partial,
                activation_partial,
                server_salt,
                origin_signature,
            } => Self::OriginIssued {
                authorization: hex::decode(authorization)?,
                proof: hex::decode(proof)?,
                partial: crate::hex32(partial)?,
                activation_partial: crate::hex32(activation_partial)?,
                server_salt: crate::hex32(server_salt)?,
                origin_signature: hex::decode(origin_signature)?,
            },
            PrivateRecord::TransferIssued {
                authorization,
                proof,
                partial,
                server_salt,
            } => Self::TransferIssued {
                authorization: hex::decode(authorization)?,
                proof: hex::decode(proof)?,
                partial: crate::hex32(partial)?,
                server_salt: crate::hex32(server_salt)?,
            },
        };
        ensure!(
            value.encode_private()?.as_slice() == bytes,
            "noncanonical private certificate"
        );
        Ok(value)
    }
}

/// Bounded metadata recorded only after successful proof verification/issuance.
/// Computing this identity is not proof verification or permission to commit.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedTransferRecord {
    pub context: TransferContext,
    pub receiver_role_hash: Digest,
    pub statement_digest: Digest,
    pub proof_digest: Digest,
    pub request_digest: Digest,
    pub signing_digest: Digest,
    pub partial: Digest,
    pub server_salt: Digest,
    pub state: Digest,
    pub capability: Digest,
}
impl IssuedTransferRecord {
    pub fn from_request(
        request: &Request,
        authorization: &IssuanceBinding,
        partial: Digest,
        server_salt: Digest,
        state: Digest,
    ) -> Result<Self> {
        request.authenticate()?;
        let (statement, proof) = match &request.command {
            Command::Issue { statement, proof } => {
                ensure!(
                    request.context.scope == crate::handoff::OperationScope::Single,
                    "ordinary issuance scope"
                );
                (statement, proof)
            }
            Command::BatchReady {
                manifest,
                statement,
                proof,
                ..
            } => {
                manifest.index(&request.context, false)?;
                (statement, proof)
            }
            _ => anyhow::bail!("transfer identity requires Issue or BatchReady"),
        };
        ensure!(
            request.context == authorization.signing.context && request.context.start_revision > 0,
            "transfer identity context"
        );
        ensure!(
            *statement == authorization.encode()? && proof.len() == PROOF_BYTES,
            "transfer identity statement/proof"
        );
        let cert = OwnerCertificate::TransferIssued {
            authorization: statement.clone(),
            proof: proof.clone(),
            partial,
            server_salt,
        };
        ensure!(
            cert.lineage_binding()?.state == state,
            "issued state does not match response"
        );
        let value = Self {
            context: request.context.clone(),
            receiver_role_hash: authorization.role_hashes[RECEIVER_AUTHORIZATION],
            statement_digest: hash(&[statement]),
            proof_digest: hash(&[proof]),
            request_digest: request.digest()?,
            signing_digest: authorization.signing.digest()?,
            partial,
            server_salt,
            state,
            capability: authorization.signing.next_capability,
        };
        value.identity()?;
        Ok(value)
    }
    pub fn identity(&self) -> Result<Digest> {
        ensure!(self.context.start_revision > 0, "issued transfer revision");
        crate::handoff::validate_recursive_vk_hash(&self.receiver_role_hash)?;
        scalar(&self.partial)?;
        let mut bytes = self.context.encode()?;
        for value in [
            &self.receiver_role_hash,
            &self.statement_digest,
            &self.proof_digest,
            &self.request_digest,
            &self.signing_digest,
        ] {
            ensure!(*value != [0; 32], "empty issued identity field");
            bytes.extend_from_slice(value);
        }
        bytes.extend_from_slice(&self.partial);
        for value in [&self.server_salt, &self.state, &self.capability] {
            ensure!(*value != [0; 32], "empty issued response field");
            bytes.extend_from_slice(value);
        }
        Ok(hash(&[b"ZARK/private-handoff/issued-transfer/v1", &bytes]))
    }
}

/// Immutable private deposit release receipt, persisted atomically with both nonce consumptions.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedOriginRecord {
    pub context: TransferContext,
    pub deposit_role_hash: Digest,
    pub statement_digest: Digest,
    pub proof_digest: Digest,
    pub request_digest: Digest,
    pub signing_digest: Digest,
    pub partial: Digest,
    pub activation_partial: Digest,
    pub server_salt: Digest,
    pub state: Digest,
    pub capability: Digest,
    pub origin_signature: Vec<u8>,
}
impl IssuedOriginRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn from_request(
        request: &Request,
        authorization: &DepositBinding,
        partial: Digest,
        activation_partial: Digest,
        server_salt: Digest,
        state: Digest,
        origin_signature: Vec<u8>,
    ) -> Result<Self> {
        request.authenticate()?;
        let (statement, proof) = match &request.command {
            Command::IssueDeposit { statement, proof } => (statement, proof),
            _ => anyhow::bail!("origin identity requires IssueDeposit"),
        };
        ensure!(
            request.context == authorization.authorization.signing.context,
            "origin identity context"
        );
        crate::bootstrap::validate_context(&request.context)?;
        ensure!(
            *statement == authorization.encode()? && proof.len() == PROOF_BYTES,
            "origin identity statement/proof"
        );
        let cert = OwnerCertificate::OriginIssued {
            authorization: statement.clone(),
            proof: proof.clone(),
            partial,
            activation_partial,
            server_salt,
            origin_signature: origin_signature.clone(),
        };
        ensure!(
            cert.lineage_binding()?.state == state,
            "origin issued state mismatch"
        );
        let value = Self {
            context: request.context.clone(),
            deposit_role_hash: authorization.authorization.role_hashes[DEPOSIT_AUTHORIZATION],
            statement_digest: hash(&[statement]),
            proof_digest: hash(&[proof]),
            request_digest: request.digest()?,
            signing_digest: authorization.authorization.signing.digest()?,
            partial,
            activation_partial,
            server_salt,
            state,
            capability: authorization.authorization.signing.next_capability,
            origin_signature,
        };
        value.identity()?;
        Ok(value)
    }
    pub fn identity(&self) -> Result<Digest> {
        crate::bootstrap::validate_context(&self.context)?;
        crate::handoff::validate_recursive_vk_hash(&self.deposit_role_hash)?;
        scalar(&self.partial)?;
        scalar(&self.activation_partial)?;
        ensure!(self.origin_signature.len() == 64, "origin signature length");
        let mut bytes = self.context.encode()?;
        for value in [
            &self.deposit_role_hash,
            &self.statement_digest,
            &self.proof_digest,
            &self.request_digest,
            &self.signing_digest,
        ] {
            ensure!(*value != [0; 32], "empty issued origin identity field");
            bytes.extend_from_slice(value);
        }
        bytes.extend_from_slice(&self.partial);
        bytes.extend_from_slice(&self.activation_partial);
        for value in [&self.server_salt, &self.state, &self.capability] {
            ensure!(*value != [0; 32], "empty issued origin response field");
            bytes.extend_from_slice(value);
        }
        bytes.extend_from_slice(&self.origin_signature);
        Ok(hash(&[b"ZARK/private-handoff/issued-origin/v1", &bytes]))
    }
}

impl Drop for OwnerCertificate {
    fn drop(&mut self) {
        match self {
            Self::OriginIssued {
                authorization,
                proof,
                partial,
                activation_partial,
                server_salt,
                origin_signature,
            } => {
                authorization.zeroize();
                proof.zeroize();
                partial.zeroize();
                activation_partial.zeroize();
                server_salt.zeroize();
                origin_signature.zeroize();
            }
            Self::TransferIssued {
                authorization,
                proof,
                partial,
                server_salt,
            } => {
                authorization.zeroize();
                proof.zeroize();
                partial.zeroize();
                server_salt.zeroize();
            }
        }
    }
}

impl Drop for PrivateRecord {
    fn drop(&mut self) {
        match self {
            Self::OriginIssued {
                authorization,
                proof,
                partial,
                activation_partial,
                server_salt,
                origin_signature,
            } => {
                authorization.zeroize();
                proof.zeroize();
                partial.zeroize();
                activation_partial.zeroize();
                server_salt.zeroize();
                origin_signature.zeroize();
            }
            Self::TransferIssued {
                authorization,
                proof,
                partial,
                server_salt,
            } => {
                authorization.zeroize();
                proof.zeroize();
                partial.zeroize();
                server_salt.zeroize();
            }
        }
    }
}
