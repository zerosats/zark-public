//! Canonical operation scope, intent and recipient-session context.
use super::{Digest, PROTOCOL_VERSION, nonzero, part};
use crate::hash;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Fixed operation scope. Batch manifests are constructed before this digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationScope {
    Single,
    Batch { manifest_digest: Digest },
}

impl OperationScope {
    pub fn encode(self) -> Result<[u8; 33]> {
        let mut bytes = [0; 33];
        if let Self::Batch { manifest_digest } = self {
            nonzero(&manifest_digest)?;
            bytes[0] = 1;
            bytes[1..].copy_from_slice(&manifest_digest);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == 33, "operation scope length");
        let value = match bytes[0] {
            0 => Self::Single,
            1 => Self::Batch {
                manifest_digest: part(bytes, 1),
            },
            _ => anyhow::bail!("unsupported operation scope"),
        };
        ensure!(
            value.encode()?.as_slice() == bytes,
            "noncanonical operation scope"
        );
        Ok(value)
    }
}

/// Sender-selected intent, available before the receiver creates a session key.
/// This digest authorizes no operation without its corresponding ownership proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferIntent {
    pub deployment: Digest,
    pub coin: Digest,
    pub previous_state: Digest,
    pub operation: Digest,
    pub recipient_claim: Digest,
    pub start_revision: u64,
    pub scope: OperationScope,
}

impl TransferIntent {
    pub const ENCODED_LEN: usize = 4 + 5 * 32 + 8 + 33;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "transfer intent length");
        let value = Self {
            deployment: part(bytes, 4),
            coin: part(bytes, 36),
            previous_state: part(bytes, 68),
            operation: part(bytes, 100),
            recipient_claim: part(bytes, 132),
            start_revision: u64::from_le_bytes(part(bytes, 164)),
            scope: OperationScope::decode(&bytes[172..])?,
        };
        ensure!(value.encode()? == bytes, "noncanonical transfer intent");
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        for value in [
            &self.deployment,
            &self.coin,
            &self.previous_state,
            &self.operation,
            &self.recipient_claim,
        ] {
            nonzero(value)?;
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&self.start_revision.to_le_bytes());
        out.extend_from_slice(&self.scope.encode()?);
        Ok(out)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(crate::application_hash::hash(&[
            b"ZARK/private-handoff/intent/v1",
            &self.encode()?,
        ]))
    }

    pub fn with_session(&self, session_auth: Digest) -> Result<TransferContext> {
        let context = TransferContext {
            deployment: self.deployment,
            coin: self.coin,
            previous_state: self.previous_state,
            operation: self.operation,
            recipient_claim: self.recipient_claim,
            session_auth,
            start_revision: self.start_revision,
            scope: self.scope,
        };
        context.encode()?;
        Ok(context)
    }
}

/// A receiver claim is a hiding commitment, not the address authentication key.
/// `session_auth` is independently generated for this operation, not a Bitcoin
/// user-share point, payout key or address key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferContext {
    pub deployment: Digest,
    pub coin: Digest,
    pub previous_state: Digest,
    pub operation: Digest,
    pub recipient_claim: Digest,
    pub session_auth: Digest,
    pub start_revision: u64,
    pub scope: OperationScope,
}

impl TransferContext {
    pub const ENCODED_LEN: usize = 4 + 6 * 32 + 8 + 33;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == Self::ENCODED_LEN, "transfer context length");
        let mut intent = bytes[..164].to_vec();
        intent.extend_from_slice(&bytes[196..]);
        let value = TransferIntent::decode(&intent)?.with_session(part(bytes, 164))?;
        ensure!(value.encode()? == bytes, "noncanonical transfer context");
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let intent = self.intent().encode()?;
        let mut out = intent[..164].to_vec();
        nonzero(&self.session_auth)?;
        k256::schnorr::VerifyingKey::from_bytes(&self.session_auth)?;
        out.extend_from_slice(&self.session_auth);
        out.extend_from_slice(&intent[164..]);
        Ok(out)
    }

    pub fn intent(&self) -> TransferIntent {
        TransferIntent {
            deployment: self.deployment,
            coin: self.coin,
            previous_state: self.previous_state,
            operation: self.operation,
            recipient_claim: self.recipient_claim,
            start_revision: self.start_revision,
            scope: self.scope,
        }
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(hash(&[b"ZARK/private-handoff/context/v1", &self.encode()?]))
    }

    /// Sender authorization binds the recipient claim before the recipient
    /// selects an independent retry key. A receiver must separately prove its
    /// claim opening and bind the full context, including that session key.
    /// Equality of this intent digest alone does not authorize a new session.
    pub fn intent_digest(&self) -> Result<Digest> {
        self.intent().digest()
    }

    pub fn require_domain(&self, deployment: &Digest, coin: &Digest) -> Result<()> {
        self.encode()?;
        ensure!(
            self.deployment == *deployment,
            "handoff deployment mismatch"
        );
        ensure!(self.coin == *coin, "handoff coin mismatch");
        Ok(())
    }
}
