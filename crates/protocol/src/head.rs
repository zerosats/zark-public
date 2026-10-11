//! Challenge-bound, minimal signer state responses. No private replay cache is
//! serializable through this interface. A fresh signer head is not chain state.
use crate::{
    handoff::{Digest, PROTOCOL_VERSION},
    hash, random32,
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Reserved,
    Draft,
    Issued,
    Accepted,
    Terminal,
}

impl Phase {
    fn tag(self) -> u8 {
        match self {
            Self::Reserved => 1,
            Self::Draft => 2,
            Self::Issued => 3,
            Self::Accepted => 4,
            Self::Terminal => 5,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadQuery {
    pub deployment: Digest,
    pub coin: Digest,
    pub session_auth: Digest,
    pub challenge: Digest,
}

impl HeadQuery {
    /// The caller creates a new query for each freshness check, retains its
    /// issuance deadline locally and never accepts a peer's substitute challenge.
    pub fn fresh(deployment: Digest, coin: Digest, session_auth: Digest) -> Result<Self> {
        let query = Self {
            deployment,
            coin,
            session_auth,
            challenge: random32(),
        };
        query.encode()?;
        Ok(query)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = PROTOCOL_VERSION.to_le_bytes().to_vec();
        for value in [
            &self.deployment,
            &self.coin,
            &self.session_auth,
            &self.challenge,
        ] {
            ensure!(*value != [0; 32], "empty head query field");
            out.extend_from_slice(value);
        }
        VerifyingKey::from_bytes(&self.session_auth)?;
        Ok(out)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub query: HeadQuery,
    pub state: Digest,
    pub capability: Digest,
    pub phase: Phase,
    pub revision: u64,
    pub checkpoint_sequence: u64,
}

impl Head {
    pub fn digest(&self) -> Result<Digest> {
        ensure!(
            self.state != [0; 32]
                && self.capability != [0; 32]
                && self.revision > 0
                && self.checkpoint_sequence > 0,
            "invalid head state"
        );
        Ok(hash(&[
            b"ZARK/private-handoff/head/v1",
            &self.query.encode()?,
            &self.state,
            &self.capability,
            &[self.phase.tag()],
            &self.revision.to_le_bytes(),
            &self.checkpoint_sequence.to_le_bytes(),
        ]))
    }

    /// The service must construct this from its locked, current durable state
    /// after authenticating the original role session. Never sign a client head.
    pub fn sign(&self, control: &SigningKey) -> Result<[u8; 64]> {
        Ok(control.sign_raw(&self.digest()?, &random32())?.to_bytes())
    }

    pub fn verify(
        &self,
        expected: &HeadQuery,
        trusted_control: &Digest,
        signature: &[u8; 64],
    ) -> Result<()> {
        ensure!(&self.query == expected, "head query or challenge mismatch");
        VerifyingKey::from_bytes(trusted_control)?
            .verify_raw(&self.digest()?, &Signature::try_from(signature.as_slice())?)?;
        Ok(())
    }
}
