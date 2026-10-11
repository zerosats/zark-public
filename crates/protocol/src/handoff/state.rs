//! Private ownership and signer-share openings.
use super::{Digest, PROTOCOL_VERSION, nonzero};
use crate::point;
use anyhow::Result;

/// Opened privately by the current owner. Disclosing the old server point to a
/// recipient who knows the aggregate key would reveal the old user-share point.
pub struct ServerShareOpening {
    pub deployment: Digest,
    pub coin: Digest,
    pub server: [u8; 64],
    pub salt: Digest,
}

impl ServerShareOpening {
    pub fn commitment(&self) -> Result<Digest> {
        for value in [&self.deployment, &self.coin, &self.salt] {
            nonzero(value)?;
        }
        point(&self.server)?;
        Ok(crate::application_hash::hash(&[
            b"ZARK/private-handoff/server-share/v1",
            &PROTOCOL_VERSION.to_le_bytes(),
            &self.deployment,
            &self.coin,
            &self.server,
            &self.salt,
        ]))
    }
}

/// Candidate private state opening for the application relations. A digest is
/// not an authenticated certificate: origin and recursive lineage must be
/// verified separately, and the signer must check its current accepted state.
pub struct StateOpening {
    pub deployment: Digest,
    pub coin: Digest,
    pub funding: Digest,
    pub capability: Digest,
    pub recovery: Digest,
    pub server_share: Digest,
    pub policy: Digest,
    pub issuance: Digest,
}

impl StateOpening {
    pub fn commitment(&self) -> Result<Digest> {
        let mut bytes = Vec::with_capacity(260);
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        for value in [
            &self.deployment,
            &self.coin,
            &self.funding,
            &self.capability,
            &self.recovery,
            &self.server_share,
            &self.policy,
            &self.issuance,
        ] {
            nonzero(value)?;
            bytes.extend_from_slice(value);
        }
        Ok(crate::application_hash::hash(&[
            b"ZARK/private-handoff/state/v1",
            &bytes,
        ]))
    }
}
