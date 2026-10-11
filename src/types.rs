//! Public Bitcoin backing shared between successive coin owners.
//! These fields are peer data; they are never sent to the blind signer.
use anyhow::{Result, ensure};
use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};
use zark_protocol::{even, point, point_bytes, scalar, tagged_hash};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub deployment: String,
    pub id: String,
    pub funding_salt: String,
    pub internal_point: String,
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
}

impl Input {
    /// Derive the empty-script-tree Taproot output key from the canonical even
    /// internal point. Ownership, commitments and chain backing are checked by
    /// the caller's protocol stage.
    pub fn key(&self) -> Result<[u8; 32]> {
        let p = point(&hex::decode(&self.internal_point)?)?;
        ensure!(point_bytes(p)?[63] & 1 == 0, "odd internal key");
        let t = scalar(&tagged_hash("TapTweak", &[&point_bytes(p)?[..32]]))?;
        Ok(point_bytes(even(p + ProjectivePoint::GENERATOR * t)?.0)?[..32].try_into()?)
    }
}
