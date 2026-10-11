//! Private Bitcoin funding and recovery openings.
use super::{Digest, PROTOCOL_VERSION, RecoveryDelay, nonzero};
use crate::{even, point, point_bytes, scalar, tagged_hash};
use anyhow::{Result, ensure};
use k256::ProjectivePoint;

/// Recipient-visible common backing facts, without a previous payout or recovery.
/// The commitment relation must be proved against an authenticated predecessor;
/// constructing this value does not establish that the output exists or is live.
pub struct FundingOpening {
    pub deployment: Digest,
    pub coin: Digest,
    pub salt: Digest,
    /// Bitcoin consensus txid byte order, not RPC display hex order.
    pub txid: Digest,
    pub vout: u32,
    pub amount: u64,
    pub internal_point: [u8; 64],
}

impl FundingOpening {
    pub fn output_key(&self) -> Result<Digest> {
        let internal = point(&self.internal_point)?;
        ensure!(
            self.internal_point[63] & 1 == 0,
            "noncanonical internal key parity"
        );
        let tweak = scalar(&tagged_hash("TapTweak", &[&self.internal_point[..32]]))?;
        let output = even(internal + ProjectivePoint::GENERATOR * tweak)?.0;
        Ok(point_bytes(output)?[..32].try_into()?)
    }

    pub fn commitment(&self) -> Result<Digest> {
        for value in [&self.deployment, &self.coin, &self.salt, &self.txid] {
            nonzero(value)?;
        }
        ensure!(
            (1..=2_100_000_000_000_000).contains(&self.amount),
            "invalid backing amount"
        );
        Ok(crate::application_hash::hash(&[
            b"ZARK/private-handoff/funding/v1",
            &PROTOCOL_VERSION.to_le_bytes(),
            &self.deployment,
            &self.coin,
            &self.salt,
            &self.txid,
            &self.vout.to_le_bytes(),
            &self.amount.to_le_bytes(),
            &self.output_key()?,
            &self.internal_point[..32],
        ]))
    }
}

/// Receiver-only payout opening. No predecessor recovery opening is required.
pub struct RecoveryOpening {
    pub deployment: Digest,
    pub coin: Digest,
    pub funding: Digest,
    pub salt: Digest,
    pub payout: Digest,
    pub fee: u64,
    pub delay: RecoveryDelay,
}

impl RecoveryOpening {
    pub fn commitment(&self) -> Result<Digest> {
        for value in [&self.deployment, &self.coin, &self.funding, &self.salt] {
            nonzero(value)?;
        }
        k256::schnorr::VerifyingKey::from_bytes(&self.payout)?;
        ensure!((1..=10_000).contains(&self.fee), "invalid recovery fee");
        Ok(crate::application_hash::hash(&[
            b"ZARK/private-handoff/recovery/v1",
            &PROTOCOL_VERSION.to_le_bytes(),
            &self.deployment,
            &self.coin,
            &self.funding,
            &self.salt,
            &self.payout,
            &self.fee.to_le_bytes(),
            &self.delay.blocks().to_le_bytes(),
        ]))
    }
}
