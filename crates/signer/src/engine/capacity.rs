//! Operator admission ceilings, separate from persisted authority and checkpoint identity.
use anyhow::{Result, ensure};
use serde::Deserialize;

pub(super) const MAX_COINS: u64 = 10_000;
pub(super) const MAX_BATCHES: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CapacityLimits {
    pub coins: u64,
    pub batches: u64,
}

impl Default for CapacityLimits {
    fn default() -> Self {
        Self {
            coins: MAX_COINS,
            batches: MAX_BATCHES,
        }
    }
}

impl CapacityLimits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_COINS).contains(&self.coins) && (1..=MAX_BATCHES).contains(&self.batches),
            "invalid signer storage admission limits"
        );
        Ok(())
    }
}
