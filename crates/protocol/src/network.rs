//! Network identifiers shared by deployment and Bitcoin adapters.
use serde::{Deserialize, Serialize};

pub const REGTEST_GENESIS: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Regtest,
    CustomSignet,
}
