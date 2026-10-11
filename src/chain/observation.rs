//! Optional evidence aggregation and early gateway connections through the
//! already authenticated RPC bridge. Only capability discovery is cached; every
//! observation reads fresh evidence.
use super::{ChainConfig, Observation};
use crate::types::Input;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::VecDeque,
    sync::{Mutex, MutexGuard},
};
use zark_protocol::timing::{Phase, Span};

type Capability = Mutex<VecDeque<[u8; 32]>>;

// Full serialized local configuration scopes a capability to its endpoint,
// credentials, network and deployment. No consensus or UTXO data is cached.
// Process-wide, so observations on helper threads reuse the same discovery.
static AGGREGATED: Capability = Mutex::new(VecDeque::new());
static PREPARED: Capability = Mutex::new(VecDeque::new());

fn known(capability: &'static Capability) -> MutexGuard<'static, VecDeque<[u8; 32]>> {
    capability
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn remember(capability: &'static Capability, key: [u8; 32]) {
    let mut cache = known(capability);
    if !cache.contains(&key) {
        if cache.len() == 8 {
            cache.pop_front();
        }
        cache.push_back(key);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    version: u32,
    request: Vec<String>,
    reads: VecDeque<Read>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    method: String,
    args: Vec<String>,
    result: Value,
    failed: bool,
}
impl Read {
    fn result(self, method: &str, args: &[String]) -> Result<Value> {
        ensure!(
            self.method == method && self.args == args,
            "Bitcoin observation request binding mismatch"
        );
        ensure!(!self.failed, "Bitcoin observation RPC failed");
        Ok(self.result)
    }
}

impl ChainConfig {
    /// Discovers aggregated observations before the first one is needed. Only
    /// the capability is recorded; every observation still reads fresh evidence.
    pub fn discover_observation(&self) -> Result<()> {
        let key = self.capability_key()?;
        if !known(&AGGREGATED).contains(&key) {
            record(key, &self.info()?);
        }
        Ok(())
    }

    /// Lets a bridge that advertised it open its gateway connection while the
    /// command does local work. Nothing is read or cached, and a failure only
    /// leaves the first chain read to connect for itself.
    pub fn prepare_connection(&self) {
        let Ok(key) = self.capability_key() else {
            return;
        };
        if known(&PREPARED).contains(&key) {
            let chain = self.clone();
            let _ = std::thread::Builder::new().spawn(move || {
                let _timing = Span::new(Phase::ChainPrepare);
                let _ = chain.call("zark_prepare", &[]);
            });
        }
    }

    fn capability_key(&self) -> Result<[u8; 32]> {
        Ok(zark_protocol::hash(&[&serde_json::to_vec(self)?]))
    }

    pub(super) fn observe_transport(
        &self,
        backing: &Input,
        deposit: &Input,
    ) -> Result<Observation> {
        let key = self.capability_key()?;
        if known(&AGGREGATED).contains(&key) {
            return self.observe_aggregated(backing, deposit);
        }
        let before = self.info()?;
        if record(key, &before) {
            return self.observe_aggregated(backing, deposit);
        }
        // Old gateways and direct Core retain the original checks and budget.
        // Reuse this freshly read initial tip rather than adding a probe RPC.
        let mut before = Some(before);
        for _ in 0..3 {
            let tip = match before.take() {
                Some(tip) => tip,
                None => self.info()?,
            };
            let result = self.observe_at_tip(backing, deposit, &tip, &mut |method, args| {
                self.rpc(method, args)
            });
            let after = self.info()?;
            if same_tip(&tip, &after) {
                return result;
            }
        }
        anyhow::bail!("Bitcoin tip kept changing; retry the live chain observation")
    }

    fn observe_aggregated(&self, backing: &Input, deposit: &Input) -> Result<Observation> {
        let request = vec![
            "1".into(),
            backing.txid.clone(),
            backing.vout.to_string(),
            deposit.txid.clone(),
            deposit.vout.to_string(),
        ];
        for _ in 0..3 {
            let value = self.rpc("zark_observe", &request)?;
            if let Some(result) = self.validate_evidence(value, &request, backing, deposit)? {
                return Ok(result);
            }
        }
        anyhow::bail!("Bitcoin tip kept changing; retry the live chain observation")
    }

    // None means a changed tip, not an invalid proof of backing. Exactly as in
    // the sequential adapter, unchanged-tip errors must never be retried away.
    fn validate_evidence(
        &self,
        value: Value,
        request: &[String],
        backing: &Input,
        deposit: &Input,
    ) -> Result<Option<Observation>> {
        let mut evidence: Evidence = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("invalid Bitcoin observation evidence"))?;
        ensure!(
            evidence.version == 1
                && evidence.request == request
                && (5..=7).contains(&evidence.reads.len()),
            "Bitcoin observation envelope mismatch"
        );
        let before = evidence
            .reads
            .pop_front()
            .context("missing initial tip")?
            .result("getblockchaininfo", &[])?;
        let after = evidence
            .reads
            .pop_back()
            .context("missing final tip")?
            .result("getblockchaininfo", &[])?;
        self.validate_info(&before)?;
        self.validate_info(&after)?;
        if !same_tip(&before, &after) {
            return Ok(None);
        }
        let result = self.observe_at_tip(backing, deposit, &before, &mut |method, args| {
            evidence
                .reads
                .pop_front()
                .context("missing Bitcoin observation read")?
                .result(method, args)
        })?;
        ensure!(
            evidence.reads.is_empty(),
            "unexpected Bitcoin observation reads"
        );
        Ok(Some(result))
    }
}
/// Records what a validated tip reply says the bridge supports, and reports
/// whether it aggregates observations.
fn record(key: [u8; 32], info: &Value) -> bool {
    if info["zark_prepare_version"] == 1 {
        remember(&PREPARED, key);
    }
    let aggregated = info["zark_observation_version"] == 1;
    if aggregated {
        remember(&AGGREGATED, key);
    }
    aggregated
}

fn same_tip(before: &Value, after: &Value) -> bool {
    before["blocks"] == after["blocks"] && before["bestblockhash"] == after["bestblockhash"]
}

#[cfg(test)]
mod tests;
