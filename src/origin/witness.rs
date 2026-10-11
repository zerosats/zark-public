//! One deposit proof directly checks the activation and recovery signing drafts.
use super::persistence::write_private;
use super::{OriginJournal, field};
use anyhow::{Context, Result};
use std::path::Path;
use zeroize::Zeroizing;

impl OriginJournal {
    pub fn deposit_public_inputs(&self) -> Result<Vec<u8>> {
        self.deposit_binding()?.encode()
    }

    pub fn write_deposit_witness(&self, path: &Path) -> Result<()> {
        self.require_parent_frozen()?;
        let binding = self.deposit_binding()?;
        let mut out = Zeroizing::new(String::new());
        field(&mut out, "statement", &binding.encode()?)?;
        crate::prover::packed_witness(&mut out, &binding.encode()?)?;
        let mut recovery = Zeroizing::new(String::new());
        self.ensure_recovery()?
            .append_recovery_witness(&mut recovery, false)?;
        for line in recovery.lines() {
            let (key, _) = line.split_once(" = ").context("recovery witness field")?;
            if !matches!(key, "statement" | "binding_digest") {
                out.push_str(line);
                out.push('\n');
            }
        }
        let mut parent = Zeroizing::new(String::new());
        self.ensure_bootstrap()?
            .append_authorization_witness(&mut parent)?;
        for line in parent.lines() {
            let (key, value) = line.split_once(" = ").context("activation witness field")?;
            let target = match key {
                "alpha" => "parent_alpha",
                "beta" => "parent_beta",
                "parent_funding_salt" => "parent_funding_salt",
                "nonce_salt" => "parent_nonce_salt",
                "txid" => "parent_txid",
                "vout" => "parent_vout",
                "amount" => "parent_amount",
                "fee" => "activation_fee",
                _ => continue,
            };
            out.push_str(&format!("{target} = {value}\n"));
        }
        field(&mut out, "capability", &self.record.capability)?;
        let schedule = self.policy.schedule;
        out.push_str(&format!(
            "initial = {}\ngap = {}\nmargin = {}\n",
            schedule.initial, schedule.gap, schedule.margin
        ));
        write_private(path, out.as_bytes())
    }
}
