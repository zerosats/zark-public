//! Receiver-only Bitcoin observations. Nothing here is a signer request.
//! Observations are short-lived: repeat immediately before issuance consent and
//! acceptance. A proof or cached observation does not establish live backing.
mod observation;
mod rpc_http;
mod rpc_process;
use crate::types::Input;
use anyhow::{Context, Result, ensure};
use bitcoin::Denomination;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::Command, str::FromStr};
use zark_protocol::{
    deployment::Deployment,
    handoff::{RecoveryDelay, TransferWindow},
    hex32,
    network::Network,
};

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcTransport {
    #[default]
    Cli,
    /// Authenticated cookie HTTP to the configured loopback port only.
    Http,
}
impl RpcTransport {
    fn is_cli(&self) -> bool {
        *self == Self::Cli
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    pub deployment: Deployment,
    pub bitcoin_cli: PathBuf,
    pub datadir: PathBuf,
    pub rpc_cookie: Option<PathBuf>,
    pub rpc_port: u16,
    #[serde(default, skip_serializing_if = "RpcTransport::is_cli")]
    pub rpc_transport: RpcTransport,
    pub minimum_confirmations: u32,
}

pub struct Observation {
    pub tip_height: u64,
    pub tip_hash: String,
    /// None means the common activation is still unpublished or in the mempool.
    pub activation_height: Option<u64>,
    pub activation_in_mempool: bool,
}

/// The journal-side inputs of one live backing check. They are read before
/// the chain request so the request itself can run on a helper thread.
pub struct LiveBacking {
    pub backing: Input,
    pub activation_input: Input,
    pub previous: RecoveryDelay,
    pub next: RecoveryDelay,
}
impl LiveBacking {
    pub fn observe(&self, chain: &ChainConfig) -> Result<Observation> {
        chain.observe(&self.backing, &self.activation_input)
    }
}

impl ChainConfig {
    fn require_network(&self) -> Result<()> {
        self.info()?;
        ensure!(
            self.rpc("getblockhash", &["0".into()])? == self.deployment.genesis_hash,
            "Bitcoin genesis mismatch"
        );
        Ok(())
    }

    /// Broadcast only the exact transaction supplied by a completed local
    /// workflow. An identical transaction already in the active chain/mempool
    /// is an idempotent success; errors never authorize a different spend.
    pub fn publish(&self, transaction: &bitcoin::Transaction) -> Result<bitcoin::Txid> {
        self.require_network()?;
        let id = transaction.compute_txid();
        let raw = hex::encode(bitcoin::consensus::serialize(transaction));
        match self.rpc("sendrawtransaction", &[raw]) {
            Ok(value) => ensure!(
                value.as_str() == Some(id.to_string().as_str()),
                "Bitcoin broadcast transaction mismatch"
            ),
            Err(original) => {
                if self.confirmations(transaction).is_err() {
                    return Err(original);
                }
            }
        }
        Ok(id)
    }

    pub fn confirmations(&self, transaction: &bitcoin::Transaction) -> Result<u64> {
        self.require_network()?;
        self.with_stable_tip(|tip| self.confirmations_at_tip(transaction, tip))
    }

    fn confirmations_at_tip(
        &self,
        transaction: &bitcoin::Transaction,
        tip: &serde_json::Value,
    ) -> Result<u64> {
        let id = transaction.compute_txid().to_string();
        let value = self.rpc("getrawtransaction", &[id.clone(), "true".into()])?;
        ensure!(
            value["txid"] == id
                && value["hex"] == hex::encode(bitcoin::consensus::serialize(transaction)),
            "Bitcoin transaction bytes mismatch"
        );
        ensure!(
            value["in_active_chain"] != false,
            "Bitcoin transaction is on an inactive activation"
        );
        let confirmations = match value.get("confirmations") {
            None => 0,
            Some(v) => v.as_u64().context("invalid Bitcoin confirmations")?,
        };
        if confirmations > 0 {
            self.require_active_block(&value, tip, confirmations)?;
        } else {
            // txindex retaining transaction bytes is not mempool acceptance.
            // This matters when sendrawtransaction failed and publish is trying
            // to recognize an already accepted exact transaction.
            ensure!(
                self.rpc("getmempoolentry", &[id])?.is_object(),
                "Bitcoin transaction is absent from mempool"
            );
        }
        Ok(confirmations)
    }

    /// Every callback is read-only. A new tip can invalidate intermediate
    /// confirmation arithmetic even before the final freshness check runs.
    /// Discard the whole attempt, including errors, only when the tip changed;
    /// an unchanged tip must preserve every validation failure.
    fn with_stable_tip<T>(
        &self,
        mut read: impl FnMut(&serde_json::Value) -> Result<T>,
    ) -> Result<T> {
        for _ in 0..3 {
            let before = self.info()?;
            let result = read(&before);
            let after = self.info()?;
            if before["blocks"] == after["blocks"]
                && before["bestblockhash"] == after["bestblockhash"]
            {
                return result;
            }
        }
        anyhow::bail!("Bitcoin tip kept changing; retry the live chain observation")
    }

    fn require_active_block(
        &self,
        value: &serde_json::Value,
        tip: &serde_json::Value,
        confirmations: u64,
    ) -> Result<()> {
        self.require_active_block_with(value, tip, confirmations, &mut |method, args| {
            self.rpc(method, args)
        })
    }

    fn require_active_block_with(
        &self,
        value: &serde_json::Value,
        tip: &serde_json::Value,
        confirmations: u64,
        rpc: &mut impl FnMut(&str, &[String]) -> Result<serde_json::Value>,
    ) -> Result<()> {
        ensure!(
            confirmations > 0 && value["in_active_chain"] != false,
            "Bitcoin transaction is on an inactive activation"
        );
        let tip_height = tip["blocks"].as_u64().context("Bitcoin tip height")?;
        let height = tip_height
            .checked_add(1)
            .and_then(|v| v.checked_sub(confirmations))
            .context("Bitcoin confirmation height exceeds tip")?;
        let block = value["blockhash"]
            .as_str()
            .context("confirmed Bitcoin transaction lacks block hash")?;
        canonical_txid(block)?;
        ensure!(
            rpc("getblockhash", &[height.to_string()])? == block,
            "Bitcoin transaction block is not on active chain"
        );
        Ok(())
    }

    pub fn test_accept(&self, transaction: &bitcoin::Transaction) -> Result<()> {
        self.require_network()?;
        let raws =
            serde_json::to_string(&[hex::encode(bitcoin::consensus::serialize(transaction))])?;
        let value = self.rpc("testmempoolaccept", &[raws])?;
        let result = value
            .as_array()
            .filter(|v| v.len() == 1)
            .and_then(|v| v.first())
            .context("Bitcoin mempool test result")?;
        ensure!(
            result["txid"] == transaction.compute_txid().to_string() && result["allowed"] == true,
            "Bitcoin mempool rejected transaction"
        );
        Ok(())
    }

    fn rpc(&self, method: &str, args: &[String]) -> Result<serde_json::Value> {
        let _timing = zark_protocol::timing::Span::new(zark_protocol::timing::Phase::ChainRpc);
        self.call(method, args)
    }

    fn call(&self, method: &str, args: &[String]) -> Result<serde_json::Value> {
        self.deployment.id()?;
        ensure!(
            self.rpc_port != 0 && self.minimum_confirmations > 0,
            "invalid private chain policy"
        );
        if self.rpc_transport == RpcTransport::Http {
            return rpc_http::call(self, method, args);
        }
        let mut command = Command::new(&self.bitcoin_cli);
        zark_protocol::local::inherit_operation_lock(&mut command);
        command
            .arg(match self.deployment.network {
                Network::Regtest => "-regtest",
                Network::CustomSignet => "-signet",
            })
            .arg(format!("-datadir={}", self.datadir.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg("-rpcconnect=127.0.0.1")
            .arg("-rpcclienttimeout=10");
        if let Some(cookie) = &self.rpc_cookie {
            command.arg(format!("-rpccookiefile={}", cookie.display()));
        }
        let stdout = rpc_process::run(command.arg(method).args(args))
            .with_context(|| format!("Bitcoin RPC {method}"))?;
        parse_rpc_response(method, &stdout)
    }

    fn info(&self) -> Result<serde_json::Value> {
        let info = self.rpc("getblockchaininfo", &[])?;
        self.validate_info(&info)?;
        Ok(info)
    }

    fn validate_info(&self, info: &serde_json::Value) -> Result<()> {
        ensure!(
            info["chain"]
                == match self.deployment.network {
                    Network::Regtest => "regtest",
                    Network::CustomSignet => "signet",
                },
            "Bitcoin network mismatch"
        );
        ensure!(
            info["initialblockdownload"] == false,
            "Bitcoin node is synchronizing"
        );
        if self.deployment.network == Network::CustomSignet {
            ensure!(
                info["signet_challenge"] == self.deployment.signet_challenge,
                "Bitcoin Signet challenge mismatch"
            );
        }
        Ok(())
    }

    /// The caller already validated the signed common activation and its link
    /// between these two exact inputs. A spent mempool output is never accepted
    /// merely because an RPC query excluding the mempool still finds it.
    pub fn observe(&self, backing: &Input, activation_input: &Input) -> Result<Observation> {
        let _timing =
            zark_protocol::timing::Span::new(zark_protocol::timing::Phase::ChainObservation);
        let deployment = hex::encode(self.deployment.id()?);
        ensure!(
            backing.deployment == deployment && activation_input.deployment == deployment,
            "Bitcoin inputs belong to another private deployment"
        );
        validate_input(backing)?;
        validate_input(activation_input)?;
        ensure!(backing.vout == 0, "whole-coin activation output index");
        self.observe_transport(backing, activation_input)
    }

    fn observe_at_tip(
        &self,
        backing: &Input,
        activation_input: &Input,
        before: &serde_json::Value,
        rpc: &mut impl FnMut(&str, &[String]) -> Result<serde_json::Value>,
    ) -> Result<Observation> {
        ensure!(
            rpc("getblockhash", &["0".into()])? == self.deployment.genesis_hash,
            "Bitcoin genesis mismatch"
        );
        let height = before["blocks"].as_u64().context("Bitcoin height")?;
        let hash = before["bestblockhash"]
            .as_str()
            .context("Bitcoin tip hash")?
            .to_owned();
        canonical_txid(&hash)?;
        // txindex (or another capable Bitcoin RPC backend) is needed once the
        // confirmed deposit has been consumed by the common activation.
        let deposit = rpc(
            "getrawtransaction",
            &[activation_input.txid.clone(), "true".into()],
        )?;
        ensure!(
            deposit["txid"] == activation_input.txid
                && deposit["confirmations"].as_u64().unwrap_or(0)
                    >= self.minimum_confirmations as u64,
            "deposit lacks required confirmations"
        );
        self.require_active_block_with(
            &deposit,
            before,
            deposit["confirmations"]
                .as_u64()
                .context("deposit confirmations")?,
            rpc,
        )?;
        let output = deposit["vout"]
            .as_array()
            .and_then(|v| {
                v.iter()
                    .find(|o| o["n"].as_u64() == Some(activation_input.vout as u64))
            })
            .context("deposit output missing")?;
        check_output(output, activation_input)?;
        let active = rpc(
            "gettxout",
            &[
                backing.txid.clone(),
                backing.vout.to_string(),
                "true".into(),
            ],
        )?;
        let (activation_height, activation_in_mempool) = if active.is_null() {
            let parent = rpc(
                "gettxout",
                &[
                    activation_input.txid.clone(),
                    activation_input.vout.to_string(),
                    "true".into(),
                ],
            )?;
            ensure!(
                !parent.is_null(),
                "backing is spent, missing or conflicted in the mempool"
            );
            check_output(&parent, activation_input)?;
            ensure!(
                parent["bestblock"] == hash,
                "Bitcoin tip changed during backing check"
            );
            (None, false)
        } else {
            check_output(&active, backing)?;
            ensure!(
                active["bestblock"] == hash,
                "Bitcoin tip changed during backing check"
            );
            let confirmations = active["confirmations"]
                .as_u64()
                .context("activation confirmations")?;
            ensure!(
                confirmations <= height + 1,
                "invalid activation confirmation height"
            );
            (
                if confirmations == 0 {
                    None
                } else {
                    Some(height + 1 - confirmations)
                },
                confirmations == 0,
            )
        };
        Ok(Observation {
            tip_height: height,
            tip_hash: hash,
            activation_height,
            activation_in_mempool,
        })
    }

    pub fn check_transfer_window(
        &self,
        observation: &Observation,
        previous: RecoveryDelay,
        next: RecoveryDelay,
    ) -> Result<Option<TransferWindow>> {
        self.deployment
            .schedule()
            .check_transition(previous, next)?;
        match observation.activation_height {
            Some(height) => Ok(Some(self.deployment.schedule().confirmed_transfer_window(
                previous,
                next,
                u32::try_from(height)?,
                u32::try_from(observation.tip_height)?,
                self.minimum_confirmations,
            )?)),
            // No confirmation means BIP68 has not started. The configured gap
            // must still fit the receiver's confirmation target and margin.
            None => {
                ensure!(
                    u64::from(self.minimum_confirmations) + u64::from(self.deployment.margin)
                        <= u64::from(self.deployment.gap) + 1,
                    "confirmation target exceeds recovery gap"
                );
                Ok(None)
            }
        }
    }
}

fn parse_rpc_response(method: &str, stdout: &[u8]) -> Result<serde_json::Value> {
    // bitcoin-cli prints string RPC results without JSON quotes, and gettxout
    // emits an empty line for a spent/missing output. Preserve those exact cases.
    if method == "gettxout" && stdout.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(serde_json::Value::Null);
    }
    match serde_json::from_slice(stdout) {
        Ok(value) => Ok(value),
        Err(_) if matches!(method, "getblockhash" | "sendrawtransaction") => {
            let value = std::str::from_utf8(stdout)
                .map_err(|_| anyhow::anyhow!("Bitcoin RPC returned invalid text"))?
                .trim();
            canonical_txid(value)
                .map_err(|_| anyhow::anyhow!("Bitcoin RPC returned an invalid transaction hash"))?;
            Ok(serde_json::Value::String(value.into()))
        }
        Err(_) => anyhow::bail!("Bitcoin RPC returned invalid JSON"),
    }
}

fn canonical_txid(value: &str) -> Result<()> {
    let txid = bitcoin::Txid::from_str(value)?;
    ensure!(
        txid.to_string() == value && hex32(value)? != [0; 32],
        "noncanonical transaction hash"
    );
    Ok(())
}
fn validate_input(input: &Input) -> Result<()> {
    canonical_txid(&input.txid)?;
    input.key()?;
    ensure!(
        input.amount > 0 && input.amount <= 2_100_000_000_000_000,
        "invalid Bitcoin amount"
    );
    Ok(())
}
fn check_output(value: &serde_json::Value, input: &Input) -> Result<()> {
    let number = value["value"]
        .as_number()
        .context("Bitcoin output value")?
        .to_string();
    let amount = bitcoin::Amount::from_str_in(&number, Denomination::Bitcoin)?;
    ensure!(
        amount.to_sat() == input.amount,
        "Bitcoin backing amount mismatch"
    );
    let script = hex::encode(crate::bitcoin::p2tr(&input.key()?).as_bytes());
    ensure!(
        value["scriptPubKey"]["hex"] == script,
        "Bitcoin backing output script mismatch"
    );
    Ok(())
}
