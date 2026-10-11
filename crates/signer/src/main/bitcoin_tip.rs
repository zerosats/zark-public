//! Signer-side Bitcoin block observation for batch readiness. Coin outpoints
//! remain private; a different active tip invalidates every saved readiness.
use super::{FilePin, canonical_digest, check_file_pin, open_trusted};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use zark_protocol::{deployment::Deployment, handoff::Digest, network::Network};
use zark_signer::engine::BatchTip;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    bitcoin_cli: FilePin,
    datadir: PathBuf,
    rpc_cookie: Option<PathBuf>,
    rpc_port: u16,
}

impl Config {
    pub(super) fn input_paths(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.bitcoin_cli.path.as_path()).chain(self.rpc_cookie.as_deref())
    }
}

struct Unavailable;
impl BatchTip for Unavailable {
    fn current_tip(&self) -> Result<Digest> {
        anyhow::bail!("batch readiness requires a configured Bitcoin tip source")
    }
}

struct BitcoinTip {
    cli: PathBuf,
    datadir: PathBuf,
    cookie: Option<PathBuf>,
    port: u16,
    network: Network,
    genesis: Digest,
}

impl BitcoinTip {
    fn rpc(&self, method: &str, arguments: &[&str]) -> Result<serde_json::Value> {
        let mut command = Command::new(&self.cli);
        command
            .arg(match self.network {
                Network::Regtest => "-regtest",
                Network::CustomSignet => "-signet",
            })
            .arg(format!("-datadir={}", self.datadir.display()))
            .arg(format!("-rpcport={}", self.port))
            .arg("-rpcconnect=127.0.0.1")
            .arg("-rpcclienttimeout=5");
        if let Some(cookie) = &self.cookie {
            command.arg(format!("-rpccookiefile={}", cookie.display()));
        }
        let output = command
            .arg(method)
            .args(arguments)
            .output()
            .context(StartupUnavailable)?;
        if !output.status.success() {
            return Err(
                anyhow::anyhow!("Bitcoin tip RPC {method} failed").context(StartupUnavailable)
            );
        }
        ensure!(
            output.stdout.len() <= 4096,
            "Bitcoin tip RPC output too large"
        );
        if method == "getblockhash" {
            return Ok(serde_json::Value::String(
                std::str::from_utf8(&output.stdout)?.trim().to_owned(),
            ));
        }
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}

impl BatchTip for BitcoinTip {
    fn current_tip(&self) -> Result<Digest> {
        let info = self.rpc("getblockchaininfo", &[])?;
        ensure!(
            info["chain"]
                == match self.network {
                    Network::Regtest => "regtest",
                    Network::CustomSignet => "signet",
                },
            "Bitcoin tip source network mismatch"
        );
        if !(info["initialblockdownload"] == false
            && info["blocks"].as_u64().is_some()
            && info["blocks"] == info["headers"])
        {
            return Err(
                anyhow::anyhow!("Bitcoin tip source is not synced").context(StartupUnavailable)
            );
        }
        ensure!(
            self.rpc("getblockhash", &["0"])? == hex::encode(self.genesis),
            "Bitcoin tip source genesis mismatch"
        );
        canonical_digest(
            info["bestblockhash"]
                .as_str()
                .context("Bitcoin bestblockhash")?,
        )
    }
}

/// Only an unavailable/not-yet-synced node is a retryable startup failure.
#[derive(Debug)]
pub(super) struct StartupUnavailable;
impl std::fmt::Display for StartupUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Bitcoin tip source is unavailable at startup")
    }
}
impl std::error::Error for StartupUnavailable {}

pub(super) fn open(config: Option<&Config>, deployment: &Deployment) -> Result<Arc<dyn BatchTip>> {
    let Some(config) = config else {
        return Ok(Arc::new(Unavailable));
    };
    ensure!(
        config.datadir.is_absolute() && config.rpc_port != 0,
        "invalid Bitcoin tip source configuration"
    );
    check_file_pin(
        &config.bitcoin_cli.path,
        &config.bitcoin_cli.sha256,
        128 * 1024 * 1024,
    )?;
    ensure!(
        open_trusted(&config.bitcoin_cli.path)?
            .metadata()?
            .permissions()
            .mode()
            & 0o111
            != 0,
        "pinned Bitcoin CLI is not executable"
    );
    if let Some(cookie) = &config.rpc_cookie {
        open_trusted(cookie)?;
    }
    let source: Arc<dyn BatchTip> = Arc::new(BitcoinTip {
        cli: config.bitcoin_cli.path.clone(),
        datadir: config.datadir.clone(),
        cookie: config.rpc_cookie.clone(),
        port: config.rpc_port,
        network: deployment.network,
        genesis: canonical_digest(&deployment.genesis_hash)?,
    });
    source.current_tip()?;
    Ok(source)
}
