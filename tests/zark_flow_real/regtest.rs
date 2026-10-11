//! Isolated Bitcoin Core process and transaction helpers.
use super::*;

pub(super) struct Regtest {
    pub(super) child: Child,
    pub(super) cli: PathBuf,
    pub(super) datadir: PathBuf,
    pub(super) port: u16,
    pub(super) mining_address: String,
    rpc_transport: zark_wallet::chain::RpcTransport,
}

impl Regtest {
    pub(super) fn start(config: &Config, run: &Path) -> Result<Self> {
        let datadir = run.join("regtest-node");
        private_dir(&datadir)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let log = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(datadir.join("startup.log"))?;
        let child = Command::new(&config.bitcoind.path)
            .args([
                "-regtest",
                "-server=1",
                "-txindex=1",
                "-listen=0",
                "-connect=0",
                "-dnsseed=0",
                "-discover=0",
                "-daemon=0",
                "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1",
                "-printtoconsole=1",
            ])
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={port}"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let mut node = Self {
            child,
            cli: config.bitcoin_cli.path.clone(),
            datadir,
            port,
            mining_address: String::new(),
            rpc_transport: config.rpc_transport,
        };
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if node.rpc(None, "getblockchaininfo", &[]).is_ok() {
                break;
            }
            ensure!(
                Instant::now() < deadline && node.child.try_wait()?.is_none(),
                "isolated regtest did not start; inspect its startup.log"
            );
            thread::sleep(Duration::from_millis(100));
        }
        ensure!(
            node.rpc(None, "getblockhash", &["0".into()])? == network::REGTEST_GENESIS,
            "isolated node genesis mismatch"
        );
        node.rpc(None, "createwallet", &["flow-funding".into()])?;
        node.mining_address = node
            .rpc(Some("flow-funding"), "getnewaddress", &[])?
            .as_str()
            .context("mining address")?
            .into();
        node.mine(101)?;
        Ok(node)
    }

    pub(super) fn rpc(&self, wallet: Option<&str>, method: &str, args: &[String]) -> Result<Value> {
        let mut command = Command::new(&self.cli);
        command
            .arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.display()))
            .arg("-rpcconnect=127.0.0.1")
            .arg(format!("-rpcport={}", self.port))
            .arg("-rpcclienttimeout=10");
        if let Some(wallet) = wallet {
            command.arg(format!("-rpcwallet={wallet}"));
        }
        let output = command.arg(method).args(args).output()?;
        ensure!(
            output.status.success(),
            "isolated Bitcoin RPC {method}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout)?;
        Ok(serde_json::from_str(text.trim()).unwrap_or_else(|_| Value::String(text.trim().into())))
    }

    pub(super) fn mine(&self, blocks: u32) -> Result<()> {
        self.rpc(
            None,
            "generatetoaddress",
            &[blocks.to_string(), self.mining_address.clone()],
        )?;
        Ok(())
    }

    /// Signs without broadcasting. The deposit remains external until the wallet
    /// has durably saved both activation and recovery plus its base certificate.
    pub(super) fn signed_funding(
        &self,
        script: &ScriptBuf,
        amount_sat: u64,
    ) -> Result<(Transaction, u32)> {
        let address = Address::from_script(script, Network::Regtest)?.to_string();
        let mut output = serde_json::Map::new();
        output.insert(address, json!(Amount::from_sat(amount_sat).to_btc()));
        let outputs = Value::Array(vec![Value::Object(output)]);
        let funded = self.rpc(
            Some("flow-funding"),
            "walletcreatefundedpsbt",
            &[
                "[]".into(),
                serde_json::to_string(&outputs)?,
                "0".into(),
                json!({"fee_rate":2,"replaceable":false,"lockUnspents":true}).to_string(),
            ],
        )?;
        let signed = self.rpc(
            Some("flow-funding"),
            "walletprocesspsbt",
            &[funded["psbt"].as_str().context("funding PSBT")?.into()],
        )?;
        let complete = self.rpc(
            None,
            "finalizepsbt",
            &[signed["psbt"]
                .as_str()
                .context("signed funding PSBT")?
                .into()],
        )?;
        ensure!(
            complete["complete"] == true,
            "funding wallet did not fully sign"
        );
        let transaction: Transaction = deserialize(&hex::decode(
            complete["hex"].as_str().context("funding transaction")?,
        )?)?;
        let matches: Vec<_> = transaction
            .output
            .iter()
            .enumerate()
            .filter(|(_, out)| out.script_pubkey == *script && out.value.to_sat() == amount_sat)
            .collect();
        ensure!(matches.len() == 1, "funding output is not unique");
        let vout = matches[0].0 as u32;
        ensure!(
            self.rpc(None, "getrawmempool", &[])? == json!([]),
            "external funding unexpectedly published"
        );
        Ok((transaction, vout))
    }

    pub(super) fn chain(&self, deployment: Deployment) -> ChainConfig {
        ChainConfig {
            deployment,
            bitcoin_cli: self.cli.clone(),
            datadir: self.datadir.clone(),
            rpc_cookie: Some(self.datadir.join("regtest/.cookie")),
            rpc_port: self.port,
            rpc_transport: self.rpc_transport,
            minimum_confirmations: 1,
        }
    }
}

impl Drop for Regtest {
    fn drop(&mut self) {
        let _ = self.rpc(None, "stop", &[]);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
