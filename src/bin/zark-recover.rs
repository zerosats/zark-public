//! Standalone archive-only recovery. No wallet, prover, signer or RPC adapter.
use anyhow::{Context, Result, ensure};
use bitcoin::{Address, Network, Transaction, consensus::serialize};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};
use zark_protocol::{handoff::Digest, hex32};
use zark_wallet::recovery_export::PortableRecovery;

#[derive(Clone, Copy, ValueEnum)]
enum RecoveryNetwork {
    Regtest,
    Signet,
}
impl RecoveryNetwork {
    fn bitcoin(self) -> Network {
        match self {
            Self::Regtest => Network::Regtest,
            Self::Signet => Network::Signet,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Signet => "signet",
        }
    }
}

#[derive(Parser)]
#[command(
    name = "zark-recover",
    about = "Inspect and use a v9 or v10 native recovery archive without signer, wallet journals or proving tools"
)]
struct Cli {
    #[arg(long)]
    archive: PathBuf,
    /// Authenticated deployment ID obtained independently of the archive.
    #[arg(long)]
    deployment: String,
    /// Expected coin ID obtained independently of the archive.
    #[arg(long)]
    coin: String,
    /// Address encoding only. Independently authenticate your Bitcoin node's chain.
    #[arg(long, value_enum)]
    network: RecoveryNetwork,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Inspect,
    /// Save the exact pre-signed activation and own recovery; does not broadcast.
    ExtractTransactions {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Sign a payout spend after recovery. Requires an explicit fee and a fresh output file.
    Sweep {
        #[arg(long)]
        to: String,
        #[arg(long)]
        fee: u64,
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() {
    let result = execute(Cli::parse());
    match result {
        Ok(value) => println!("{}", json!({"api_version":1,"ok":true,"result":value})),
        Err(error) => {
            eprintln!("{error:#}");
            println!(
                "{}",
                json!({"api_version":1,"ok":false,"error":{"code":"recovery_failed","message":error.to_string()}})
            );
            std::process::exit(1);
        }
    }
}

fn execute(cli: Cli) -> Result<Value> {
    let deployment = hex32(&cli.deployment)?;
    let coin = hex32(&cli.coin)?;
    let archive = if cli.archive.is_absolute() {
        cli.archive.clone()
    } else {
        std::env::current_dir()?.join(&cli.archive)
    };
    let portable = PortableRecovery::read(&archive, &deployment, &coin)?;
    let [activation, recovery] = portable.transactions()?;
    let summary = summary(
        &deployment,
        &coin,
        cli.network,
        &activation,
        &recovery,
        portable.relative_blocks(),
        portable.protocol_version(),
    )?;
    match cli.command {
        Action::Inspect => Ok(summary),
        Action::ExtractTransactions { directory } => {
            private_parent(&directory)?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .context(
                    "choose a new extraction directory; existing directories are never overwritten",
                )?;
            fs::File::open(parent_directory(&directory))?.sync_all()?;
            let activation_path = directory.join("activation.hex");
            let recovery_path = directory.join("recovery.hex");
            write_new(
                &activation_path,
                format!("{}\n", hex::encode(serialize(&activation))).as_bytes(),
            )?;
            write_new(
                &recovery_path,
                format!("{}\n", hex::encode(serialize(&recovery))).as_bytes(),
            )?;
            write_new(
                &directory.join("transactions.json"),
                &serde_json::to_vec_pretty(&summary)?,
            )?;
            Ok(
                json!({"activation":activation_path,"recovery":recovery_path,"manifest":directory.join("transactions.json"),
                "broadcast":false,"next_action":"Authenticate your node's exact chain, inspect live inputs, then publish activation. Wait for the recovery's BIP68 maturity before publishing recovery."}),
            )
        }
        Action::Sweep { to, fee, output } => {
            private_parent(&output)?;
            ensure!(
                !output.try_exists()?,
                "output already exists; reuse the saved transaction or choose a new file"
            );
            let address = Address::from_str(&to)?.require_network(cli.network.bitcoin())?;
            let script = address.script_pubkey();
            let bytes = script.as_bytes();
            ensure!(
                bytes.len() == 34 && bytes[..2] == [0x51, 0x20],
                "this prototype requires a Taproot payout destination"
            );
            let destination: Digest = bytes[2..].try_into()?;
            let transaction = portable.sign_payout_spend(destination, fee)?;
            ensure!(
                transaction.output.len() == 1
                    && transaction.output[0].script_pubkey == script
                    && recovery.output[0]
                        .value
                        .to_sat()
                        .checked_sub(transaction.output[0].value.to_sat())
                        == Some(fee),
                "signed payout amount or destination differs from the request"
            );
            write_new(
                &output,
                format!("{}\n", hex::encode(serialize(&transaction))).as_bytes(),
            )?;
            Ok(
                json!({"transaction":output,"transaction_id":transaction.compute_txid().to_string(),"destination":address.to_string(),
                "fee_sat":fee,"amount_received_sat":transaction.output[0].value.to_sat(),"broadcast":false,
                "next_action":"Confirm the exact recovery output is available on the authenticated chain; test this saved transaction with testmempoolaccept, then broadcast it."}),
            )
        }
    }
}

fn summary(
    deployment: &Digest,
    coin: &Digest,
    network: RecoveryNetwork,
    activation: &Transaction,
    recovery: &Transaction,
    delay: u32,
    protocol_version: u32,
) -> Result<Value> {
    ensure!(
        activation.output.len() == 1 && recovery.output.len() == 1,
        "recovery archive must contain whole-coin transactions"
    );
    let recovery_fee = activation.output[0]
        .value
        .to_sat()
        .checked_sub(recovery.output[0].value.to_sat())
        .context("invalid recovery fee")?;
    Ok(
        json!({"version":protocol_version,"deployment":hex::encode(deployment),"coin":hex::encode(coin),"network":network.label(),
        "native_signatures_verified":true,"live_chain_checked":false,"current_ownership_checked":false,
        "activation":{"transaction_id":activation.compute_txid().to_string(),"parent":activation.input[0].previous_output.to_string(),
            "address":Address::from_script(&activation.output[0].script_pubkey,network.bitcoin())?.to_string(),"amount_sat":activation.output[0].value.to_sat()},
        "recovery":{"transaction_id":recovery.compute_txid().to_string(),"parent":recovery.input[0].previous_output.to_string(),
            "payout_address":Address::from_script(&recovery.output[0].script_pubkey,network.bitcoin())?.to_string(),
            "amount_sat":recovery.output[0].value.to_sat(),"fee_sat":recovery_fee,"relative_blocks":delay},
        "maturity_rule":"If activation confirms at height H, recovery may confirm no earlier than H + relative_blocks. Recheck after reorgs."}),
    )
}

fn private_parent(path: &Path) -> Result<()> {
    let parent = parent_directory(path);
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == 0o700,
        "output parent must be an existing private directory (0700)"
    );
    Ok(())
}
fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(parent_directory(path))?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{OutPoint, Txid, consensus::deserialize, hashes::Hash};
    use k256::schnorr::SigningKey;
    use zark_protocol::{random32, scalar};
    use zark_wallet::bitcoin::{attach_signature, backup, p2tr, sighash};
    use zeroize::Zeroizing;
    struct Home(PathBuf);
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    const D: Digest = [101; 32];
    const C: Digest = [102; 32];
    fn key(n: u8) -> SigningKey {
        let mut bytes = [0; 32];
        bytes[31] = n;
        SigningKey::from_bytes(&scalar(&bytes).unwrap().to_bytes()).unwrap()
    }
    fn sign(tx: &mut Transaction, amount: u64, key: &SigningKey) {
        let output: Digest = key.verifying_key().to_bytes().into();
        let sig = key
            .sign_prehash_with_aux_rand(&sighash(tx, amount, output).unwrap(), &random32())
            .unwrap();
        attach_signature(tx, amount, output, &sig.to_bytes()).unwrap();
    }
    fn fixture() -> Home {
        let path =
            std::env::temp_dir().join(format!("zark-recover-cli-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let home = Home(path);
        let parent = key(11);
        let active = key(13);
        let payout = key(17);
        let parent_key: Digest = parent.verifying_key().to_bytes().into();
        let active_key: Digest = active.verifying_key().to_bytes().into();
        let parent_out = OutPoint::new(Txid::from_byte_array([44; 32]), 0);
        let mut activation =
            zark_wallet::bitcoin::activation(parent_out, 100_000, &[(99_000, active_key)], 0)
                .unwrap();
        sign(&mut activation, 100_000, &parent);
        let mut recovery = backup(
            OutPoint::new(activation.compute_txid(), 0),
            99_000,
            1000,
            payout.verifying_key().to_bytes().into(),
            12,
        )
        .unwrap();
        sign(&mut recovery, 99_000, &active);
        let value = json!({"schema":"zark-portable-recovery","version":1,"protocol_version":9,"deployment":D,"coin":C,
            "activation_parent":{"txid":parent_out.txid.to_string(),"vout":0,"amount":100000,"output_key":parent_key},
            "activation":hex::encode(serialize(&activation)),
            "backing":{"txid":activation.compute_txid().to_string(),"vout":0,"amount":99000,"output_key":active_key},
            "recovery":hex::encode(serialize(&recovery)),"fee_sat":1000,"relative_blocks":12,
            "payout_secret":<[u8;32]>::from(payout.to_bytes())});
        write_new(
            &home.0.join("archive.json"),
            &Zeroizing::new(serde_json::to_vec(&value).unwrap()),
        )
        .unwrap();
        home
    }
    fn cli(home: &Home, command: Action) -> Cli {
        Cli {
            archive: home.0.join("archive.json"),
            deployment: hex::encode(D),
            coin: hex::encode(C),
            network: RecoveryNetwork::Regtest,
            command,
        }
    }
    #[test]
    fn explicit_context_network_and_fee_are_required() {
        assert!(Cli::try_parse_from(["zark-recover", "inspect"]).is_err());
        let d = hex::encode(D);
        let c = hex::encode(C);
        assert!(
            Cli::try_parse_from([
                "zark-recover",
                "--archive",
                "a",
                "--deployment",
                &d,
                "--coin",
                &c,
                "--network",
                "regtest",
                "inspect"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "zark-recover",
                "--archive",
                "a",
                "--deployment",
                &d,
                "--coin",
                &c,
                "--network",
                "regtest",
                "sweep",
                "--to",
                "bcrt1…",
                "--output",
                "out"
            ])
            .is_err()
        );
    }
    #[test]
    fn native_inspect_and_extraction_report_no_live_claims() {
        let home = fixture();
        let result = execute(cli(&home, Action::Inspect)).unwrap();
        assert_eq!(result["native_signatures_verified"], true);
        assert_eq!(result["live_chain_checked"], false);
        assert_eq!(result["recovery"]["relative_blocks"], 12);
        assert_eq!(result["recovery"]["amount_sat"], 98000);
        let dir = home.0.join("transactions");
        let out = execute(cli(
            &home,
            Action::ExtractTransactions {
                directory: dir.clone(),
            },
        ))
        .unwrap();
        assert_eq!(out["broadcast"], false);
        for name in ["activation.hex", "recovery.hex"] {
            let bytes = hex::decode(fs::read_to_string(dir.join(name)).unwrap().trim()).unwrap();
            let tx: Transaction = deserialize(&bytes).unwrap();
            assert_eq!(tx.input[0].witness.len(), 1);
            assert_eq!(fs::metadata(dir.join(name)).unwrap().mode() & 0o777, 0o600);
        }
        assert!(execute(cli(&home, Action::ExtractTransactions { directory: dir })).is_err());
    }
    #[test]
    fn sweep_checks_context_network_amount_and_never_overwrites() {
        let home = fixture();
        let output = home.0.join("sweep.hex");
        let dest: Digest = key(29).verifying_key().to_bytes().into();
        let address = Address::from_script(&p2tr(&dest), Network::Regtest)
            .unwrap()
            .to_string();
        let result = execute(cli(
            &home,
            Action::Sweep {
                to: address.clone(),
                fee: 1000,
                output: output.clone(),
            },
        ))
        .unwrap();
        assert_eq!(result["amount_received_sat"], 97000);
        assert_eq!(result["fee_sat"], 1000);
        let bytes = fs::read(&output).unwrap();
        assert!(
            execute(cli(
                &home,
                Action::Sweep {
                    to: address.clone(),
                    fee: 1000,
                    output: output.clone()
                }
            ))
            .is_err()
        );
        assert_eq!(bytes, fs::read(&output).unwrap());
        let mainnet = Address::from_script(&p2tr(&dest), Network::Bitcoin)
            .unwrap()
            .to_string();
        assert!(
            execute(cli(
                &home,
                Action::Sweep {
                    to: mainnet,
                    fee: 1000,
                    output: home.0.join("wrong-network")
                }
            ))
            .is_err()
        );
        assert!(
            execute(cli(
                &home,
                Action::Sweep {
                    to: address,
                    fee: 0,
                    output: home.0.join("zero-fee")
                }
            ))
            .is_err()
        );
        let mut wrong = cli(&home, Action::Inspect);
        wrong.coin = hex::encode([8; 32]);
        assert!(execute(wrong).is_err());
    }
}
