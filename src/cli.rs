//! Private whole-coin research CLI. No fixture imports or verifier bypass.
//! Operation metadata locates native journals; it is never ownership authority.
use crate::{exit_operation::ExitOperation, sender::SenderDraft};
use anyhow::{Result, ensure};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use zark_protocol::{batch::Manifest as BatchManifest, local::ProcessLock};

mod address;
mod arguments;
mod batch;
mod commands;
mod config;
mod exit;
mod mail;
mod origin;
mod proofs;
mod receiver;
mod sender;
mod storage;
mod swap_group;
mod worker;
use arguments::Cli;
use commands::execute;
use config::App;
use exit::advance_exit;
use origin::advance_origin;
use receiver::advance_receiver;
use sender::advance_sender;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u32,
    deployment: String,
    manifest_sha256: String,
    kind: Kind,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Kind {
    Origin {
        amount: u64,
        activation_fee: u64,
        recovery_fee: u64,
    },
    Sender {
        owner: PathBuf,
        recipient: String,
        output: PathBuf,
    },
    Receiver {
        invitation: PathBuf,
        coin: String,
        transfer_operation: String,
        offer_sha256: String,
        recovery_fee: u64,
        #[serde(default)]
        batch: Option<Box<BatchManifest>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_amount: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<PathBuf>,
    },
    SwapGroup {
        plan: Box<swap_group::FrozenPlan>,
    },
    Exit {
        owner: PathBuf,
        destination: String,
        fee: u64,
    },
}

#[cfg(target_os = "macos")]
pub(crate) mod macos;

pub fn main() -> i32 {
    #[cfg(target_os = "macos")]
    macos::bound_descriptor_limit();
    let cli = Cli::parse();
    if matches!(cli.command, arguments::Action::Worker) {
        return worker::main(&cli.config);
    }
    match execute(cli) {
        Ok(value) => {
            println!("{}", json!({"api_version":1,"ok":true,"result":value}));
            0
        }
        Err(error) => {
            eprintln!("{error:#}");
            println!(
                "{}",
                json!({"api_version":1,"ok":false,"error":{"code":"operation_failed","message":error.to_string(),"next_action":"Fix the reported cause and resume the same operation; do not delete its journal."}})
            );
            1
        }
    }
}

fn advance(app: &App, root: &Path, broadcast: bool) -> Result<Value> {
    let metadata = app.metadata(root)?;
    // A member cannot independently release readiness. All resumed members use
    // the same native full-set economic and recovery gate as the GUI.
    if let Kind::Receiver {
        group: Some(group), ..
    } = &metadata.kind
    {
        ensure!(!broadcast, "swap receiver cannot broadcast");
        return swap_group::advance_from_child(app, root, group);
    }
    let _lock = ProcessLock::acquire(&root.join(".cli.lock"))?;
    match &metadata.kind {
        Kind::Origin { .. } => advance_origin(app, root, &metadata, broadcast),
        Kind::Sender {
            owner,
            recipient,
            output,
        } => advance_sender(app, root, owner, recipient, output),
        Kind::Receiver { .. } => advance_receiver(app, root, &metadata, None),
        Kind::SwapGroup { plan } => {
            ensure!(!broadcast, "swap group cannot broadcast");
            swap_group::advance(app, root, plan)
        }
        Kind::Exit {
            owner,
            destination,
            fee,
        } => advance_exit(app, root, owner, destination, *fee, broadcast),
    }
}

fn status(app: &App, root: &Path) -> Result<Value> {
    let metadata = app.metadata(root)?;
    let _lock = ProcessLock::acquire(&root.join(".cli.lock"))?;
    if let Kind::SwapGroup { plan } = &metadata.kind {
        return swap_group::status(root, plan);
    }
    if !root.join("journal").try_exists()? {
        return Ok(
            json!({"operation":root,"metadata_only":true,"phase":"initializing","next_action":"Resume this operation."}),
        );
    }
    let (kind, stage, coin) = match &metadata.kind {
        Kind::Origin { .. } => {
            let journal = app.origin(root, &metadata)?;
            (
                "origin",
                format!("{:?}", journal.phase()),
                journal.context().coin,
            )
        }
        Kind::Receiver { .. } => {
            let (_, journal) = app.receiver(root, &metadata)?;
            (
                "receiver",
                format!("{:?}", journal.phase()),
                journal.context().coin,
            )
        }
        Kind::Sender { .. } => {
            let journal = SenderDraft::open(&root.join("journal"), &app.policy)?;
            (
                "sender",
                if journal.offer_bytes().is_ok() {
                    "handoff_saved"
                } else {
                    "preparing_handoff"
                }
                .into(),
                journal.context().coin,
            )
        }
        Kind::Exit { .. } => {
            let journal = ExitOperation::open(&root.join("journal"), &app.policy)?;
            (
                "exit",
                if journal.is_terminal()? {
                    "released_terminal"
                } else {
                    "preparing_exit"
                }
                .into(),
                journal.context().coin,
            )
        }
        Kind::SwapGroup { .. } => unreachable!("group status handled above"),
    };
    Ok(
        json!({"operation":root,"kind":kind,"phase":stage,"coin":hex::encode(coin),"metadata_only":true,"current_ownership_verified":false}),
    )
}

#[cfg(test)]
mod tests;
