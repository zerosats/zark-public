//! CLI arguments and flags; names and defaults are part of the public interface.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "zark-wallet", about = "Private whole-coin research wallet")]
pub(super) struct Cli {
    /// Locally authenticated configuration, mode 0600. Never use a config supplied by a coin sender.
    #[arg(long)]
    pub(super) config: PathBuf,
    #[command(subcommand)]
    pub(super) command: Action,
}
#[derive(Subcommand)]
pub(super) enum Action {
    /// Desktop-owned, serial native command worker over inherited stdio pipes.
    #[command(hide = true)]
    Worker,
    /// Local delivery cryptography. Input/output are private files, never key exports.
    MailCrypto {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    VerifyAssets,
    /// Check a destination locally before creating any operation or journal.
    ValidateAddress {
        #[arg(long)]
        address: String,
    },
    /// Create one fresh receiving invitation. Reusing its directory returns the same address.
    NewAddress {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Create Alice's origin journal and allocate joint parent/active signer keys.
    OriginCreate {
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 1000)]
        activation_fee: u64,
        #[arg(long, default_value_t = 1000)]
        recovery_fee: u64,
    },
    /// Bind a fully signed external funding transaction. Does not broadcast.
    OriginBind {
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        transaction: PathBuf,
        #[arg(long)]
        vout: u32,
    },
    /// Advance the exact saved operation. Publishing Bitcoin transactions requires --broadcast.
    #[command(alias = "resume")]
    Advance {
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        broadcast: bool,
    },
    /// Transfer the entire accepted coin and export its encrypted offer.
    Send {
        #[arg(long)]
        owner: PathBuf,
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze a sender operation for a two-coin batch without reserving a coin yet.
    BatchDraft {
        #[arg(long)]
        owner: PathBuf,
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build one sorted manifest from a local sender and a local or public peer draft.
    BatchManifest {
        #[arg(long, required_unless_present = "draft", conflicts_with = "draft")]
        first: Option<PathBuf>,
        #[arg(long, required_unless_present_any = ["peer", "draft"], conflicts_with_all = ["peer", "draft"])]
        second: Option<PathBuf>,
        /// Public peer draft JSON containing only context, coin, and revision.
        #[arg(long, required_unless_present_any = ["second", "draft"], conflicts_with_all = ["second", "draft"])]
        peer: Option<PathBuf>,
        /// Local outgoing drafts, one per coin; requires --peer-drafts.
        #[arg(long, requires = "peer_drafts", conflicts_with_all = ["first", "second", "peer"])]
        draft: Vec<PathBuf>,
        /// JSON array of one to five public peer drafts.
        #[arg(long, requires = "draft")]
        peer_drafts: Option<PathBuf>,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Join a drafted sender to the exact manifest, then resume its handover.
    BatchSend {
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Abort an uncommitted batch and release the local outgoing owner guard.
    BatchAbort {
        #[arg(long)]
        operation: PathBuf,
    },
    /// Freeze and advance a private, equal-value multi-coin swap agreement.
    SwapGroup {
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        plan: PathBuf,
    },
    /// Abort the entire uncommitted swap and release every local sender guard.
    SwapAbort {
        #[arg(long)]
        operation: PathBuf,
    },
    /// Cancel an ordinary transfer before issuance and release its local owner guard.
    Cancel {
        #[arg(long)]
        operation: PathBuf,
    },
    /// Accept an encrypted offer with a locally owned one-use invitation.
    Receive {
        #[arg(long)]
        invitation: PathBuf,
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        offer: PathBuf,
        #[arg(long)]
        coin: String,
        #[arg(long)]
        transfer_operation: String,
        #[arg(long, default_value_t = 1000)]
        recovery_fee: u64,
        #[arg(long)]
        batch: Option<PathBuf>,
        /// Refuse unless the decrypted coin has this exact gross/direct-exit value.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        expected_amount: Option<u64>,
    },
    /// Record the receiver's acceptance and retire the sender journal.
    Complete {
        #[arg(long)]
        operation: PathBuf,
    },
    /// Prepare and sign a cooperative exit; use --broadcast to also publish it.
    Exit {
        #[arg(long)]
        owner: PathBuf,
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long, default_value_t = 1000)]
        fee: u64,
        #[arg(long)]
        broadcast: bool,
    },
    ExportRecovery {
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Local metadata only; does not claim current ownership or chain freshness.
    Status {
        #[arg(long)]
        operation: PathBuf,
    },
}
