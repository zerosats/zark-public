//! Canonical batch membership, peer drafts and abort handling.
use super::Kind;
use super::config::App;
use super::sender::{release_cancelled_sender, require_sender_owner, sender_from_owner};
use super::storage::read_bounded;
use crate::sender::SenderDraft;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;
use zark_protocol::address::{AddressNetwork, ReceivingAddress};
use zark_protocol::batch::{Manifest as BatchManifest, Member as BatchMember};
use zark_protocol::handoff::{Digest, TransferContext};
use zark_protocol::hex32;
use zark_protocol::local::ProcessLock;

pub(super) fn read_batch_manifest(path: &Path) -> Result<BatchManifest> {
    let bytes = read_bounded(path, 65_536)?;
    let manifest: BatchManifest = serde_json::from_slice(&bytes)?;
    manifest.validate()?;
    Ok(manifest)
}

/// Public draft transport deliberately has no local journal path or secret material.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerBatchDraft {
    pub(super) context: String,
    pub(super) coin: String,
    pub(super) revision: u64,
}

pub(super) fn read_peer_batch_member(path: &Path, deployment: &Digest) -> Result<BatchMember> {
    let bytes = read_bounded(path, 4096)?;
    let peer: PeerBatchDraft = serde_json::from_slice(&bytes)?;
    peer_batch_member(&peer, deployment)
}

pub(super) fn peer_batch_member(peer: &PeerBatchDraft, deployment: &Digest) -> Result<BatchMember> {
    let context = TransferContext::decode(&hex::decode(&peer.context)?)?;
    ensure!(
        context.deployment == *deployment,
        "peer draft deployment mismatch"
    );
    ensure!(
        context.coin == hex32(&peer.coin)?,
        "peer draft coin differs from context"
    );
    ensure!(
        peer.revision > 0 && peer.revision == context.start_revision,
        "peer draft revision mismatch"
    );
    ensure!(
        matches!(
            context.scope,
            zark_protocol::handoff::OperationScope::Single
        ),
        "peer draft already bound to a batch"
    );
    Ok(member_from_context(&context, peer.revision))
}

pub(super) fn member_from_context(context: &TransferContext, revision: u64) -> BatchMember {
    BatchMember {
        coin: context.coin,
        previous_state: context.previous_state,
        operation: context.operation,
        recipient_claim: context.recipient_claim,
        sender_session: context.session_auth,
        revision,
    }
}

pub(super) fn require_saved_peer(
    manifest: &BatchManifest,
    local: &TransferContext,
    peer: &BatchMember,
) -> Result<()> {
    require_draft_member(manifest, local)?;
    ensure!(
        local.coin != peer.coin,
        "batch members must have distinct coins"
    );
    ensure!(
        manifest.members.iter().any(|member| member == peer),
        "saved batch manifest differs from peer draft"
    );
    Ok(())
}

pub(super) fn require_draft_member(
    manifest: &BatchManifest,
    draft: &TransferContext,
) -> Result<()> {
    let mut context = draft.clone();
    let expected = zark_protocol::handoff::OperationScope::Batch {
        manifest_digest: manifest.digest()?,
    };
    ensure!(
        matches!(
            context.scope,
            zark_protocol::handoff::OperationScope::Single
        ) || context.scope == expected,
        "draft belongs to another batch"
    );
    context.scope = expected;
    manifest.index(&context, true)?;
    Ok(())
}

pub(super) fn owner_batch_revision(app: &App, owner: &Path, scratch: &Path) -> Result<u64> {
    let metadata = app.metadata(owner)?;
    match metadata.kind {
        Kind::Origin { .. } => app.origin(owner, &metadata)?.batch_revision(
            app.v()?,
            scratch,
            &app.config.endpoint,
            &app.control,
        ),
        Kind::Receiver { .. } => app.receiver(owner, &metadata)?.1.batch_revision(
            app.v()?,
            scratch,
            &app.config.endpoint,
            &app.control,
        ),
        _ => anyhow::bail!("batch source is not an accepted owner"),
    }
}

pub(super) fn abort_batch_sender(app: &App, root: &Path) -> Result<Value> {
    let metadata = app.metadata(root)?;
    let Kind::Sender {
        owner, recipient, ..
    } = &metadata.kind
    else {
        anyhow::bail!("batch-abort requires a sender operation")
    };
    let address =
        ReceivingAddress::decode(recipient, AddressNetwork::Test, &app.policy.deployment)?;
    let _lock = ProcessLock::acquire(&root.join(".cli.lock"))?;
    let mut sender = SenderDraft::open(&root.join("journal"), &app.policy)?;
    if !sender.is_aborted() {
        require_sender_owner(app, root, owner, &address, &sender)?;
        if sender.batch().is_some() {
            if let Err(abort_error) = sender.abort_batch(&app.config.endpoint) {
                owner_batch_revision(app, owner, &root.join("verify"))
                    .with_context(|| format!("batch abort did not complete: {abort_error}"))?;
                sender.cancel_after_accepted_head()?;
            }
        } else {
            owner_batch_revision(app, owner, &root.join("verify"))?;
            sender.cancel_after_accepted_head()?;
        }
    }
    drop(sender);
    release_cancelled_sender(app, root, owner, &address)?;
    Ok(
        json!({"operation":root,"aborted":true,"next_action":"The original owner may draft a fresh transfer."}),
    )
}

pub(super) fn batch_draft_context(
    app: &App,
    root: &Path,
) -> Result<zark_protocol::handoff::TransferContext> {
    let metadata = app.metadata(root)?;
    let Kind::Sender {
        owner, recipient, ..
    } = &metadata.kind
    else {
        anyhow::bail!("batch member is not a sender draft")
    };
    let address =
        ReceivingAddress::decode(recipient, AddressNetwork::Test, &app.policy.deployment)?;
    Ok(sender_from_owner(app, root, owner, &address)?
        .context()
        .clone())
}

pub(super) fn batch_member(app: &App, root: &Path) -> Result<BatchMember> {
    let metadata = app.metadata(root)?;
    let Kind::Sender {
        owner, recipient, ..
    } = &metadata.kind
    else {
        anyhow::bail!("batch member is not a sender draft")
    };
    let address =
        ReceivingAddress::decode(recipient, AddressNetwork::Test, &app.policy.deployment)?;
    let sender = sender_from_owner(app, root, owner, &address)?;
    ensure!(
        sender.batch().is_none() && sender.offer_bytes().is_err(),
        "batch member already started"
    );
    let ctx = sender.context().clone();
    drop(sender);
    let revision = owner_batch_revision(app, owner, &root.join("verify"))?;
    Ok(member_from_context(&ctx, revision))
}
