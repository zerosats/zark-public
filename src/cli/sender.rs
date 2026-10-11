//! Resume transfers and release owner guards only after cancellation.
use super::batch::owner_batch_revision;
use super::config::App;
use super::storage::write_exact;
use super::{Kind, swap_group};
use crate::sender::SenderDraft;
use anyhow::Result;
use serde_json::{Value, json};
use std::path::Path;
use zark_protocol::address::{AddressNetwork, ReceivingAddress};

pub(super) fn sender_from_owner(
    app: &App,
    root: &Path,
    owner: &Path,
    recipient: &ReceivingAddress,
) -> Result<SenderDraft> {
    swap_group::require_owner_group_ready(app, owner)?;
    if root.join("journal").try_exists()? {
        let sender = SenderDraft::open(&root.join("journal"), &app.policy)?;
        require_sender_owner(app, root, owner, recipient, &sender)?;
        return Ok(sender);
    }
    let metadata = app.metadata(owner)?;
    let scratch = root.join("verify");
    match &metadata.kind {
        Kind::Origin { .. } => app.origin(owner, &metadata)?.create_sender(
            &root.join("journal"),
            recipient,
            app.v()?,
            &scratch,
            &app.config.endpoint,
            &app.config.chain,
            &app.control,
        ),
        Kind::Receiver { .. } => {
            let (mut invitation, mut journal) = app.receiver(owner, &metadata)?;
            journal.authorize_and_reserve(&mut invitation, app.v()?, &scratch)?;
            journal.create_sender(
                &root.join("journal"),
                recipient,
                app.v()?,
                &scratch,
                &app.config.endpoint,
                &app.config.chain,
                &app.control,
            )
        }
        _ => anyhow::bail!("send requires an accepted origin or receiver operation"),
    }
}

pub(super) fn release_cancelled_sender(
    app: &App,
    root: &Path,
    owner: &Path,
    address: &ReceivingAddress,
) -> Result<()> {
    // An old cancellation receipt cannot establish current availability.
    owner_batch_revision(app, owner, &root.join("verify"))?;
    let metadata = app.metadata(owner)?;
    match metadata.kind {
        Kind::Origin { .. } => app
            .origin(owner, &metadata)?
            .clear_aborted_sender(&root.join("journal"), address),
        Kind::Receiver { .. } => app
            .receiver(owner, &metadata)?
            .1
            .clear_aborted_sender(&root.join("journal"), address),
        _ => anyhow::bail!("transfer source is not an accepted owner"),
    }
}

pub(super) fn require_sender_owner(
    app: &App,
    root: &Path,
    owner: &Path,
    recipient: &ReceivingAddress,
    sender: &SenderDraft,
) -> Result<()> {
    let metadata = app.metadata(owner)?;
    match &metadata.kind {
        Kind::Origin { .. } => app.origin(owner, &metadata)?.require_saved_sender(
            &root.join("journal"),
            recipient,
            sender,
        ),
        Kind::Receiver { .. } => {
            let (_, journal) = app.receiver(owner, &metadata)?;
            journal.require_saved_sender(&root.join("journal"), recipient, sender)
        }
        _ => anyhow::bail!("send requires an origin or receiver source operation"),
    }
}

pub(super) fn advance_sender(
    app: &App,
    root: &Path,
    owner: &Path,
    recipient: &str,
    output: &Path,
) -> Result<Value> {
    let address =
        ReceivingAddress::decode(recipient, AddressNetwork::Test, &app.policy.deployment)?;
    let mut journal = sender_from_owner(app, root, owner, &address)?;
    let scratch = root.join("verify");
    if journal.offer_bytes().is_err() {
        if !journal.has_reservation_mask() {
            journal.reserve(app.v()?, &scratch, &app.config.endpoint, &app.config.chain)?;
            if let Some(manifest) = journal.batch() {
                return Ok(
                    json!({"operation":root,"batch":hex::encode(manifest.id),"phase":"joined","next_action":"After both senders join, run advance on this sender operation."}),
                );
            }
        }
        let role = match journal.sender_role()? {
            zark_protocol::proof::Relation::SenderFromOrigin => "sender_from_origin",
            zark_protocol::proof::Relation::SenderFromTransfer => "sender_from_transfer",
            _ => anyhow::bail!("invalid sender predecessor role"),
        };
        let sender = app.prove(root, role, "sender", |p| {
            journal.write_sender_witness(p, app.v()?, &scratch)
        })?;
        journal.authorize_handover(
            &sender,
            app.v()?,
            &scratch,
            &app.config.endpoint,
            &app.config.chain,
        )?;
    }
    write_exact(output, &journal.offer_bytes()?)?;
    Ok(
        json!({"operation":root,"offer":output,"coin":hex::encode(journal.context().coin),
        "transfer_operation":hex::encode(journal.context().operation),"next_action":"Deliver this encrypted offer and context to the recipient; after acceptance run complete."}),
    )
}
