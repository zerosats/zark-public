//! Resume cooperative exits and optionally publish the signed transaction.
use super::address::taproot_destination;
use super::config::App;
use super::{Kind, swap_group};
use crate::exit_operation::ExitOperation;
use anyhow::Result;
use bitcoin::Address;
use serde_json::{Value, json};
use std::path::Path;
use std::str::FromStr;
use zark_protocol::handoff::Digest;

pub(super) fn require_exit_owner(
    app: &App,
    root: &Path,
    owner: &Path,
    destination: &Digest,
    fee: u64,
    exit: &ExitOperation,
) -> Result<()> {
    let metadata = app.metadata(owner)?;
    match &metadata.kind {
        Kind::Origin { .. } => app.origin(owner, &metadata)?.require_saved_exit(
            &root.join("journal"),
            destination,
            fee,
            exit,
        ),
        Kind::Receiver { .. } => {
            let (_, journal) = app.receiver(owner, &metadata)?;
            journal.require_saved_exit(&root.join("journal"), destination, fee, exit)
        }
        _ => anyhow::bail!("exit requires an origin or receiver source operation"),
    }
}
pub(super) fn advance_exit(
    app: &App,
    root: &Path,
    owner: &Path,
    destination: &str,
    fee: u64,
    broadcast: bool,
) -> Result<Value> {
    swap_group::require_owner_group_ready(app, owner)?;
    let address = Address::from_str(destination)?.require_network(app.network())?;
    let target = taproot_destination(&address)?;
    let scratch = root.join("verify");
    let mut journal = if root.join("journal").try_exists()? {
        let exit = ExitOperation::open(&root.join("journal"), &app.policy)?;
        require_exit_owner(app, root, owner, &target, fee, &exit)?;
        exit
    } else {
        let metadata = app.metadata(owner)?;
        match &metadata.kind {
            Kind::Origin { .. } => app.origin(owner, &metadata)?.create_exit(
                &root.join("journal"),
                target,
                fee,
                app.v()?,
                &scratch,
                &app.config.endpoint,
                &app.config.chain,
                &app.control,
            )?,
            Kind::Receiver { .. } => {
                let (mut invitation, mut receiver) = app.receiver(owner, &metadata)?;
                receiver.authorize_and_reserve(&mut invitation, app.v()?, &scratch)?;
                receiver.create_exit(
                    &root.join("journal"),
                    target,
                    fee,
                    app.v()?,
                    &scratch,
                    &app.config.endpoint,
                    &app.config.chain,
                    &app.control,
                )?
            }
            _ => anyhow::bail!("exit requires an accepted owner operation"),
        }
    };
    if !journal.is_terminal()? {
        if !journal.is_prepared()? {
            journal.prepare(app.v()?, &scratch, &app.config.endpoint, &app.config.chain)?;
        }
        let role = match journal.proof_role()? {
            zark_protocol::proof::Relation::ExitFromOrigin => "exit_from_origin",
            zark_protocol::proof::Relation::ExitFromTransfer => "exit_from_transfer",
            _ => anyhow::bail!("invalid exit predecessor role"),
        };
        let proof = app.prove(root, role, "cooperative-exit", |p| {
            journal.write_authorization_witness(p, app.p()?, app.v()?, &scratch)
        })?;
        if journal.has_issuance_request()? {
            match journal.retrieve(&app.config.endpoint) {
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Saved exit retrieval unavailable: {error}");
                    journal.issue(
                        &proof,
                        app.v()?,
                        &scratch,
                        &app.config.endpoint,
                        &app.config.chain,
                    )?;
                }
            }
        } else {
            journal.issue(
                &proof,
                app.v()?,
                &scratch,
                &app.config.endpoint,
                &app.config.chain,
            )?;
        }
    }
    if broadcast {
        journal.publish(&app.config.chain)
    } else {
        Ok(
            json!({"operation":root,"signature_status":"released_terminal","broadcast":false,"next_action":"Run advance --broadcast for this operation to broadcast its exact exit transaction."}),
        )
    }
}
