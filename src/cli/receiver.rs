//! Advance recipient proof, recovery and acceptance in durable order.
use super::config::App;
use super::storage::{initialize_cli_local, read_private};
use super::{Kind, Metadata, swap_group};
use crate::envelope::OfferContext;
use crate::invitation::LocalInvitation;
use crate::receiver::ReceiverJournal;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::path::Path;
use zark_protocol::{hash, hex32};

pub(super) fn open_cli_receiver(
    app: &App,
    root: &Path,
    metadata: &Metadata,
) -> Result<(LocalInvitation, ReceiverJournal)> {
    let Kind::Receiver {
        invitation,
        coin,
        transfer_operation,
        offer_sha256,
        recovery_fee,
        batch,
        expected_amount,
        ..
    } = &metadata.kind
    else {
        anyhow::bail!("not receiver metadata")
    };
    let invitation = app.invitation(invitation)?;
    let context = OfferContext {
        deployment: app.policy.deployment,
        coin: hex32(coin)?,
        operation: hex32(transfer_operation)?,
    };
    if !root.join("journal").try_exists()? {
        let offer = read_private(
            &root.join("encrypted-offer.bin"),
            crate::envelope::MAX_ENVELOPE_BYTES,
        )?;
        ensure!(
            hash(&[&offer]) == hex32(offer_sha256)?,
            "frozen offer changed"
        );
        drop(initialize_cli_local(
            &root.join("journal"),
            &serde_json::to_vec(metadata)?,
            |attempt| ReceiverJournal::prepare(attempt, &invitation, &context, &offer, &app.policy),
            |published| ReceiverJournal::open(published, &invitation, &context, &app.policy),
        )?);
    }
    let mut journal =
        ReceiverJournal::open(&root.join("journal"), &invitation, &context, &app.policy)?;
    journal.require_cli_parameters(&hex32(offer_sha256)?, *recovery_fee)?;
    if let Some(amount) = expected_amount {
        journal.require_expected_amount(*amount)?;
    }
    if let Some(manifest) = batch {
        journal.bind_batch(manifest)?;
    }
    Ok((invitation, journal))
}

pub(super) fn advance_receiver(
    app: &App,
    root: &Path,
    metadata: &Metadata,
    group_authorization: Option<&swap_group::Authorization>,
) -> Result<Value> {
    swap_group::require_child_authorization(root, metadata, group_authorization)?;
    let Kind::Receiver { recovery_fee, .. } = &metadata.kind else {
        anyhow::bail!("not receiver metadata")
    };
    let (mut invitation, mut journal) = open_cli_receiver(app, root, metadata)?;
    let scratch = root.join("verify");
    journal.authorize_and_reserve(&mut invitation, app.v()?, &scratch)?;
    if let Some(gate) = group_authorization {
        gate.check_request(root, journal.issuance_request(app.v()?, &scratch)?.body())?;
    }
    if !journal.has_issuance_request() {
        journal.claim(&app.config.endpoint)?;
        journal.prepare_with_signer(*recovery_fee, &app.config.endpoint)?;
        let issuance = app.prove(
            root,
            "receiver_authorization",
            "receiver-authorization",
            |p| invitation.write_receiver_authorization_witness(&journal, app.v()?, &scratch, p),
        )?;
        if journal.batch().is_some() {
            if let Some(gate) = group_authorization {
                gate.check_live_set(app, Some(root))?;
            }
            if !journal.ready_batch(
                Some(&issuance),
                app.v()?,
                &scratch,
                &app.config.endpoint,
                &app.config.chain,
            )? {
                return Ok(
                    json!({"operation":root,"phase":"batch_ready","next_action":"Run advance after the other recipient becomes ready."}),
                );
            }
        } else {
            journal.issue(
                &issuance,
                app.v()?,
                &scratch,
                &app.config.endpoint,
                &app.config.chain,
            )?;
        }
    } else if !journal.has_completed_recovery()? {
        // A saved request may not yet have reached the server. Exact issue is
        // still safe, but a released response must be recoverable after expiry.
        match journal.retrieve_issued(app.v()?, &scratch, &app.config.endpoint) {
            Ok(_) => {}
            Err(error) => {
                eprintln!("Saved issuance retrieval unavailable: {error}");
                let saved = journal.issuance_request(app.v()?, &scratch)?;
                match zark_protocol::wire::Command::decode(saved.body())? {
                    zark_protocol::wire::Command::Issue { proof, .. } => journal
                        .issue(
                            &proof,
                            app.v()?,
                            &scratch,
                            &app.config.endpoint,
                            &app.config.chain,
                        )
                        .map(|_| ())?,
                    zark_protocol::wire::Command::BatchReady { .. } => {
                        if let Some(gate) = group_authorization {
                            gate.check_live_set(app, Some(root))?;
                        }
                        if !journal.ready_batch(
                            None,
                            app.v()?,
                            &scratch,
                            &app.config.endpoint,
                            &app.config.chain,
                        )? {
                            return Ok(
                                json!({"operation":root,"phase":"batch_ready","next_action":"Run advance after the other recipient becomes ready."}),
                            );
                        }
                    }
                    _ => anyhow::bail!("saved issuance command mismatch"),
                }
            }
        }
    }
    journal.freeze_certificate(app.v()?, &scratch)?;
    let binding = journal.accept(
        app.v()?,
        &scratch,
        &app.config.endpoint,
        &app.config.chain,
        &app.control,
    )?;
    Ok(
        json!({"operation":root,"accepted":true,"coin":hex::encode(binding.coin),"state":hex::encode(binding.state),"recovery_saved":true}),
    )
}
