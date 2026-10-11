//! Advance deposits without publishing funding before recovery acceptance.
use super::config::App;
use super::storage::initialize_cli_local;
use super::{Kind, Metadata};
use crate::origin::{OriginJournal, OriginPhase};
use anyhow::Result;
use bitcoin::Address;
use serde_json::{Value, json};
use std::path::Path;

pub(super) fn ensure_origin(app: &App, root: &Path, metadata: &Metadata) -> Result<()> {
    let Kind::Origin {
        amount,
        activation_fee,
        recovery_fee,
    } = metadata.kind
    else {
        anyhow::bail!("not an origin operation")
    };
    drop(initialize_cli_local(
        &root.join("journal"),
        &serde_json::to_vec(metadata)?,
        |attempt| OriginJournal::create(attempt, &app.policy, amount, activation_fee, recovery_fee),
        |published| {
            let journal = OriginJournal::open(published, &app.policy)?;
            journal.require_parameters(amount, activation_fee, recovery_fee)?;
            Ok(journal)
        },
    )?);
    Ok(())
}

pub(super) fn advance_origin(
    app: &App,
    root: &Path,
    metadata: &Metadata,
    broadcast: bool,
) -> Result<Value> {
    ensure_origin(app, root, metadata)?;
    let scratch = root.join("verify");
    let mut journal = app.origin(root, metadata)?;
    if matches!(
        journal.phase(),
        OriginPhase::AllocatedRequest | OriginPhase::Allocated
    ) {
        let script = journal.allocate(&app.config.endpoint)?;
        return Ok(
            json!({"operation":root,"phase":"awaiting_external_funding","funding_address":Address::from_script(&script,app.network())?.to_string(),"next_action":"Bind a signed external transaction with origin-bind; do not broadcast it yet."}),
        );
    }
    if !matches!(
        journal.phase(),
        OriginPhase::Ready | OriginPhase::FundingBroadcast
    ) {
        if !journal.has_issuance_request() {
            journal.prepare_parent(&app.config.endpoint)?;
            journal.freeze_parent(&app.config.endpoint)?;
            journal.prepare_recovery(&app.config.endpoint)?;
            let proof = app.prove(
                root,
                "deposit_authorization",
                "deposit-authorization",
                |p| journal.write_deposit_witness(p),
            )?;
            journal.issue_recovery(&proof, app.v()?, &scratch, &app.config.endpoint)?;
        } else if !matches!(
            journal.phase(),
            OriginPhase::RecoveryComplete | OriginPhase::ParentReleased
        ) {
            match journal.retrieve_issued(app.v()?, &scratch, &app.config.endpoint) {
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Saved deposit response unavailable: {error}");
                    journal.retry_issuance(app.v()?, &scratch, &app.config.endpoint)?;
                }
            }
        }
        journal.accept_initial_recovery(app.v()?, &scratch, &app.config.endpoint)?;
        journal.freeze_certificate(app.v()?, &scratch)?;
    }
    let published = if broadcast {
        Some(
            journal
                .broadcast_funding(
                    app.v()?,
                    &scratch,
                    &app.config.endpoint,
                    &app.config.chain,
                    &app.control,
                )?
                .to_string(),
        )
    } else {
        None
    };
    Ok(
        json!({"operation":root,"phase":format!("{:?}",journal.phase()),"coin":hex::encode(journal.context().coin),
        "transaction_id":published,"recovery_and_activation_saved":true,"next_action":"Use advance --broadcast to publish the deposit, then wait for its required confirmations before sending."}),
    )
}
