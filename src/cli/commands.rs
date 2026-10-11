//! Dispatch user commands into durable native operations.
use super::address::{taproot_destination, validate_address};
use super::arguments::{Action, Cli};
use super::batch::{
    abort_batch_sender, batch_draft_context, batch_member, owner_batch_revision,
    read_batch_manifest, read_peer_batch_member, require_draft_member, require_saved_peer,
};
use super::config::App;
use super::origin::ensure_origin;
use super::sender::{release_cancelled_sender, require_sender_owner, sender_from_owner};
use super::storage::{absolute, read_bounded, write_exact};
use super::{Kind, advance, status, swap_group};
use crate::invitation::LocalInvitation;
use crate::sender::SenderDraft;
use anyhow::{Context, Result, ensure};
use bitcoin::consensus::deserialize;
use bitcoin::{Address, Transaction};
use serde_json::{Value, json};
use std::str::FromStr;
use zark_protocol::address::{AddressNetwork, ReceivingAddress};
use zark_protocol::batch::Manifest as BatchManifest;
use zark_protocol::local::ProcessLock;
use zark_protocol::{hash, hex32};

pub(super) fn execute(cli: Cli) -> Result<Value> {
    let need_proofs = !matches!(
        &cli.command,
        Action::Status { .. }
            | Action::ExportRecovery { .. }
            | Action::NewAddress { .. }
            | Action::ValidateAddress { .. }
            | Action::MailCrypto { .. }
    );
    let app = App::load(&cli.config, need_proofs)?;
    execute_with_app(&app, cli.command)
}

pub(super) fn execute_with_app(app: &App, command: Action) -> Result<Value> {
    if matches!(
        command,
        Action::OriginCreate { .. }
            | Action::Advance { .. }
            | Action::Send { .. }
            | Action::BatchSend { .. }
            | Action::Cancel { .. }
            | Action::SwapGroup { .. }
            | Action::Receive { .. }
            | Action::Complete { .. }
            | Action::Exit { .. }
    ) {
        app.config.endpoint.preconnect();
    }
    if matches!(
        command,
        Action::Advance { .. }
            | Action::Send { .. }
            | Action::BatchSend { .. }
            | Action::SwapGroup { .. }
            | Action::Receive { .. }
            | Action::Exit { .. }
    ) {
        app.config.chain.prepare_connection();
    }
    match command {
        Action::Worker => anyhow::bail!("nested wallet worker is not permitted"),
        Action::MailCrypto { input, output } => super::mail::execute(app, input, output),
        Action::VerifyAssets => {
            app.v()?;
            app.p()?;
            Ok(
                json!({"verified":true,"version":10,"deployment":hex::encode(app.policy.deployment),"proof_roles":6}),
            )
        }
        Action::ValidateAddress { address } => {
            let kind = validate_address(&address, &app.policy.deployment, app.network())?;
            Ok(json!({"valid":true,"kind":kind}))
        }
        Action::NewAddress { directory } => {
            let path = absolute(&directory)?;
            let invitation = if path.try_exists()? {
                app.invitation(&path)?
            } else {
                LocalInvitation::create(&path, AddressNetwork::Test, app.policy.deployment)?
            };
            Ok(
                json!({"address":invitation.public_address()?.encode(),"directory":path,"one_use":true}),
            )
        }
        Action::OriginCreate {
            operation,
            amount,
            activation_fee,
            recovery_fee,
        } => {
            let root = absolute(&operation)?;
            let metadata = app.initialize(
                &root,
                Kind::Origin {
                    amount,
                    activation_fee,
                    recovery_fee,
                },
            )?;
            let _lock = ProcessLock::acquire(&root.join(".cli.lock"))?;
            ensure_origin(app, &root, &metadata)?;
            let mut origin = app.origin(&root, &metadata)?;
            let script = origin.allocate(&app.config.endpoint)?;
            Ok(
                json!({"operation":root,"funding_address":Address::from_script(&script,app.network())?.to_string(),"amount_sat":amount,
                "next_action":"Create and sign external funding without broadcasting; then run origin-bind."}),
            )
        }
        Action::OriginBind {
            operation,
            transaction,
            vout,
        } => {
            let root = absolute(&operation)?;
            let metadata = app.metadata(&root)?;
            ensure!(
                matches!(metadata.kind, Kind::Origin { .. }),
                "not an origin operation"
            );
            let _lock = ProcessLock::acquire(&root.join(".cli.lock"))?;
            let encoded = read_bounded(&transaction, 1_000_000)?;
            let text = std::str::from_utf8(&encoded)?.trim();
            let transaction: Transaction = deserialize(&hex::decode(text)?)?;
            app.origin(&root, &metadata)?
                .bind_funding(&transaction, vout)?;
            Ok(
                json!({"operation":root,"funding_bound":true,"broadcast":false,"transaction_id":transaction.compute_txid().to_string()}),
            )
        }
        Action::Advance {
            operation,
            broadcast,
        } => advance(app, &absolute(&operation)?, broadcast),
        Action::Send {
            owner,
            operation,
            to,
            output,
        } => {
            let root = absolute(&operation)?;
            let recipient =
                ReceivingAddress::decode(&to, AddressNetwork::Test, &app.policy.deployment)?;
            app.initialize(
                &root,
                Kind::Sender {
                    owner: absolute(&owner)?,
                    recipient: recipient.encode(),
                    output: absolute(&output)?,
                },
            )?;
            advance(app, &root, false)
        }
        Action::BatchDraft {
            owner,
            operation,
            to,
            output,
        } => {
            let root = absolute(&operation)?;
            let address =
                ReceivingAddress::decode(&to, AddressNetwork::Test, &app.policy.deployment)?;
            let owner = absolute(&owner)?;
            app.initialize(
                &root,
                Kind::Sender {
                    owner: owner.clone(),
                    recipient: address.encode(),
                    output: absolute(&output)?,
                },
            )?;
            let sender = sender_from_owner(app, &root, &owner, &address)?;
            let context = sender.context().clone();
            let saved_revision = sender
                .batch()
                .map(|manifest| {
                    manifest
                        .members
                        .iter()
                        .find(|member| member.coin == context.coin)
                        .map(|member| member.revision)
                        .context("sender absent from saved batch")
                })
                .transpose()?;
            drop(sender);
            let revision = if let Some(revision) = saved_revision {
                revision
            } else {
                owner_batch_revision(app, &owner, &root.join("verify"))?
            };
            Ok(
                json!({"operation":root,"context":hex::encode(context.encode()?),"coin":hex::encode(context.coin),"revision":revision,"next_action":"Draft the second sender, create one batch manifest, then run batch-send for both."}),
            )
        }
        Action::BatchManifest {
            first,
            second,
            peer,
            draft,
            peer_drafts,
            expires_at,
            output,
        } => {
            if !draft.is_empty() {
                return swap_group::manifest(
                    app,
                    &draft,
                    peer_drafts.as_deref().context("missing peer drafts")?,
                    expires_at,
                    &output,
                );
            }
            let first = absolute(first.as_deref().context("missing first batch member")?)?;
            let second = second.as_deref().map(absolute).transpose()?;
            let peer = peer
                .as_deref()
                .map(|path| read_peer_batch_member(path, &app.policy.deployment))
                .transpose()?;
            let output = absolute(&output)?;
            let manifest = if output.try_exists()? {
                let saved = read_batch_manifest(&output)?;
                ensure!(
                    saved.members.len() == 2,
                    "saved manifest is not a two-coin batch"
                );
                let local = batch_draft_context(app, &first)?;
                require_draft_member(&saved, &local)?;
                if let Some(peer) = &peer {
                    require_saved_peer(&saved, &local, peer)?;
                } else {
                    let other = batch_draft_context(
                        app,
                        second.as_deref().context("missing second batch member")?,
                    )?;
                    ensure!(
                        local.coin != other.coin,
                        "batch members must have distinct coins"
                    );
                    require_draft_member(&saved, &other)?;
                }
                ensure!(
                    saved.deployment == app.policy.deployment && saved.expires_at == expires_at,
                    "saved batch manifest differs from current draft"
                );
                saved
            } else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                ensure!(
                    expires_at > now + 300 && expires_at <= now + 86_400,
                    "batch expiry must be 5 minutes to 24 hours away"
                );
                let second = match peer {
                    Some(member) => member,
                    None => batch_member(
                        app,
                        second.as_deref().context("missing second batch member")?,
                    )?,
                };
                let mut members = vec![batch_member(app, &first)?, second];
                members.sort_by_key(|m| m.coin);
                BatchManifest {
                    id: zark_protocol::random32(),
                    deployment: app.policy.deployment,
                    expires_at,
                    members,
                }
            };
            manifest.validate()?;
            write_exact(&output, &serde_json::to_vec_pretty(&manifest)?)?;
            Ok(
                json!({"manifest":output,"batch":hex::encode(manifest.id),"digest":hex::encode(manifest.digest()?),"members":[hex::encode(manifest.members[0].coin),hex::encode(manifest.members[1].coin)]}),
            )
        }
        Action::BatchSend {
            operation,
            manifest,
        } => {
            let root = absolute(&operation)?;
            let metadata = app.metadata(&root)?;
            let Kind::Sender {
                owner, recipient, ..
            } = &metadata.kind
            else {
                anyhow::bail!("batch-send requires a drafted sender")
            };
            let address =
                ReceivingAddress::decode(recipient, AddressNetwork::Test, &app.policy.deployment)?;
            let manifest = read_batch_manifest(&manifest)?;
            let mut sender = sender_from_owner(app, &root, owner, &address)?;
            sender.bind_batch(&manifest)?;
            drop(sender);
            advance(app, &root, false)
        }
        Action::Cancel { operation } => {
            let root = absolute(&operation)?;
            let metadata = app.metadata(&root)?;
            let Kind::Sender {
                owner, recipient, ..
            } = &metadata.kind
            else {
                anyhow::bail!("cancel requires a sender operation")
            };
            let address =
                ReceivingAddress::decode(recipient, AddressNetwork::Test, &app.policy.deployment)?;
            let _lock = ProcessLock::acquire(&root.join(".cli.lock"))?;
            let mut sender = SenderDraft::open(&root.join("journal"), &app.policy)?;
            ensure!(
                sender.batch().is_none(),
                "batch members require batch-abort"
            );
            if !sender.is_aborted() {
                require_sender_owner(app, &root, owner, &address, &sender)?;
                if sender.has_reservation_request() {
                    // Includes response loss: the request is saved before it is sent.
                    sender.cancel_transfer(&app.config.endpoint)?;
                } else {
                    owner_batch_revision(app, owner, &root.join("verify"))?;
                    sender.cancel_after_accepted_head()?;
                }
            }
            drop(sender);
            release_cancelled_sender(app, &root, owner, &address)?;
            Ok(json!({"operation":root,"cancelled":true,
                "next_action":"The original owner may start a fresh transfer or cooperative exit."}))
        }
        Action::BatchAbort { operation } => {
            let root = absolute(&operation)?;
            abort_batch_sender(app, &root)
        }
        Action::SwapGroup { operation, plan } => {
            let root = absolute(&operation)?;
            swap_group::initialize(app, &root, &plan)?;
            advance(app, &root, false)
        }
        Action::SwapAbort { operation } => swap_group::abort(app, &absolute(&operation)?),
        Action::Receive {
            invitation,
            operation,
            offer,
            coin,
            transfer_operation,
            recovery_fee,
            batch,
            expected_amount,
        } => {
            let root = absolute(&operation)?;
            hex32(&coin)?;
            hex32(&transfer_operation)?;
            let bytes = read_bounded(&offer, crate::envelope::MAX_ENVELOPE_BYTES)?;
            let batch = batch.as_deref().map(read_batch_manifest).transpose()?;
            if let Some(manifest) = &batch {
                ensure!(
                    manifest.members.len() == 2,
                    "multi-coin receive requires a native swap-group agreement"
                );
                let coin_id = hex32(&coin)?;
                let operation_id = hex32(&transfer_operation)?;
                ensure!(
                    manifest.deployment == app.policy.deployment
                        && manifest
                            .members
                            .iter()
                            .any(|m| m.coin == coin_id && m.operation == operation_id),
                    "receiver offer absent from batch"
                );
            }
            app.initialize(
                &root,
                Kind::Receiver {
                    invitation: absolute(&invitation)?,
                    coin,
                    transfer_operation,
                    offer_sha256: hex::encode(hash(&[&bytes])),
                    recovery_fee,
                    batch: batch.map(Box::new),
                    expected_amount,
                    group: None,
                },
            )?;
            write_exact(&root.join("encrypted-offer.bin"), &bytes)?;
            advance(app, &root, false)
        }
        Action::Complete { operation } => {
            let root = absolute(&operation)?;
            let metadata = app.metadata(&root)?;
            let Kind::Sender {
                owner, recipient, ..
            } = &metadata.kind
            else {
                anyhow::bail!("not a sender operation")
            };
            let _lock = ProcessLock::acquire(&root.join(".cli.lock"))?;
            let address =
                ReceivingAddress::decode(recipient, AddressNetwork::Test, &app.policy.deployment)?;
            let mut sender = sender_from_owner(app, &root, owner, &address)?;
            let complete = sender.complete(&app.config.endpoint)?;
            Ok(json!({"operation":root,"completed":complete,"waiting":!complete}))
        }
        Action::Exit {
            owner,
            operation,
            to,
            fee,
            broadcast,
        } => {
            let address = Address::from_str(&to)?.require_network(app.network())?;
            taproot_destination(&address)?;
            let root = absolute(&operation)?;
            app.initialize(
                &root,
                Kind::Exit {
                    owner: absolute(&owner)?,
                    destination: address.to_string(),
                    fee,
                },
            )?;
            advance(app, &root, broadcast)
        }
        Action::ExportRecovery { operation, output } => {
            let root = absolute(&operation)?;
            let metadata = app.metadata(&root)?;
            let _lock = ProcessLock::acquire(&root.join(".cli.lock"))?;
            match metadata.kind {
                Kind::Origin { .. } => app.origin(&root, &metadata)?.export_recovery(&output)?,
                Kind::Receiver { .. } => {
                    let (_invitation, journal) = app.receiver(&root, &metadata)?;
                    journal.export_recovery(&output)?;
                }
                _ => anyhow::bail!(
                    "export recovery from the accepted owner operation, not its outgoing operation"
                ),
            }
            Ok(json!({"exported":true,"output":output,"contains_private_recovery_data":true}))
        }
        Action::Status { operation } => status(app, &absolute(&operation)?),
    }
}
