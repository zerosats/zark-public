//! Private economic agreement and full-set readiness gate. Signer manifests
//! contain no amounts; native-verified deposit values are checked only here.
use super::batch::{
    PeerBatchDraft, abort_batch_sender, batch_draft_context, batch_member, member_from_context,
    peer_batch_member, read_batch_manifest, require_draft_member,
};
use super::config::App;
use super::receiver::{advance_receiver, open_cli_receiver};
use super::sender::sender_from_owner;
use super::storage::{absolute, read_bounded, read_private, write_exact};
use super::{Kind, Metadata};
use crate::invitation::LocalInvitation;
use crate::receiver::ReceiverJournal;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use zark_protocol::address::{AddressNetwork, ReceivingAddress};
use zark_protocol::batch::Manifest as BatchManifest;
use zark_protocol::handoff::Digest;
use zark_protocol::local::ProcessLock;
use zark_protocol::{hash, hex32};

mod approval;
mod plan;
use approval::{
    authorized_receiver, check_complete_result, check_incoming, check_local_ready_result,
    check_outgoing, prepare_requests,
};
pub(super) use approval::{require_child_authorization, require_owner_group_ready};
pub(super) use plan::initialize;
use plan::{check_totals, expected_child, initialize_children, validate_plan};

const MAX_SIDE: usize = 5;
const MAX_PLAN_BYTES: usize = 200_000;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Outgoing {
    operation: PathBuf,
    amount_sat: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Incoming {
    operation: PathBuf,
    invitation: PathBuf,
    offer: PathBuf,
    coin: String,
    transfer_operation: String,
    amount_sat: u64,
    recovery_fee: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanInput {
    version: u32,
    agreement_id: String,
    manifest: PathBuf,
    outgoing: Vec<Outgoing>,
    incoming: Vec<Incoming>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FrozenIncoming {
    leg: Incoming,
    offer_sha256: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenPlan {
    version: u32,
    agreement_id: String,
    manifest: BatchManifest,
    outgoing: Vec<Outgoing>,
    incoming: Vec<FrozenIncoming>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestPin {
    operation: PathBuf,
    body_sha256: Digest,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Approval {
    plan_sha256: Digest,
    requests: Vec<RequestPin>,
}

/// Cannot be constructed by a child command or deserialized from a GUI hint.
pub(super) struct Authorization {
    root: PathBuf,
    plan: FrozenPlan,
    approval: Approval,
}

pub(super) fn advance_from_child(app: &App, child: &Path, root: &Path) -> Result<Value> {
    let metadata = app.metadata(root)?;
    let Kind::SwapGroup { plan } = &metadata.kind else {
        anyhow::bail!("receiver group is not a swap");
    };
    ensure!(
        plan.incoming.iter().any(|i| i.leg.operation == child),
        "receiver absent from swap group"
    );
    super::advance(app, root, false)
}

pub(super) fn advance(app: &App, root: &Path, plan: &FrozenPlan) -> Result<Value> {
    validate_plan(plan)?;
    ensure!(
        !root.join("aborted.json").try_exists()?,
        "swap group was aborted"
    );
    if root.join("complete.json").try_exists()? {
        let result =
            serde_json::from_slice(&read_private(&root.join("complete.json"), MAX_PLAN_BYTES)?)?;
        check_complete_result(&result, plan)?;
        return Ok(result);
    }
    initialize_children(app, root, plan)?;
    // Serialize cooperating child commands throughout the approval and release
    // boundary. Individual journals also take their existing native locks.
    let mut paths: Vec<_> = plan
        .outgoing
        .iter()
        .map(|o| &o.operation)
        .chain(plan.incoming.iter().map(|i| &i.leg.operation))
        .collect();
    paths.sort();
    let _locks = paths
        .iter()
        .map(|path| ProcessLock::acquire(&path.join(".cli.lock")))
        .collect::<Result<Vec<_>>>()?;
    let approval_path = root.join("approved.json");
    let plan_sha256 = hash(&[&serde_json::to_vec(plan)?]);
    let gate = if approval_path.try_exists()? {
        // Once readiness could have committed, never put a group-wide fresh
        // head/chain gate in front of retrieval of any released recovery.
        let approval: Approval =
            serde_json::from_slice(&read_private(&approval_path, MAX_PLAN_BYTES)?)?;
        ensure!(
            approval.plan_sha256 == plan_sha256 && approval.requests.len() == plan.incoming.len(),
            "swap approval or frozen plan changed"
        );
        for (request, incoming) in approval.requests.iter().zip(&plan.incoming) {
            ensure!(
                request.operation == incoming.leg.operation,
                "swap approved request membership changed"
            );
        }
        Authorization {
            root: root.to_path_buf(),
            plan: plan.clone(),
            approval,
        }
    } else {
        let outgoing_amounts = check_outgoing(app, plan)?;
        let incoming_amounts = check_incoming(app, root, plan)?;
        check_totals(&outgoing_amounts, &incoming_amounts)?;
        let requests = prepare_requests(app, plan)?;
        let approval = Approval {
            plan_sha256,
            requests,
        };
        let gate = Authorization {
            root: root.to_path_buf(),
            plan: plan.clone(),
            approval,
        };
        gate.check_live_set(app, None)?;
        write_exact(&approval_path, &serde_json::to_vec(&gate.approval)?)?;
        gate
    };
    // Recover all already issued signatures first. A failure on one child
    // must not strand a different child's released Bitcoin recovery.
    let _retrieval_attempts = attempt_every(&plan.incoming, |incoming| {
        let path = &incoming.leg.operation;
        let metadata = app.metadata(path)?;
        ensure!(
            metadata.kind == expected_child(root, plan, incoming),
            "swap child parameters changed"
        );
        let (mut invitation, mut journal) = open_cli_receiver(app, path, &metadata)?;
        let scratch = path.join("verify");
        journal.authorize_and_reserve(&mut invitation, app.v()?, &scratch)?;
        gate.check_request(path, journal.issuance_request(app.v()?, &scratch)?.body())?;
        if !journal.has_completed_recovery()? {
            journal.retrieve_issued(app.v()?, &scratch, &app.config.endpoint)?;
        }
        journal.freeze_certificate(app.v()?, &scratch)?;
        Ok(())
    });
    let mut incoming_results = Vec::new();
    for (incoming, attempt) in plan
        .incoming
        .iter()
        .zip(attempt_every(&plan.incoming, |incoming| {
            let path = &incoming.leg.operation;
            let metadata = app.metadata(path)?;
            ensure!(
                metadata.kind == expected_child(root, plan, incoming),
                "swap child parameters changed"
            );
            let (invitation, journal) = authorized_receiver(app, path, &metadata)?;
            let accepted = journal.phase() == crate::receiver::ReceiverPhase::Accepted;
            if accepted {
                gate.check_request(
                    path,
                    journal
                        .issuance_request(app.v()?, &path.join("verify"))?
                        .body(),
                )?;
                ensure!(
                    journal.has_completed_recovery()?,
                    "accepted swap recovery missing"
                );
                return Ok(json!({"accepted":true,"recovery_saved":true}));
            }
            drop(journal);
            drop(invitation);
            advance_receiver(app, path, &metadata, Some(&gate))
        }))
    {
        let path = &incoming.leg.operation;
        incoming_results.push(match attempt {
            Ok(result) => json!({"operation":path,"coin":incoming.leg.coin,"accepted":result["accepted"] == true,"recovery_saved":result["recovery_saved"] == true}),
            Err(error) => {
                let recovery_saved = app.metadata(path).and_then(|m| app.receiver(path,&m)).and_then(|(_,j)|j.has_completed_recovery()).unwrap_or(false);
                json!({"operation":path,"coin":incoming.leg.coin,"accepted":false,"recovery_saved":recovery_saved,"error":error.to_string()})
            }
        });
    }
    let mut outgoing_results = Vec::new();
    for (outgoing, attempt) in plan
        .outgoing
        .iter()
        .zip(attempt_every(&plan.outgoing, |outgoing| {
            let path = &outgoing.operation;
            let metadata = app.metadata(path)?;
            let Kind::Sender {
                owner, recipient, ..
            } = &metadata.kind
            else {
                anyhow::bail!("swap outgoing not sender");
            };
            let address =
                ReceivingAddress::decode(recipient, AddressNetwork::Test, &app.policy.deployment)?;
            let mut sender = sender_from_owner(app, path, owner, &address)?;
            sender.complete(&app.config.endpoint)
        }))
    {
        outgoing_results.push(match attempt {
            Ok(completed) => json!({"operation":outgoing.operation,"completed":completed}),
            Err(error) => {
                json!({"operation":outgoing.operation,"completed":false,"error":error.to_string()})
            }
        });
    }
    let completed = incoming_results.iter().all(|r| r["accepted"] == true)
        && outgoing_results.iter().all(|r| r["completed"] == true);
    let result = json!({"operation":root,"phase":if completed {"complete"} else {"batch_ready"},
        "completed":completed,"waiting":!completed,"incoming":incoming_results,"outgoing":outgoing_results});
    if check_local_ready_result(&result, plan).is_ok() {
        let ready =
            json!({"operation":root,"plan_sha256":plan_sha256,"incoming":result["incoming"]});
        write_exact(&root.join("local-ready.json"), &serde_json::to_vec(&ready)?)?;
    }
    zark_protocol::storage::atomic_write(
        &root.join("progress.json"),
        &serde_json::to_vec(&result)?,
    )?;
    if completed {
        write_exact(&root.join("complete.json"), &serde_json::to_vec(&result)?)?;
    }
    Ok(result)
}

fn attempt_every<T, U>(members: &[T], mut action: impl FnMut(&T) -> Result<U>) -> Vec<Result<U>> {
    members.iter().map(&mut action).collect()
}

pub(super) fn abort(app: &App, root: &Path) -> Result<Value> {
    let metadata = app.metadata(root)?;
    let Kind::SwapGroup { plan } = &metadata.kind else {
        anyhow::bail!("swap-abort requires a swap group");
    };
    let _lock = ProcessLock::acquire(&root.join(".cli.lock"))?;
    ensure!(
        !root.join("complete.json").try_exists()?,
        "completed swap cannot abort"
    );
    for outgoing in &plan.outgoing {
        abort_batch_sender(app, &outgoing.operation)?;
    }
    let result = json!({"operation":root,"aborted":true});
    write_exact(&root.join("aborted.json"), &serde_json::to_vec(&result)?)?;
    Ok(result)
}

pub(super) fn status(root: &Path, plan: &FrozenPlan) -> Result<Value> {
    validate_plan(plan)?;
    let mut result = if root.join("progress.json").try_exists()? {
        serde_json::from_slice::<Value>(&read_private(
            &root.join("progress.json"),
            MAX_PLAN_BYTES,
        )?)?
    } else {
        json!({"operation":root,"phase":"preparing","completed":false,"waiting":true})
    };
    result["kind"] = json!("swap_group");
    result["metadata_only"] = json!(true);
    result["current_ownership_verified"] = json!(false);
    Ok(result)
}

pub(super) fn manifest(
    app: &App,
    drafts: &[PathBuf],
    peers: &Path,
    expires_at: u64,
    output: &Path,
) -> Result<Value> {
    let peers: Vec<PeerBatchDraft> = serde_json::from_slice(&read_bounded(peers, 24_000)?)
        .map_err(|_| anyhow::anyhow!("invalid public peer draft list"))?;
    ensure!(
        (1..=MAX_SIDE).contains(&drafts.len()) && (1..=MAX_SIDE).contains(&peers.len()),
        "batch requires one to five drafts on each side"
    );
    let output = absolute(output)?;
    let saved = output
        .try_exists()?
        .then(|| read_batch_manifest(&output))
        .transpose()?;
    let mut members = Vec::new();
    for draft in drafts {
        let path = absolute(draft)?;
        let member = if let Some(saved) = &saved {
            let context = batch_draft_context(app, &path)?;
            require_draft_member(saved, &context)?;
            member_from_context(&context, context.start_revision)
        } else {
            batch_member(app, &path)?
        };
        members.push(member);
    }
    for peer in peers {
        members.push(peer_batch_member(&peer, &app.policy.deployment)?);
    }
    members.sort_by_key(|m| m.coin);
    let manifest = if let Some(saved) = saved {
        ensure!(
            saved.deployment == app.policy.deployment
                && saved.expires_at == expires_at
                && saved.members == members,
            "saved batch manifest differs from exact draft set"
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
        json!({"manifest":output,"batch":hex::encode(manifest.id),"digest":hex::encode(manifest.digest()?),
        "members":manifest.members.iter().map(|m| hex::encode(m.coin)).collect::<Vec<_>>()}),
    )
}

#[cfg(test)]
mod tests;
