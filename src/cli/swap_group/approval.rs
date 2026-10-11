//! Validate every member and bind readiness to the exact full-set approval.
use super::{
    AddressNetwork, App, Authorization, BTreeSet, Context, FrozenPlan, Kind, LocalInvitation,
    MAX_PLAN_BYTES, Metadata, Path, ReceiverJournal, ReceivingAddress, RequestPin, Result, Value,
    ensure, expected_child, hash, hex32, json, open_cli_receiver, read_private, sender_from_owner,
};

pub(super) fn check_complete_result(result: &Value, plan: &FrozenPlan) -> Result<()> {
    ensure!(result["completed"] == true, "swap group is not complete");
    check_local_ready_result(result, plan)?;
    let outgoing = result["outgoing"]
        .as_array()
        .context("swap completion outgoing set")?;
    ensure!(
        outgoing.len() == plan.outgoing.len(),
        "swap completion member count changed"
    );
    for (saved, expected) in outgoing.iter().zip(&plan.outgoing) {
        ensure!(
            saved["operation"] == json!(expected.operation) && saved["completed"] == true,
            "swap completion omits outgoing retirement"
        );
    }
    Ok(())
}

pub(super) fn check_local_ready_result(result: &Value, plan: &FrozenPlan) -> Result<()> {
    let incoming = result["incoming"]
        .as_array()
        .context("swap completion incoming set")?;
    ensure!(
        incoming.len() == plan.incoming.len(),
        "swap completion member count changed"
    );
    for (saved, expected) in incoming.iter().zip(&plan.incoming) {
        ensure!(
            saved["operation"] == json!(expected.leg.operation)
                && saved["coin"] == expected.leg.coin
                && saved["accepted"] == true
                && saved["recovery_saved"] == true,
            "swap completion omits incoming ownership"
        );
    }
    Ok(())
}

/// Receiving one committed member is not permission to spend it while the
/// wallet still needs to retrieve its incoming set. Once local recovery and
/// acceptance are durable, an offline peer's acknowledgement cannot block
/// onward transfer or cooperative exit. Unilateral recovery is never gated.
pub(in crate::cli) fn require_owner_group_ready(app: &App, owner: &Path) -> Result<()> {
    let metadata = app.metadata(owner)?;
    if let Kind::Receiver {
        group: Some(group), ..
    } = &metadata.kind
    {
        let group_metadata = app.metadata(group)?;
        let Kind::SwapGroup { plan } = &group_metadata.kind else {
            anyhow::bail!("owner group is not a swap");
        };
        ensure!(
            plan.incoming.iter().any(|i| i.leg.operation == owner),
            "owner absent from swap group"
        );
        let result: Value = serde_json::from_slice(
            &read_private(&group.join("local-ready.json"), MAX_PLAN_BYTES).context(
                "save and accept every incoming swap coin before spending a received member",
            )?,
        )?;
        ensure!(
            result["plan_sha256"] == json!(hash(&[&serde_json::to_vec(plan)?])),
            "local swap readiness belongs to another agreement"
        );
        check_local_ready_result(&result, plan)?;
    }
    Ok(())
}

pub(super) fn authorized_receiver(
    app: &App,
    root: &Path,
    metadata: &Metadata,
) -> Result<(LocalInvitation, ReceiverJournal)> {
    let (mut invitation, mut journal) = app.receiver(root, metadata)?;
    journal.authorize_and_reserve(&mut invitation, app.v()?, &root.join("verify"))?;
    Ok((invitation, journal))
}

pub(super) fn check_outgoing(app: &App, plan: &FrozenPlan) -> Result<Vec<u64>> {
    let incoming: BTreeSet<_> = plan
        .incoming
        .iter()
        .map(|i| hex32(&i.leg.coin))
        .collect::<Result<_>>()?;
    let mut coins = BTreeSet::new();
    let mut amounts = Vec::new();
    for outgoing in &plan.outgoing {
        let root = &outgoing.operation;
        let metadata = app.metadata(root)?;
        let Kind::Sender {
            owner, recipient, ..
        } = &metadata.kind
        else {
            anyhow::bail!("swap outgoing operation is not a sender");
        };
        let address =
            ReceivingAddress::decode(recipient, AddressNetwork::Test, &app.policy.deployment)?;
        let sender = sender_from_owner(app, root, owner, &address)?;
        ensure!(
            sender.batch() == Some(&plan.manifest),
            "swap outgoing manifest changed"
        );
        plan.manifest.index(sender.context(), true)?;
        let coin = sender.context().coin;
        ensure!(
            !incoming.contains(&coin) && coins.insert(coin),
            "swap outgoing coin duplicated or also incoming"
        );
        let owner_metadata = app.metadata(owner)?;
        let amount = match owner_metadata.kind {
            Kind::Origin { .. } => app
                .origin(owner, &owner_metadata)?
                .verified_deposit_amount(app.v()?, &root.join("verify"))?,
            Kind::Receiver { .. } => authorized_receiver(app, owner, &owner_metadata)?
                .1
                .verified_deposit_amount(app.v()?, &root.join("verify"))?,
            _ => anyhow::bail!("swap source is not an accepted owner"),
        };
        ensure!(
            amount == outgoing.amount_sat,
            "outgoing deposit amount differs from agreement"
        );
        amounts.push(amount);
    }
    ensure!(
        coins.len() + incoming.len() == plan.manifest.members.len(),
        "swap manifest contains an unapproved member"
    );
    Ok(amounts)
}

/// Verify the entire incoming set before making a recipient claim or producing
/// a readiness request for any member. Invitation identities, not just paths,
/// must be distinct (two copies of one invitation are still one invitation).
pub(super) fn check_incoming(app: &App, root: &Path, plan: &FrozenPlan) -> Result<Vec<u64>> {
    let mut invitations = BTreeSet::new();
    let mut amounts = Vec::new();
    for incoming in &plan.incoming {
        let path = &incoming.leg.operation;
        let metadata = app.metadata(path)?;
        ensure!(
            metadata.kind == expected_child(root, plan, incoming),
            "swap child parameters changed"
        );
        let (mut invitation, mut journal) = open_cli_receiver(app, path, &metadata)?;
        ensure!(
            invitations.insert(invitation.public_address()?.encode()),
            "swap reuses a one-use receiving invitation"
        );
        journal.authorize_and_reserve(&mut invitation, app.v()?, &path.join("verify"))?;
        journal.recovery_delays()?;
        let amount = journal.deposit_amount()?;
        ensure!(
            amount == incoming.leg.amount_sat,
            "incoming deposit amount differs from agreement"
        );
        amounts.push(amount);
    }
    Ok(amounts)
}

pub(super) fn prepare_requests(app: &App, plan: &FrozenPlan) -> Result<Vec<RequestPin>> {
    let mut requests = Vec::new();
    for incoming in &plan.incoming {
        let path = &incoming.leg.operation;
        let metadata = app.metadata(path)?;
        let (mut invitation, mut journal) = open_cli_receiver(app, path, &metadata)?;
        let scratch = path.join("verify");
        journal.authorize_and_reserve(&mut invitation, app.v()?, &scratch)?;
        if !journal.has_issuance_request() {
            journal.claim(&app.config.endpoint)?;
            journal.prepare_with_signer(incoming.leg.recovery_fee, &app.config.endpoint)?;
            let proof = app.prove(
                path,
                "receiver_authorization",
                "receiver-authorization",
                |p| {
                    invitation.write_receiver_authorization_witness(&journal, app.v()?, &scratch, p)
                },
            )?;
            journal.freeze_issuance_request(&proof, app.v()?, &scratch, Some(&app.config.chain))?;
        }
        let request = journal.issuance_request(app.v()?, &scratch)?;
        requests.push(RequestPin {
            operation: path.clone(),
            body_sha256: hash(&[request.body()]),
        });
    }
    Ok(requests)
}

impl Authorization {
    pub(in crate::cli) fn check_request(&self, path: &Path, body: &[u8]) -> Result<()> {
        ensure!(
            self.approval
                .requests
                .iter()
                .any(|r| r.operation == path && r.body_sha256 == hash(&[body])),
            "swap readiness differs from approved request"
        );
        Ok(())
    }
    pub(in crate::cli) fn check_live_set(&self, app: &App, current: Option<&Path>) -> Result<()> {
        for incoming in &self.plan.incoming {
            // The caller holds this journal and ready_batch checks it itself.
            if current == Some(incoming.leg.operation.as_path()) {
                continue;
            }
            let metadata = app.metadata(&incoming.leg.operation)?;
            let (_, journal) = app.receiver(&incoming.leg.operation, &metadata)?;
            journal.check_live_backing(&app.config.chain)?;
        }
        Ok(())
    }
}

pub(in crate::cli) fn require_child_authorization(
    path: &Path,
    metadata: &Metadata,
    authorization: Option<&Authorization>,
) -> Result<()> {
    if let Kind::Receiver { group, batch, .. } = &metadata.kind {
        if let Some(group) = group {
            let gate = authorization.context("swap receiver requires full-group authorization")?;
            ensure!(
                &gate.root == group && gate.approval.requests.iter().any(|r| r.operation == path),
                "swap receiver belongs to another group"
            );
        } else {
            ensure!(
                batch.as_ref().is_none_or(|b| b.members.len() == 2),
                "multi-coin receive requires a native swap-group agreement"
            );
        }
    }
    Ok(())
}
