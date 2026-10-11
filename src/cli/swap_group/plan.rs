//! Freeze complete, equal-value swap plans and their child metadata.
use super::{
    App, BTreeSet, Context, FrozenIncoming, FrozenPlan, Kind, MAX_PLAN_BYTES, MAX_SIDE, Path,
    PlanInput, Result, absolute, ensure, hash, hex32, read_batch_manifest, read_bounded,
    read_private, write_exact,
};

pub(super) fn sum_amounts(amounts: impl IntoIterator<Item = u64>) -> Result<u64> {
    amounts.into_iter().try_fold(0u64, |total, amount| {
        ensure!(amount > 0, "swap coin amount must be positive");
        total.checked_add(amount).context("swap total overflow")
    })
}

pub(super) fn check_totals(outgoing: &[u64], incoming: &[u64]) -> Result<u64> {
    ensure!(
        (1..=MAX_SIDE).contains(&outgoing.len()) && (1..=MAX_SIDE).contains(&incoming.len()),
        "swap requires one to five coins on each side"
    );
    let total = sum_amounts(outgoing.iter().copied())?;
    ensure!(
        total == sum_amounts(incoming.iter().copied())?,
        "swap deposit totals differ"
    );
    Ok(total)
}

pub(super) fn validate_plan(plan: &FrozenPlan) -> Result<()> {
    ensure!(
        plan.version == 1 && hex32(&plan.agreement_id)? != [0; 32],
        "invalid swap agreement version or identity"
    );
    plan.manifest.validate()?;
    check_totals(
        &plan
            .outgoing
            .iter()
            .map(|leg| leg.amount_sat)
            .collect::<Vec<_>>(),
        &plan
            .incoming
            .iter()
            .map(|leg| leg.leg.amount_sat)
            .collect::<Vec<_>>(),
    )?;
    ensure!(
        plan.outgoing.len() + plan.incoming.len() == plan.manifest.members.len(),
        "swap agreement must account for every manifest member"
    );
    let mut paths = BTreeSet::new();
    let mut invitations = BTreeSet::new();
    let mut incoming_coins = BTreeSet::new();
    for outgoing in &plan.outgoing {
        ensure!(
            outgoing.operation.is_absolute() && paths.insert(&outgoing.operation),
            "duplicate or relative swap operation"
        );
    }
    for incoming in &plan.incoming {
        let leg = &incoming.leg;
        ensure!(
            leg.operation.is_absolute() && paths.insert(&leg.operation),
            "duplicate or relative swap operation"
        );
        ensure!(
            leg.invitation.is_absolute() && invitations.insert(&leg.invitation),
            "duplicate or relative swap invitation"
        );
        ensure!(leg.offer.is_absolute(), "relative swap offer");
        ensure!(
            leg.recovery_fee > 0 && leg.recovery_fee <= 10_000,
            "invalid swap recovery fee"
        );
        let coin = hex32(&leg.coin)?;
        ensure!(incoming_coins.insert(coin), "duplicate incoming coin");
        let operation = hex32(&leg.transfer_operation)?;
        hex32(&incoming.offer_sha256)?;
        ensure!(
            plan.manifest
                .members
                .iter()
                .any(|m| m.coin == coin && m.operation == operation),
            "incoming coin absent from swap manifest"
        );
    }
    Ok(())
}

pub(in crate::cli) fn initialize(app: &App, root: &Path, input: &Path) -> Result<()> {
    let mut input: PlanInput = serde_json::from_slice(&read_private(input, MAX_PLAN_BYTES)?)
        .map_err(|_| anyhow::anyhow!("invalid private swap plan"))?;
    for outgoing in &mut input.outgoing {
        outgoing.operation = absolute(&outgoing.operation)?;
    }
    let mut incoming = Vec::new();
    for mut leg in input.incoming {
        leg.operation = absolute(&leg.operation)?;
        leg.invitation = absolute(&leg.invitation)?;
        leg.offer = absolute(&leg.offer)?;
        let bytes = read_bounded(&leg.offer, crate::envelope::MAX_ENVELOPE_BYTES)?;
        incoming.push(FrozenIncoming {
            leg,
            offer_sha256: hex::encode(hash(&[&bytes])),
        });
    }
    let plan = FrozenPlan {
        version: input.version,
        agreement_id: input.agreement_id,
        manifest: read_batch_manifest(&input.manifest)?,
        outgoing: input.outgoing,
        incoming,
    };
    validate_plan(&plan)?;
    ensure!(
        plan.manifest.deployment == app.policy.deployment,
        "swap deployment mismatch"
    );
    ensure!(
        plan.outgoing.iter().all(|o| o.operation != root)
            && plan.incoming.iter().all(|i| i.leg.operation != root),
        "swap group cannot be its own child"
    );
    app.initialize(
        root,
        Kind::SwapGroup {
            plan: Box::new(plan),
        },
    )?;
    Ok(())
}

pub(super) fn expected_child(root: &Path, plan: &FrozenPlan, incoming: &FrozenIncoming) -> Kind {
    Kind::Receiver {
        invitation: incoming.leg.invitation.clone(),
        coin: incoming.leg.coin.clone(),
        transfer_operation: incoming.leg.transfer_operation.clone(),
        offer_sha256: incoming.offer_sha256.clone(),
        recovery_fee: incoming.leg.recovery_fee,
        batch: Some(Box::new(plan.manifest.clone())),
        expected_amount: Some(incoming.leg.amount_sat),
        group: Some(root.to_path_buf()),
    }
}

pub(super) fn initialize_children(app: &App, root: &Path, plan: &FrozenPlan) -> Result<()> {
    for incoming in &plan.incoming {
        app.initialize(
            &incoming.leg.operation,
            expected_child(root, plan, incoming),
        )?;
        let target = incoming.leg.operation.join("encrypted-offer.bin");
        if !target.try_exists()? {
            let bytes = read_bounded(&incoming.leg.offer, crate::envelope::MAX_ENVELOPE_BYTES)?;
            ensure!(
                hash(&[&bytes]) == hex32(&incoming.offer_sha256)?,
                "swap incoming offer changed"
            );
            write_exact(&target, &bytes)?;
        }
    }
    Ok(())
}
