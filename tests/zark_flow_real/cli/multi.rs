//! Fresh asymmetric/maximum group qualification using only the real CLI, TLS
//! signer, pinned proofs and the isolated test node. Never uses live profiles.
use super::*;

struct Coin {
    owner: PathBuf,
    coin: String,
    amount: u64,
}
struct Leg {
    sender: PathBuf,
    receiver: PathBuf,
    invitation: PathBuf,
    offer: PathBuf,
    draft: Value,
    amount: u64,
}

fn deposit(
    client: &mut WalletCli,
    node: &Regtest,
    directory: &Path,
    index: usize,
    amount: u64,
) -> Result<Coin> {
    let owner = directory.join(format!("multi-origin-{index}"));
    let allocated = client.ok(
        "multi-create",
        &args(&[
            word("origin-create"),
            word("--operation"),
            owner.as_os_str(),
            word("--amount"),
            word(&amount.to_string()),
        ]),
    )?;
    let pending = client.ok(
        "multi-origin-status",
        &args(&[word("status"), word("--operation"), owner.as_os_str()]),
    )?;
    let coin = text_field(&pending, "coin")?.to_owned();
    let address = Address::from_str(text_field(&allocated, "funding_address")?)?
        .require_network(Network::Regtest)?;
    let (transaction, vout) = node.signed_funding(&address.script_pubkey(), amount)?;
    let path = directory.join(format!("multi-deposit-{index}.hex"));
    write_private(
        &path,
        hex::encode(bitcoin::consensus::serialize(&transaction)).as_bytes(),
    )?;
    client.ok(
        "multi-bind",
        &args(&[
            word("origin-bind"),
            word("--operation"),
            owner.as_os_str(),
            word("--transaction"),
            path.as_os_str(),
            word("--vout"),
            word(&vout.to_string()),
        ]),
    )?;
    client.ok(
        "multi-prepare",
        &args(&[word("advance"), word("--operation"), owner.as_os_str()]),
    )?;
    let receipt = deposit_receipt(&owner)?;
    client.ok(
        "multi-origin-resume",
        &args(&[word("advance"), word("--operation"), owner.as_os_str()]),
    )?;
    ensure!(
        deposit_receipt(&owner)? == receipt,
        "deposit resume generated another proof attempt"
    );
    client.ok(
        "multi-broadcast",
        &args(&[
            word("advance"),
            word("--operation"),
            owner.as_os_str(),
            word("--broadcast"),
        ]),
    )?;
    node.mine(1)?;
    Ok(Coin {
        owner,
        coin,
        amount,
    })
}

fn draft(
    sender: &mut WalletCli,
    recipient: &mut WalletCli,
    run: &Path,
    coin: &Coin,
    index: usize,
) -> Result<Leg> {
    let invitation = run
        .join(recipient.actor)
        .join(format!("multi-invitation-{index}"));
    let address = recipient.ok(
        "multi-address",
        &args(&[
            word("new-address"),
            word("--directory"),
            invitation.as_os_str(),
        ]),
    )?;
    let sender_path = run.join(sender.actor).join(format!("multi-send-{index}"));
    let receiver = run
        .join(recipient.actor)
        .join(format!("multi-receive-{index}"));
    let offer = run.join(format!("multi-{}-offer-{index}.json", sender.actor));
    let draft = sender.ok(
        "multi-draft",
        &args(&[
            word("batch-draft"),
            word("--owner"),
            coin.owner.as_os_str(),
            word("--operation"),
            sender_path.as_os_str(),
            word("--to"),
            word(text_field(&address, "address")?),
            word("--output"),
            offer.as_os_str(),
        ]),
    )?;
    ensure!(draft["coin"] == coin.coin, "draft changed source coin");
    Ok(Leg {
        sender: sender_path,
        receiver,
        invitation,
        offer,
        draft,
        amount: coin.amount,
    })
}

fn public_draft(leg: &Leg) -> Value {
    json!({"context":leg.draft["context"],"coin":leg.draft["coin"],"revision":leg.draft["revision"]})
}
fn incoming(leg: &Leg) -> Result<Value> {
    let context = zark_protocol::handoff::TransferContext::decode(&hex::decode(text_field(
        &leg.draft, "context",
    )?)?)?;
    Ok(
        json!({"operation":leg.receiver,"invitation":leg.invitation,"offer":leg.offer,
        "coin":leg.draft["coin"],"transfer_operation":hex::encode(context.operation),"amount_sat":leg.amount,"recovery_fee":1000}),
    )
}
fn plan(manifest: &Path, agreement: &str, outgoing: &[Leg], received: &[Leg]) -> Result<Value> {
    Ok(
        json!({"version":1,"agreement_id":agreement,"manifest":manifest,
        "outgoing":outgoing.iter().map(|l|json!({"operation":l.sender,"amount_sat":l.amount})).collect::<Vec<_>>(),
        "incoming":received.iter().map(incoming).collect::<Result<Vec<_>>>()?}),
    )
}
fn group(client: &mut WalletCli, operation: &Path, plan: &Path) -> Result<Value> {
    client.ok(
        "multi-group",
        &args(&[
            word("swap-group"),
            word("--operation"),
            operation.as_os_str(),
            word("--plan"),
            plan.as_os_str(),
        ]),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "isolated real-flow fixture ownership is explicit"
)]
pub(super) fn run(
    run: &Path,
    node: &Regtest,
    signer: &mut SignerProcess,
    alice: &mut WalletCli,
    bob: &mut WalletCli,
    first_owner: &Path,
    first_coin: &str,
    left: usize,
    right: usize,
    wrong_last_amount: bool,
) -> Result<()> {
    ensure!(
        (1..=5).contains(&left) && (1..=5).contains(&right),
        "multi qualification sizes"
    );
    let started = Instant::now();
    let mut acoins = vec![Coin {
        owner: first_owner.to_path_buf(),
        coin: first_coin.to_owned(),
        amount: 100_000,
    }];
    for index in 1..left {
        acoins.push(deposit(alice, node, &run.join("alice"), index, 100_000)?);
    }
    let total = left as u64 * 100_000;
    let mut bcoins = Vec::new();
    for index in 0..right {
        let amount = total / right as u64
            + if index == right - 1 {
                total % right as u64
            } else {
                0
            }
            - if wrong_last_amount && index == right - 1 {
                1
            } else {
                0
            };
        bcoins.push(deposit(bob, node, &run.join("bob"), index, amount)?);
    }
    let mut alegs = Vec::new();
    let mut blegs = Vec::new();
    for (index, coin) in acoins.iter().enumerate() {
        alegs.push(draft(alice, bob, run, coin, index)?);
    }
    for (index, coin) in bcoins.iter().enumerate() {
        blegs.push(draft(bob, alice, run, coin, index)?);
    }
    let peers = run.join("multi-peer-drafts.json");
    write_private(
        &peers,
        &serde_json::to_vec(&blegs.iter().map(public_draft).collect::<Vec<_>>())?,
    )?;
    let manifest = run.join("multi-batch.json");
    let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 23 * 60 * 60;
    let mut command = args(&[
        word("batch-manifest"),
        word("--peer-drafts"),
        peers.as_os_str(),
        word("--expires-at"),
        word(&deadline.to_string()),
        word("--output"),
        manifest.as_os_str(),
    ]);
    for leg in &alegs {
        command.extend(args(&[word("--draft"), leg.sender.as_os_str()]));
    }
    let frozen = alice.ok("multi-manifest", &command)?;
    ensure!(
        frozen["members"].as_array().context("batch members")?.len() == left + right,
        "manifest member count"
    );
    ensure!(
        alice.ok("multi-manifest-exact-retry", &command)? == frozen,
        "manifest retry changed"
    );
    for (client, legs) in [(&mut *alice, &alegs), (&mut *bob, &blegs)] {
        for leg in legs {
            let joined = client.ok(
                "multi-join",
                &args(&[
                    word("batch-send"),
                    word("--operation"),
                    leg.sender.as_os_str(),
                    word("--manifest"),
                    manifest.as_os_str(),
                ]),
            )?;
            ensure!(joined["phase"] == "joined", "multi member did not join");
        }
    }
    for (client, legs) in [(&mut *alice, &alegs), (&mut *bob, &blegs)] {
        for leg in legs {
            client.ok(
                "multi-handover",
                &args(&[word("advance"), word("--operation"), leg.sender.as_os_str()]),
            )?;
            require_proof_jobs(&leg.sender, &["sender_from_origin"])?;
        }
    }
    let agreement = hex::encode(random32());
    let aplan = run.join("alice/multi-plan.json");
    let bplan = run.join("bob/multi-plan.json");
    let mut aplan_value = plan(&manifest, &agreement, &alegs, &blegs)?;
    if wrong_last_amount {
        // Declared totals agree exactly; only native validation of the final
        // decrypted coin reveals the peer is one sat short.
        aplan_value["incoming"][right - 1]["amount_sat"] = json!(blegs[right - 1].amount + 1);
    }
    let bplan_value = plan(&manifest, &agreement, &blegs, &alegs)?;
    write_private(&aplan, &serde_json::to_vec(&aplan_value)?)?;
    write_private(&bplan, &serde_json::to_vec(&bplan_value)?)?;
    let agroup = run.join("alice/multi-group");
    let bgroup = run.join("bob/multi-group");

    if wrong_last_amount {
        alice.execute(
            "multi-wrong-final-amount",
            &args(&[
                word("swap-group"),
                word("--operation"),
                agroup.as_os_str(),
                word("--plan"),
                aplan.as_os_str(),
            ]),
            false,
        )?;
        ensure!(
            !agroup.join("approved.json").exists(),
            "wrong last amount authorized readiness"
        );
        for leg in &blegs[..right - 1] {
            let status = alice.ok(
                "multi-wrong-amount-no-earlier-ready",
                &args(&[
                    word("status"),
                    word("--operation"),
                    leg.receiver.as_os_str(),
                ]),
            )?;
            ensure!(
                status["phase"] == "Authorized",
                "wrong last amount advanced another member past verification"
            );
            ensure!(
                !leg.receiver
                    .join("proofs/receiver-authorization-job/completed.json")
                    .exists(),
                "wrong aggregate produced a readiness proof"
            );
        }
        for (client, legs) in [(&mut *alice, &alegs), (&mut *bob, &blegs)] {
            for leg in legs {
                client.ok(
                    "multi-abort-after-wrong-amount",
                    &args(&[
                        word("batch-abort"),
                        word("--operation"),
                        leg.sender.as_os_str(),
                    ]),
                )?;
            }
        }
        write_private(
            &run.join("multi-qualification.json"),
            &serde_json::to_vec_pretty(
                &json!({"wrong_last_amount_rejected":true,"no_readiness_released":true,"aborted":true}),
            )?,
        )?;
        return Ok(());
    }

    // Make the final incoming envelope invalid. Earlier members may be
    // locally verified, but none may release readiness or generate issuance.
    let bad_plan = run.join("alice/multi-invalid-plan.json");
    let bad_group = run.join("alice/multi-invalid-group");
    let bad_offer = run.join("multi-invalid-last-offer.json");
    let last = blegs.last().context("incoming legs")?;
    let mut corrupt = fs::read(&last.offer)?;
    let offset = corrupt.len() / 2;
    corrupt[offset] ^= 1;
    write_private(&bad_offer, &corrupt)?;
    let mut bad_value = aplan_value.clone();
    let incoming = bad_value["incoming"]
        .as_array_mut()
        .context("incoming plan")?;
    for (index, leg) in incoming.iter_mut().enumerate() {
        leg["operation"] = json!(
            run.join("alice")
                .join(format!("multi-invalid-receive-{index}"))
        );
    }
    incoming.last_mut().unwrap()["offer"] = json!(bad_offer);
    write_private(&bad_plan, &serde_json::to_vec(&bad_value)?)?;
    alice.execute(
        "multi-corrupt-last-rejected",
        &args(&[
            word("swap-group"),
            word("--operation"),
            bad_group.as_os_str(),
            word("--plan"),
            bad_plan.as_os_str(),
        ]),
        false,
    )?;
    ensure!(
        !bad_group.join("approved.json").exists(),
        "invalid last member authorized group"
    );
    for index in 0..right - 1 {
        let operation = run
            .join("alice")
            .join(format!("multi-invalid-receive-{index}"));
        let status = alice.ok(
            "multi-no-partial-readiness",
            &args(&[word("status"), word("--operation"), operation.as_os_str()]),
        )?;
        ensure!(
            status["phase"] == "Authorized",
            "invalid batch advanced a valid member past verification"
        );
    }

    let pending = group(bob, &bgroup, &bplan)?;
    ensure!(
        pending["completed"] == false
            && pending["incoming"]
                .as_array()
                .context("incoming progress")?
                .iter()
                .all(|v| v["accepted"] == false),
        "first group issued without peer"
    );
    signer.restart()?;
    // Direct resume of a prepared child must route through the same full group.
    let child_resume = bob.ok(
        "multi-child-resume-gated",
        &args(&[
            word("advance"),
            word("--operation"),
            alegs[0].receiver.as_os_str(),
        ]),
    )?;
    ensure!(
        child_resume["operation"] == bgroup.to_string_lossy().as_ref(),
        "child bypassed group resume"
    );
    group(alice, &agroup, &aplan)?;
    signer.restart()?;
    for _ in 0..3 {
        let a = group(alice, &agroup, &aplan)?;
        let b = group(bob, &bgroup, &bplan)?;
        if a["completed"] == true && b["completed"] == true {
            break;
        }
    }
    for (client, group_path, plan_path, received, sent) in [
        (&mut *alice, &agroup, &aplan, &blegs, &alegs),
        (&mut *bob, &bgroup, &bplan, &alegs, &blegs),
    ] {
        let completed = group(client, group_path, plan_path)?;
        ensure!(
            completed["completed"] == true,
            "full group did not complete"
        );
        ensure!(
            completed["incoming"].as_array().context("incoming")?.len() == received.len()
                && completed["outgoing"].as_array().context("outgoing")?.len() == sent.len(),
            "completion omitted members"
        );
        for leg in received {
            require_proof_jobs(&leg.receiver, &["receiver_authorization"])?;
        }
    }
    // A real direct cooperative exit establishes spendable received ownership.
    let destination = node.rpc(
        Some("flow-funding"),
        "getnewaddress",
        &["multi-exit".into(), "bech32m".into()],
    )?;
    let exit = run.join("alice/multi-exit");
    alice.ok(
        "multi-exit-prepare",
        &args(&[
            word("exit"),
            word("--owner"),
            blegs[0].receiver.as_os_str(),
            word("--operation"),
            exit.as_os_str(),
            word("--to"),
            word(destination.as_str().context("exit address")?),
            word("--fee"),
            word("1000"),
        ]),
    )?;
    let published = alice.ok(
        "multi-exit-broadcast",
        &args(&[
            word("advance"),
            word("--operation"),
            exit.as_os_str(),
            word("--broadcast"),
        ]),
    )?;
    ensure!(
        published["activation_broadcast"] == false,
        "group exit published activation"
    );
    node.mine(1)?;
    let confirmed = alice.ok(
        "multi-exit-confirmed",
        &args(&[
            word("advance"),
            word("--operation"),
            exit.as_os_str(),
            word("--broadcast"),
        ]),
    )?;
    ensure!(
        confirmed["waiting"] == false && confirmed["amount_received_sat"] == blegs[0].amount - 1000,
        "group exit amount or confirmation"
    );
    let report = json!({"left":left,"right":right,"total_sat":total,"fresh_transfer_proofs":2*(left+right),
        "completed":true,"signer_restart":true,"corrupt_last_offer_rejected_before_ready":true,"withdrawal":confirmed,
        "elapsed_ms":started.elapsed().as_millis(),"commands":{"alice":alice.commands,"bob":bob.commands}});
    write_private(
        &run.join("multi-qualification.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    eprintln!(
        "multi-group: {} for {} passed; report {}",
        left,
        right,
        run.join("multi-qualification.json").display()
    );
    Ok(())
}
