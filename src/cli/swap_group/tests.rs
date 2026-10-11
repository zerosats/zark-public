use super::*;
use crate::cli::Cli;
use crate::cli::storage::{new_directory, write_new};
use clap::Parser;
use std::fs;
use zark_protocol::batch::Member as BatchMember;

fn plan(left: usize, right: usize) -> FrozenPlan {
    let total = 100_000 * left as u64 * right as u64;
    let outgoing = (0..left)
        .map(|i| Outgoing {
            operation: PathBuf::from(format!("/private/send-{i}")),
            amount_sat: total / left as u64,
        })
        .collect();
    let incoming = (0..right)
        .map(|i| FrozenIncoming {
            leg: Incoming {
                operation: PathBuf::from(format!("/private/receive-{i}")),
                invitation: PathBuf::from(format!("/private/invitation-{i}")),
                offer: PathBuf::from(format!("/private/offer-{i}")),
                coin: hex::encode([left as u8 + i as u8 + 1; 32]),
                transfer_operation: hex::encode([left as u8 + i as u8 + 31; 32]),
                amount_sat: total / right as u64,
                recovery_fee: 1000,
            },
            offer_sha256: "61".repeat(32),
        })
        .collect();
    FrozenPlan {
        version: 1,
        agreement_id: "ab".repeat(32),
        outgoing,
        incoming,
        manifest: BatchManifest {
            id: [90; 32],
            deployment: [91; 32],
            expires_at: 2000,
            members: (0..left + right)
                .map(|i| BatchMember {
                    coin: [i as u8 + 1; 32],
                    previous_state: [80; 32],
                    operation: [i as u8 + 31; 32],
                    recipient_claim: [70; 32],
                    sender_session: [60; 32],
                    revision: 1,
                })
                .collect(),
        },
    }
}

#[test]
fn all_twenty_five_size_combinations_compare_gross_deposits() -> Result<()> {
    for left in 1..=5 {
        for right in 1..=5 {
            let value = plan(left, right);
            validate_plan(&value)?;
            let left_amounts: Vec<_> = value.outgoing.iter().map(|o| o.amount_sat).collect();
            let right_amounts: Vec<_> = value.incoming.iter().map(|i| i.leg.amount_sat).collect();
            let total = check_totals(&left_amounts, &right_amounts)?;
            assert_eq!(total, 100_000 * left as u64 * right as u64);
            // Unequal recovery totals for asymmetric groups are not a reason
            // to reject equal deposits. Fees belong to each individual coin.
            if left != right {
                assert_ne!(total - left as u64 * 1000, total - right as u64 * 1000);
            }
            let mut wrong = right_amounts.clone();
            *wrong.last_mut().unwrap() -= 1;
            assert!(check_totals(&left_amounts, &wrong).is_err());
        }
    }
    Ok(())
}

#[test]
fn invalid_sizes_totals_duplicates_and_last_member_are_rejected() -> Result<()> {
    for (left, right) in [(0, 1), (1, 0), (6, 1), (1, 6), (6, 6)] {
        assert!(check_totals(&vec![1; left], &vec![1; right]).is_err());
    }
    assert!(check_totals(&[u64::MAX, 1], &[u64::MAX]).is_err());
    assert!(check_totals(&[0], &[0]).is_err());
    let original = plan(5, 3);
    for mutation in 0..7 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.incoming.last_mut().unwrap().leg.amount_sat -= 1,
            1 => changed.incoming.last_mut().unwrap().leg.coin = "ff".repeat(32),
            2 => changed.incoming.last_mut().unwrap().leg.transfer_operation = "ff".repeat(32),
            3 => {
                changed.incoming.last_mut().unwrap().leg.invitation =
                    changed.incoming[0].leg.invitation.clone()
            }
            4 => {
                changed.incoming.last_mut().unwrap().leg.operation =
                    changed.outgoing[0].operation.clone()
            }
            5 => {
                changed.manifest.members.pop();
            }
            _ => changed.incoming.last_mut().unwrap().leg.recovery_fee = 0,
        }
        assert!(validate_plan(&changed).is_err(), "mutation {mutation}");
    }
    Ok(())
}

#[test]
fn approval_pins_full_set_and_cannot_be_bypassed_by_child_resume() -> Result<()> {
    let original = plan(1, 3);
    let root = PathBuf::from("/private/group");
    let request_bytes = [vec![1u8], vec![2], vec![3]];
    let approval = Approval {
        plan_sha256: hash(&[&serde_json::to_vec(&original)?]),
        requests: original
            .incoming
            .iter()
            .zip(&request_bytes)
            .map(|(i, b)| RequestPin {
                operation: i.leg.operation.clone(),
                body_sha256: hash(&[b]),
            })
            .collect(),
    };
    let encoded = serde_json::to_vec(&approval)?;
    let recovered: Approval = serde_json::from_slice(&encoded)?;
    assert!(approval == recovered);
    let gate = Authorization {
        root: root.clone(),
        plan: original.clone(),
        approval: recovered,
    };
    for (i, bytes) in original.incoming.iter().zip(&request_bytes) {
        let metadata = Metadata {
            version: 10,
            deployment: hex::encode(original.manifest.deployment),
            manifest_sha256: "00".repeat(32),
            kind: expected_child(&root, &original, i),
        };
        assert!(require_child_authorization(&i.leg.operation, &metadata, None).is_err());
        require_child_authorization(&i.leg.operation, &metadata, Some(&gate))?;
        gate.check_request(&i.leg.operation, bytes)?;
        assert!(
            gate.check_request(&i.leg.operation, b"replacement request")
                .is_err()
        );
        let mut without_group = metadata.clone();
        if let Kind::Receiver { group, .. } = &mut without_group.kind {
            *group = None;
        }
        assert!(require_child_authorization(&i.leg.operation, &without_group, None).is_err());
    }
    let mut substituted = original;
    substituted.incoming.last_mut().unwrap().leg.amount_sat += 1;
    assert_ne!(
        gate.approval.plan_sha256,
        hash(&[&serde_json::to_vec(&substituted)?])
    );
    Ok(())
}

#[test]
fn generalized_cli_contract_is_distinct_from_legacy_pair_flags() -> Result<()> {
    let base = [
        "zark-wallet",
        "--config",
        "wallet.json",
        "batch-manifest",
        "--expires-at",
        "1000",
        "--output",
        "manifest.json",
    ];
    assert!(
        Cli::try_parse_from(base.into_iter().chain([
            "--draft",
            "one",
            "--draft",
            "two",
            "--peer-drafts",
            "peers.json"
        ]))
        .is_ok()
    );
    assert!(Cli::try_parse_from(base.into_iter().chain(["--draft", "one"])).is_err());
    assert!(
        Cli::try_parse_from(base.into_iter().chain([
            "--first",
            "one",
            "--peer-drafts",
            "peers.json"
        ]))
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "zark-wallet",
            "--config",
            "wallet.json",
            "swap-group",
            "--operation",
            "group",
            "--plan",
            "plan.json"
        ])
        .is_ok()
    );
    Ok(())
}

#[test]
fn maximum_pretty_manifest_roundtrips_through_bounded_reader() -> Result<()> {
    let home = std::env::temp_dir().join(format!(
        "zark-swap-manifest-{}",
        hex::encode(zark_protocol::random32())
    ));
    new_directory(&home)?;
    let path = home.join("manifest.json");
    let manifest = plan(5, 5).manifest;
    let encoded = serde_json::to_vec_pretty(&manifest)?;
    assert!(encoded.len() < 65_536);
    write_new(&path, &encoded)?;
    assert!(read_batch_manifest(&path)? == manifest);
    fs::remove_dir_all(home)?;
    Ok(())
}

#[test]
fn failed_first_recovery_does_not_skip_later_members() -> Result<()> {
    let mut attempted = Vec::new();
    let mut saved = Vec::new();
    let outcomes = attempt_every(&[0, 1, 2, 3, 4], |member| {
        attempted.push(*member);
        ensure!(*member != 0, "first member's backing/head unavailable");
        saved.push(*member);
        Ok(())
    });
    assert_eq!(attempted, vec![0, 1, 2, 3, 4]);
    assert_eq!(saved, vec![1, 2, 3, 4]);
    assert!(outcomes[0].is_err() && outcomes[1..].iter().all(Result::is_ok));
    Ok(())
}

#[test]
fn partial_completion_cannot_unlock_received_coins() -> Result<()> {
    let plan = plan(1, 3);
    let mut result = json!({"completed":true,
        "incoming":plan.incoming.iter().map(|i|json!({"operation":i.leg.operation,"coin":i.leg.coin,"accepted":true,"recovery_saved":true})).collect::<Vec<_>>(),
        "outgoing":plan.outgoing.iter().map(|o|json!({"operation":o.operation,"completed":true})).collect::<Vec<_>>()});
    check_complete_result(&result, &plan)?;
    result["incoming"][2]["accepted"] = json!(false);
    assert!(check_complete_result(&result, &plan).is_err());
    result["incoming"][2]["accepted"] = json!(true);
    result["outgoing"][0]["completed"] = json!(false);
    assert!(check_complete_result(&result, &plan).is_err());
    // Peer acknowledgement affects overall completion, not the owner's
    // ability to spend after its entire received set is safe locally.
    check_local_ready_result(&result, &plan)?;
    result["completed"] = json!(false);
    check_local_ready_result(&result, &plan)?;
    Ok(())
}
