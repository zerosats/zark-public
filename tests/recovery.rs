//! Synthetic native transactions only. Server secrets exist only in this test
//! fixture builder; the receiver API never accepts them. No node/wallet access.
use bitcoin::{
    Txid,
    consensus::serialize,
    hashes::Hash,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
};
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
};
use zark_protocol::{
    handoff::{
        RecoveryDelay, SigningBinding, TransferContext, capability_commitment,
        origin_previous_capability, origin_previous_state, origin_refresh_commitment,
    },
    point_bytes, random32, scalar,
};
use zark_wallet::{
    bitcoin::{attach_signature, p2tr},
    recovery::{OriginRecoveryParameters, RecoveryDraft, RecoveryParameters},
    recovery_export::PortableRecovery,
};

#[path = "recovery/fixtures.rs"]
mod fixtures;
use fixtures::{
    Home, export_fixture, fixture, native_fixture_value, parity_fixtures, server_contribution,
};

fn origin_parameters(mut parameters: RecoveryParameters) -> OriginRecoveryParameters {
    parameters.context.start_revision = 0;
    parameters.context.previous_state =
        origin_previous_state(&parameters.context.deployment, &parameters.context.coin).unwrap();
    let initial_capability = capability_commitment(
        &parameters.context.deployment,
        &parameters.context.coin,
        &k256::schnorr::SigningKey::from_bytes(&[44; 32])
            .unwrap()
            .to_bytes()
            .into(),
    )
    .unwrap();
    OriginRecoveryParameters {
        context: parameters.context,
        backing: parameters.backing,
        activation_input: parameters.activation_input,
        activation: parameters.activation,
        draft_server: parameters.draft_server,
        initial_capability,
        schedule: parameters.schedule,
        fee: parameters.fee,
    }
}

#[test]
fn initial_recovery_uses_origin_binding_and_survives_restart_and_portable_export() {
    let home = Home::new();
    let f = fixture();
    let parameters = origin_parameters(f.parameters);
    let context = parameters.context.clone();
    let initial = parameters.schedule.initial;
    let initial_capability = parameters.initial_capability;
    let rs = point_bytes(ProjectivePoint::GENERATOR * f.server_nonce).unwrap();
    let draft =
        RecoveryDraft::create_origin(&home.draft(), parameters, &f.user, &f.payout).unwrap();
    let commitments = draft.commitments().unwrap();
    let path = home.draft().join("recovery-draft.json");
    let record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(record["version"], json!(4));
    assert_eq!(record["mode"], json!({"kind":"origin"}));
    assert!(record.get("previous_delay").is_none());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(draft);

    let mut draft = RecoveryDraft::open(&home.draft(), &context).unwrap();
    assert_eq!(draft.commitments().unwrap(), commitments);
    let binding = draft.bind_server_nonce(&context, rs).unwrap();
    assert_eq!(
        binding.context.previous_state,
        origin_previous_state(&context.deployment, &context.coin).unwrap()
    );
    assert_eq!(
        binding.previous_capability,
        origin_previous_capability(&context.deployment, &context.coin).unwrap()
    );
    assert_eq!(binding.next_capability, initial_capability);
    assert_eq!(
        binding.refresh_commitment,
        origin_refresh_commitment(&context, &commitments.funding, &binding.draft_server).unwrap()
    );
    let partial = server_contribution(&binding, f.server, f.server_nonce);
    drop(draft);

    let mut draft = RecoveryDraft::open(&home.draft(), &context).unwrap();
    assert_eq!(
        draft
            .bind_server_nonce(&context, rs)
            .unwrap()
            .encode()
            .unwrap(),
        binding.encode().unwrap()
    );
    let tx = draft.finish(&context, rs, partial).unwrap();
    assert_eq!(tx.input[0].sequence.to_consensus_u32(), initial);
    assert_eq!(tx.output[0].value.to_sat(), 98_000);
    assert_eq!(tx.input[0].witness.iter().next().unwrap().len(), 64);
    drop(draft);

    let draft = RecoveryDraft::open(&home.draft(), &context).unwrap();
    assert_eq!(
        serialize(&draft.completed_transaction().unwrap()),
        serialize(&tx)
    );
    let archive = home.0.join("origin-recovery.json");
    draft.export_portable(&archive).unwrap();
    drop(draft);
    fs::remove_dir_all(home.draft()).unwrap();
    let portable = PortableRecovery::read(&archive, &context.deployment, &context.coin).unwrap();
    assert_eq!(portable.relative_blocks(), initial);
    assert_eq!(
        serialize(&portable.transactions().unwrap()[1]),
        serialize(&tx)
    );
    let destination = SigningKey::from_bytes(&Scalar::from(47u64).to_bytes()).unwrap();
    let spend = portable
        .sign_payout_spend(destination.verifying_key().to_bytes().into(), 1000)
        .unwrap();
    assert_eq!(spend.input[0].previous_output.txid, tx.compute_txid());
    assert_eq!(spend.output[0].value.to_sat(), 97_000);
}

#[test]
fn bootstrap_origin_completes_own_recovery_before_parent_attachment_or_export() {
    let home = Home::new();
    let f = fixture();
    let mut p = origin_parameters(f.parameters);
    let completed_activation = p.activation.clone();
    p.activation.input[0].witness.clear();
    let context = p.context.clone();
    let mut draft =
        RecoveryDraft::create_bootstrap_origin(&home.draft(), p, &f.user, &f.payout).unwrap();
    assert!(
        draft
            .attach_completed_activation(&completed_activation)
            .is_err()
    );
    assert!(draft.completed_activation().is_err());
    let archive = home.0.join("pending-recovery.json");
    assert!(draft.export_portable(&archive).is_err());
    assert!(!archive.exists());
    let rs = point_bytes(ProjectivePoint::GENERATOR * f.server_nonce).unwrap();
    let binding = draft.bind_server_nonce(&context, rs).unwrap();
    let partial = server_contribution(&binding, f.server, f.server_nonce);
    drop(draft);
    let mut draft = RecoveryDraft::open(&home.draft(), &context).unwrap();
    let recovery = draft.finish(&context, rs, partial).unwrap();
    assert_eq!(recovery.input[0].sequence.to_consensus_u32(), 480);
    assert!(draft.export_portable(&archive).is_err());
    let mut altered = completed_activation.clone();
    altered.output[0].value = bitcoin::Amount::from_sat(98_999);
    assert!(draft.attach_completed_activation(&altered).is_err());
    draft
        .attach_completed_activation(&completed_activation)
        .unwrap();
    draft
        .attach_completed_activation(&completed_activation)
        .unwrap();
    assert_eq!(
        draft.signing_binding().unwrap().encode().unwrap(),
        binding.encode().unwrap()
    );
    assert!(draft.attach_completed_activation(&altered).is_err());
    draft.export_portable(&archive).unwrap();
    drop(draft);
    let reopened = RecoveryDraft::open(&home.draft(), &context).unwrap();
    assert_eq!(
        serialize(&reopened.completed_activation().unwrap()),
        serialize(&completed_activation)
    );
    assert_eq!(
        serialize(&reopened.completed_transaction().unwrap()),
        serialize(&recovery)
    );
    PortableRecovery::read(&archive, &context.deployment, &context.coin).unwrap();
}

#[test]
fn bootstrap_unsigned_mode_does_not_relax_regular_origins_and_rejects_reinterpretation() {
    for regular in [false, true] {
        let home = Home::new();
        let f = fixture();
        let mut p = origin_parameters(f.parameters);
        if regular {
            p.activation.input[0].witness.clear();
        }
        let result = if regular {
            RecoveryDraft::create_origin(&home.draft(), p, &f.user, &f.payout)
        } else {
            RecoveryDraft::create_bootstrap_origin(&home.draft(), p, &f.user, &f.payout)
        };
        assert!(result.is_err());
        assert!(!home.draft().exists());
    }
    let home = Home::new();
    let f = fixture();
    let mut p = origin_parameters(f.parameters);
    p.activation.input[0].witness.clear();
    let context = p.context.clone();
    drop(RecoveryDraft::create_bootstrap_origin(&home.draft(), p, &f.user, &f.payout).unwrap());
    let file = home.draft().join("recovery-draft.json");
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    for mode in [
        json!({"kind":"origin"}),
        json!({"kind":"bootstrap_origin_attached"}),
        json!({"kind":"bootstrap_origin_pending","skip_check":true}),
    ] {
        let mut changed = original.clone();
        changed["mode"] = mode;
        fs::write(&file, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(RecoveryDraft::open(&home.draft(), &context).is_err());
    }
}

#[test]
fn frozen_signing_binding_rejects_salt_or_commitment_edits_even_when_transaction_is_unchanged() {
    for completed in [false, true] {
        let home = Home::new();
        let f = fixture();
        let context = f.parameters.context.clone();
        let mut draft =
            RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).unwrap();
        let rs = point_bytes(ProjectivePoint::GENERATOR * f.server_nonce).unwrap();
        let binding = draft.bind_server_nonce(&context, rs).unwrap();
        if completed {
            draft
                .finish(
                    &context,
                    rs,
                    server_contribution(&binding, f.server, f.server_nonce),
                )
                .unwrap();
        }
        drop(draft);
        let file = home.draft().join("recovery-draft.json");
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        for name in [
            "nonce_salt",
            "backup_salt",
            "refresh_commitment",
            "previous_capability",
            "next_capability",
        ] {
            let mut changed = original.clone();
            changed[name] = json!(vec![49; 32]);
            fs::write(&file, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(
                RecoveryDraft::open(&home.draft(), &context).is_err(),
                "{completed} {name}"
            );
        }
        fs::write(&file, serde_json::to_vec(&original).unwrap()).unwrap();
        RecoveryDraft::open(&home.draft(), &context).unwrap();
    }
}

#[test]
fn invalid_origin_context_capability_or_policy_is_rejected_before_storage() {
    for case in 0..6 {
        let home = Home::new();
        let f = fixture();
        let mut parameters = origin_parameters(f.parameters);
        match case {
            0 => parameters.context.previous_state = [7; 32],
            1 => parameters.context.coin[0] ^= 1,
            2 => parameters.initial_capability = [0; 32],
            3 => {
                parameters.initial_capability = origin_previous_capability(
                    &parameters.context.deployment,
                    &parameters.context.coin,
                )
                .unwrap()
            }
            4 => parameters.schedule.initial = 120,
            5 => {
                parameters.draft_server =
                    point_bytes(ProjectivePoint::GENERATOR * Scalar::from(24u64)).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            RecoveryDraft::create_origin(&home.draft(), parameters, &f.user, &f.payout).is_err(),
            "origin case {case}"
        );
        assert!(!home.draft().exists());
    }
}

#[test]
fn transfer_creation_rejects_each_origin_sentinel_and_preserves_exact_decrement() {
    for case in 0..4 {
        let home = Home::new();
        let mut f = fixture();
        match case {
            0 => {
                f.parameters.context.previous_state = origin_previous_state(
                    &f.parameters.context.deployment,
                    &f.parameters.context.coin,
                )
                .unwrap()
            }
            1 => {
                f.parameters.previous_capability = origin_previous_capability(
                    &f.parameters.context.deployment,
                    &f.parameters.context.coin,
                )
                .unwrap()
            }
            2 => {
                f.parameters.next_capability = origin_previous_capability(
                    &f.parameters.context.deployment,
                    &f.parameters.context.coin,
                )
                .unwrap()
            }
            3 => {
                f.parameters.next_delay =
                    RecoveryDelay::from_sequence(f.parameters.schedule.initial).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).is_err(),
            "transfer case {case}"
        );
        assert!(!home.draft().exists());
    }
}

#[test]
fn persisted_origin_and_transfer_modes_are_strict_and_not_interchangeable() {
    for is_origin in [false, true] {
        let home = Home::new();
        let f = fixture();
        let (draft, context) = if is_origin {
            let parameters = origin_parameters(f.parameters);
            let context = parameters.context.clone();
            (
                RecoveryDraft::create_origin(&home.draft(), parameters, &f.user, &f.payout)
                    .unwrap(),
                context,
            )
        } else {
            let context = f.parameters.context.clone();
            (
                RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).unwrap(),
                context,
            )
        };
        drop(draft);
        let path = home.draft().join("recovery-draft.json");
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for case in 0..10 {
            let mut record = original.clone();
            match case {
                0 => {
                    record["mode"] = if is_origin {
                        json!({"kind":"transfer","previous_delay":240})
                    } else {
                        json!({"kind":"origin"})
                    }
                }
                1 => {
                    record.as_object_mut().unwrap().remove("mode");
                }
                2 => record["mode"]["unknown"] = json!(1),
                3 => record["mode"]["kind"] = json!("unknown"),
                4 => record["version"] = json!(1),
                5 => record["previous_delay"] = json!(180),
                6 => record["next_delay"] = json!(119),
                7 => {
                    record["previous_capability"] = json!(if is_origin {
                        [21; 32]
                    } else {
                        origin_previous_capability(&context.deployment, &context.coin).unwrap()
                    })
                }
                8 => {
                    record["context"]["previous_state"] = json!(if is_origin {
                        [7; 32]
                    } else {
                        origin_previous_state(&context.deployment, &context.coin).unwrap()
                    })
                }
                9 => record["mode"] = json!({"kind":"origin","previous_delay":180}),
                _ => unreachable!(),
            }
            fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            // Supply the mutated public context where present, so failure tests
            // validation of the mode/sentinels rather than only caller equality.
            let expected: TransferContext =
                serde_json::from_value(record["context"].clone()).unwrap();
            assert!(
                RecoveryDraft::open(&home.draft(), &expected).is_err(),
                "mode {is_origin} case {case}"
            );
        }
        fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(RecoveryDraft::open(&home.draft(), &context).is_ok());
    }
}

#[test]
fn persisted_origin_refresh_binds_context_funding_and_actual_server_point() {
    let home = Home::new();
    let f = fixture();
    let parameters = origin_parameters(f.parameters);
    let draft =
        RecoveryDraft::create_origin(&home.draft(), parameters, &f.user, &f.payout).unwrap();
    drop(draft);
    let path = home.draft().join("recovery-draft.json");
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for case in 0..4 {
        let mut record = original.clone();
        match case {
            0 => record["refresh_commitment"] = json!(vec![20; 32]),
            1 => record["context"]["operation"] = json!(vec![45; 32]),
            2 => record["backing"]["funding_salt"] = json!(hex::encode([46; 32])),
            3 => {
                record["draft_server"] = json!(hex::encode(
                    point_bytes(ProjectivePoint::GENERATOR * Scalar::from(24u64)).unwrap()
                ))
            }
            _ => unreachable!(),
        }
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        let expected: TransferContext = serde_json::from_value(record["context"].clone()).unwrap();
        assert!(
            RecoveryDraft::open(&home.draft(), &expected).is_err(),
            "origin refresh case {case}"
        );
    }
}

#[test]
fn receiver_recovery_is_durable_single_nonce_and_has_a_valid_bitcoin_signature() {
    let home = Home::new();
    let f = fixture();
    let context = f.parameters.context.clone();
    let payout = f.payout;
    let output_key = f.parameters.backing.key().unwrap();
    let rs = point_bytes(ProjectivePoint::GENERATOR * f.server_nonce).unwrap();
    let mut draft = RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &payout).unwrap();
    let prepared = draft.commitments().unwrap();
    assert!(draft.completed_transaction().is_err());
    assert!(draft.finish(&context, rs, [0; 32]).is_err());
    assert_eq!(
        fs::metadata(home.draft()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(home.draft().join("recovery-draft.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(draft);
    let mut draft = RecoveryDraft::open(&home.draft(), &context).unwrap();
    assert_eq!(draft.commitments().unwrap(), prepared);
    let binding = draft.bind_server_nonce(&context, rs).unwrap();
    assert_eq!(binding.funding, prepared.funding);
    assert_eq!(binding.recovery, prepared.recovery);
    assert_eq!(binding.nonce_commitment, prepared.blinding);
    assert_eq!(binding.encode().unwrap().len(), SigningBinding::ENCODED_LEN);
    let partial = server_contribution(&binding, f.server, f.server_nonce);
    drop(draft);
    let mut draft = RecoveryDraft::open(&home.draft(), &context).unwrap();
    assert_eq!(
        draft
            .bind_server_nonce(&context, rs)
            .unwrap()
            .encode()
            .unwrap(),
        binding.encode().unwrap()
    );
    let transaction = draft.finish(&context, rs, partial).unwrap();
    assert_eq!(transaction.input[0].sequence.to_consensus_u32(), 420);
    assert_eq!(transaction.output[0].value.to_sat(), 98_000);
    assert_eq!(transaction.input[0].witness.len(), 1);
    let signature: [u8; 64] = transaction.input[0]
        .witness
        .iter()
        .next()
        .unwrap()
        .try_into()
        .unwrap();
    let mut unsigned = transaction.clone();
    unsigned.input[0].witness.clear();
    attach_signature(&mut unsigned, 99_000, output_key, &signature).unwrap();
    assert_eq!(serialize(&unsigned), serialize(&transaction));
    let payout_key = SigningKey::from_bytes(&payout)
        .unwrap()
        .verifying_key()
        .to_bytes();
    assert_eq!(
        transaction.output[0].script_pubkey,
        p2tr(&payout_key.into())
    );
    // The receiver independently owns the payout secret, even after the signer
    // and source draft have gone away. No server secret signs this output.
    let secp = Secp256k1::new();
    let payout_pair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&payout).unwrap());
    let message = Message::from_digest([42; 32]);
    let payout_signature = secp.sign_schnorr_no_aux_rand(&message, &payout_pair);
    secp.verify_schnorr(
        &payout_signature,
        &message,
        &payout_pair.x_only_public_key().0,
    )
    .unwrap();
    drop(draft);
    let mut restored = RecoveryDraft::open(&home.draft(), &context).unwrap();
    assert_eq!(
        serialize(&restored.completed_transaction().unwrap()),
        serialize(&transaction)
    );
    assert_eq!(
        serialize(&restored.finish(&context, rs, partial).unwrap()),
        serialize(&transaction)
    );
}

#[test]
fn changed_nonce_context_or_partial_never_rewrites_a_bound_draft() {
    let home = Home::new();
    let f = fixture();
    let context = f.parameters.context.clone();
    let rs = point_bytes(ProjectivePoint::GENERATOR * f.server_nonce).unwrap();
    let other_rs = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(30u64)).unwrap();
    let mut draft = RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).unwrap();
    let mut wrong_context = context.clone();
    wrong_context.operation[0] ^= 1;
    assert!(draft.bind_server_nonce(&wrong_context, rs).is_err());
    assert!(draft.bind_server_nonce(&context, [0; 64]).is_err());
    let binding = draft.bind_server_nonce(&context, rs).unwrap();
    let partial = server_contribution(&binding, f.server, f.server_nonce);
    let bad_partial: [u8; 32] = (scalar(&partial).unwrap() + Scalar::ONE).to_bytes().into();
    let saved = fs::read(home.draft().join("recovery-draft.json")).unwrap();
    assert!(draft.bind_server_nonce(&context, other_rs).is_err());
    assert!(draft.finish(&wrong_context, rs, partial).is_err());
    assert!(draft.finish(&context, other_rs, partial).is_err());
    assert!(draft.finish(&context, rs, bad_partial).is_err());
    assert!(draft.finish(&context, rs, [255; 32]).is_err());
    assert!(fs::read(home.draft().join("recovery-draft.json")).unwrap() == saved);
    draft.finish(&context, rs, partial).unwrap();
    assert!(draft.finish(&context, rs, bad_partial).is_err());
    drop(draft);
    assert!(RecoveryDraft::open(&home.draft(), &wrong_context).is_err());
}

#[test]
fn invalid_activation_share_policy_or_commitment_is_rejected_before_storage() {
    for case in 0..10 {
        let home = Home::new();
        let mut f = fixture();
        match case {
            0 => {
                f.parameters.draft_server =
                    point_bytes(ProjectivePoint::GENERATOR * Scalar::from(24u64)).unwrap()
            }
            1 => f.user = [0; 32],
            2 => f.parameters.next_delay = RecoveryDelay::from_sequence(119).unwrap(),
            3 => f.parameters.backing.amount -= 1,
            4 => f.parameters.backing.txid = Txid::from_byte_array([1; 32]).to_string(),
            5 => f.parameters.context.coin[0] ^= 1,
            6 => f.parameters.refresh_commitment = [0; 32],
            7 => f.parameters.fee = 10_001,
            8 => {
                f.parameters.activation.input[0].witness =
                    bitcoin::Witness::from_slice(&[[0u8; 64]])
            }
            9 => f.parameters.previous_capability = f.parameters.next_capability,
            _ => unreachable!(),
        }
        assert!(
            RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).is_err(),
            "fixture case {case}"
        );
        assert!(!home.draft().exists());
    }
}

#[test]
fn incomplete_corrupt_or_concurrently_open_drafts_fail_closed() {
    let home = Home::new();
    let f = fixture();
    let context = f.parameters.context.clone();
    let draft = RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).unwrap();
    assert!(RecoveryDraft::open(&home.draft(), &context).is_err());
    drop(draft);
    let path = home.draft().join("recovery-draft.json");
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record["state"]["unknown"] = json!(true);
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(RecoveryDraft::open(&home.draft(), &context).is_err());
    fs::write(&path, b"{\"version\":").unwrap();
    assert!(RecoveryDraft::open(&home.draft(), &context).is_err());
    fs::remove_file(&path).unwrap();
    assert!(RecoveryDraft::open(&home.draft(), &context).is_err());
}

#[test]
fn unpublished_recovery_attempts_do_not_block_safe_initialization_retry() {
    for complete in [false, true] {
        let home = Home::new();
        let staging = home
            .0
            .join(format!(".zark-outgoing-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&staging).unwrap();
        let attempt_name = format!("attempt-{}", hex::encode(random32()));
        let attempt = staging.join(&attempt_name);
        if complete {
            // Simulate interruption after the private record was complete but
            // before its directory was published. No commitments were sent.
            let f = fixture();
            drop(RecoveryDraft::create(&attempt, f.parameters, &f.user, &f.payout).unwrap());
        } else {
            // Simulate interruption during the first private record write.
            fs::DirBuilder::new().mode(0o700).create(&attempt).unwrap();
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(attempt.join("recovery-draft.json"))
                .unwrap();
            file.write_all(b"{\"schema\":").unwrap();
            file.sync_all().unwrap();
        }
        let old_record = fs::read(attempt.join("recovery-draft.json")).unwrap();
        assert!(!home.draft().exists());

        let f = fixture();
        let context = f.parameters.context.clone();
        let draft = RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout)
            .expect("an unpublished attempt must not occupy the final recovery directory");
        let commitments = draft.commitments().unwrap();
        assert!(home.draft().join("recovery-draft.json").is_file());
        drop(draft);
        assert_eq!(
            RecoveryDraft::open(&home.draft(), &context)
                .unwrap()
                .commitments()
                .unwrap(),
            commitments,
        );
        assert_eq!(
            fs::read(attempt.join("recovery-draft.json")).unwrap(),
            old_record,
            "retry must retain, not reinterpret or rewrite, unpublished attempts",
        );
    }
}

#[test]
fn atomic_initialization_never_replaces_a_published_or_incomplete_target() {
    let home = Home::new();
    let f = fixture();
    let context = f.parameters.context.clone();
    let mut draft = RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).unwrap();
    let binding = draft
        .bind_server_nonce(
            &context,
            point_bytes(ProjectivePoint::GENERATOR * f.server_nonce).unwrap(),
        )
        .unwrap();
    let partial = server_contribution(&binding, f.server, f.server_nonce);
    let transaction = draft
        .finish(&context, binding.server_nonce, partial)
        .unwrap();
    drop(draft);
    let record = home.draft().join("recovery-draft.json");
    let saved = fs::read(&record).unwrap();
    let f = fixture();
    assert!(RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).is_err());
    assert_eq!(fs::read(&record).unwrap(), saved);
    assert_eq!(
        RecoveryDraft::open(&home.draft(), &context)
            .unwrap()
            .completed_transaction()
            .unwrap(),
        transaction,
    );

    // Existing ambiguous/corrupt final directories are never interpreted as
    // unpublished attempts: previously exposed commitments may exist elsewhere.
    fs::remove_file(&record).unwrap();
    let f = fixture();
    assert!(RecoveryDraft::create(&home.draft(), f.parameters, &f.user, &f.payout).is_err());
    assert!(!record.exists());
    assert!(RecoveryDraft::open(&home.draft(), &context).is_err());
}

#[test]
#[ignore = "explicit synthetic private proof fixture export; requires ZARK_RECOVERY_FIXTURE under this checkout's work directory"]
fn export_synthetic_recovery_fixture() {
    export_fixture(
        "ZARK_RECOVERY_FIXTURE",
        &native_fixture_value(fixture(), None),
    );
}

#[test]
fn native_recovery_covers_all_internal_output_and_nonce_parities() {
    assert_eq!(parity_fixtures().len(), 8);
}

#[test]
#[ignore = "explicit synthetic parity fixture export; requires ZARK_RECOVERY_PARITY_FIXTURE under work"]
fn export_synthetic_recovery_parity_fixtures() {
    export_fixture(
        "ZARK_RECOVERY_PARITY_FIXTURE",
        &json!({
            "fixture_version": 1,
            "source": "synthetic test keys and coins only; never for funds",
            "cases": parity_fixtures(),
        }),
    );
}
