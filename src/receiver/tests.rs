use super::*;
use crate::chain::ChainConfig;
use k256::schnorr::SigningKey;
use std::path::PathBuf;
use zark_protocol::{
    handoff::{RecoveryDelay, TransferContext},
    hash,
    session::Purpose,
    wire::{Command, Request},
};

use super::freshness::check_observed_use;
use super::response::{checked_recovery_request, exact_response_fields, response_bytes};
use serde_json::json;
use zark_protocol::session::sign_request;

#[test]
fn expired_incoming_window_blocks_transfer_but_not_current_cooperative_exit() {
    use zark_protocol::{
        deployment::Deployment,
        network::{Network, REGTEST_GENESIS},
    };
    let control = SigningKey::from_bytes(&[7; 32]).unwrap();
    let origin = SigningKey::from_bytes(&[8; 32]).unwrap();
    let chain = ChainConfig {
        deployment: Deployment {
            protocol_version: 10,
            signer_protocol_version: zark_protocol::deployment::SIGNER_PROTOCOL_VERSION,
            network: Network::Regtest,
            genesis_hash: REGTEST_GENESIS.into(),
            signet_challenge: String::new(),
            initial_delay: 480,
            gap: 60,
            margin: 6,
            origin_key: hex::encode(origin.verifying_key().to_bytes()),
            control_key: hex::encode(control.verifying_key().to_bytes()),
            suite: hex::encode([1; 32]),
        },
        bitcoin_cli: PathBuf::from("/unused"),
        datadir: PathBuf::from("/unused"),
        rpc_cookie: None,
        rpc_port: 1,
        rpc_transport: Default::default(),
        minimum_confirmations: 1,
    };
    let previous = RecoveryDelay::from_sequence(480).unwrap();
    let next = RecoveryDelay::from_sequence(420).unwrap();
    // This unit test covers window selection after a live observation. It
    // does not pretend a synthetic observation proves that backing is live.
    let mut observed = crate::chain::Observation {
        tip_height: 100,
        tip_hash: hex::encode([2; 32]),
        activation_height: Some(100),
        activation_in_mempool: false,
    };
    check_observed_use(
        &chain,
        &observed,
        previous,
        next,
        CurrentUse::IncomingTransfer,
    )
    .unwrap();
    observed.tip_height = 100 + u64::from(previous.blocks());
    assert!(
        check_observed_use(
            &chain,
            &observed,
            previous,
            next,
            CurrentUse::IncomingTransfer
        )
        .is_err()
    );
    check_observed_use(
        &chain,
        &observed,
        previous,
        next,
        CurrentUse::CooperativeExit,
    )
    .unwrap();
}

fn context(key: &SigningKey) -> TransferContext {
    TransferContext {
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
    }
}

#[test]
fn saved_requests_use_exact_engine_digest_and_reject_legacy_body_hash_signature() {
    let key = SigningKey::from_bytes(&[7; 32]).unwrap();
    let context = context(&key);
    let command = Command::Prepare {
        recovery: [8; 32],
        blinding: [9; 32],
    };
    let body = command.body().unwrap();
    let request = Request::sign(context.clone(), command, &key).unwrap();
    let mut saved = RequestRecord {
        body: hex::encode(&*body),
        digest: request.digest().unwrap(),
        signature: hex::encode(request.signature),
    };
    let replay =
        checked_recovery_request(&context, Purpose::RecoveryPreparation, &saved, &body).unwrap();
    Request::from_body(context.clone(), replay.body(), *replay.signature()).unwrap();
    assert!(checked_recovery_request(&context, Purpose::RecoveryIssuance, &saved, &body).is_err());
    let legacy = hash(&[&body]);
    assert_ne!(legacy, saved.digest);
    saved.signature =
        hex::encode(sign_request(&key, &context, Purpose::RecoveryPreparation, &legacy).unwrap());
    assert!(
        checked_recovery_request(&context, Purpose::RecoveryPreparation, &saved, &body).is_err()
    );
    saved.digest = legacy;
    assert!(
        checked_recovery_request(&context, Purpose::RecoveryPreparation, &saved, &body).is_err()
    );
}

#[test]
fn claim_wire_preserves_delta_for_engine_without_claiming_proof_validity() {
    let key = SigningKey::from_bytes(&[7; 32]).unwrap();
    let context = context(&key);
    // Message authentication only; these bytes are deliberately not a valid proof.
    let command = Command::ProposeRecipient {
        statement: vec![1; 397],
        token: [10; 32],
        delta: [8; 32],
        delta_salt: [9; 32],
    };
    let request = Request::sign(context.clone(), command, &key).unwrap();
    let wire = request.encode().unwrap();
    let decoded = Request::decode(&wire).unwrap();
    assert_eq!(request.digest().unwrap(), decoded.digest().unwrap());
    assert!(
        matches!(decoded.command, Command::ProposeRecipient { delta, delta_salt, .. }
        if delta == [8;32] && delta_salt == [9;32])
    );
    let mut wrong_context = context;
    wrong_context.operation = [6; 32];
    assert!(
        Request::from_body(
            wrong_context,
            &request.command.body().unwrap(),
            request.signature
        )
        .is_err()
    );
}

#[test]
fn server_response_parser_rejects_extra_missing_and_malformed_fields() {
    let valid = json!({"draft_server":vec![3;64],"server_salt":vec![4;32]});
    exact_response_fields(&valid, &["draft_server", "server_salt"]).unwrap();
    assert_eq!(
        response_bytes::<32>(&valid, "server_salt").unwrap(),
        [4; 32]
    );
    for changed in [
        json!({"draft_server":vec![3;64]}),
        json!({"draft_server":vec![3;64],"server_salt":vec![4;32],"refresh":vec![5;32]}),
        json!([]),
    ] {
        assert!(exact_response_fields(&changed, &["draft_server", "server_salt"]).is_err());
    }
    for malformed in [
        json!(vec![4; 31]),
        json!(vec![256; 32]),
        json!("04"),
        json!(vec![-1; 32]),
    ] {
        let mut changed = valid.clone();
        changed["server_salt"] = malformed;
        assert!(response_bytes::<32>(&changed, "server_salt").is_err());
    }
}
