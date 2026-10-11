use anyhow::Result;
use k256::schnorr::SigningKey;
use zark_protocol::{
    handoff::TransferContext,
    hash,
    session::{Purpose, sign_request},
    wire::{Command, Request},
};

#[test]
fn shared_wire_authenticates_exact_canonical_body_and_role() -> Result<()> {
    let key = SigningKey::from_bytes(&[17; 32])?;
    let context = TransferContext {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
    };
    let request = Request::sign(
        context.clone(),
        Command::Prepare {
            recovery: [6; 32],
            blinding: [7; 32],
        },
        &key,
    )?;
    let body = request.command.body()?;
    let wire = request.encode()?;
    let parsed = Request::from_body(context.clone(), &body, request.signature)?;
    assert_eq!(*parsed.encode()?, *wire);
    assert_eq!(Request::decode(&wire)?.digest()?, request.digest()?);
    let mut changed = request.clone();
    changed.context.operation[0] ^= 1;
    assert!(changed.authenticate().is_err());
    let mut changed = request.clone();
    changed.command = Command::Prepare {
        recovery: [8; 32],
        blinding: [7; 32],
    };
    assert!(changed.authenticate().is_err());
    let mut changed = request.clone();
    changed.signature = sign_request(
        &key,
        &context,
        Purpose::RecipientProposal,
        &request.digest()?,
    )?;
    assert!(changed.authenticate().is_err());
    let old = sign_request(
        &key,
        &context,
        Purpose::RecoveryPreparation,
        &hash(&[&body]),
    )?;
    assert!(
        Request::from_body(context.clone(), &body, old).is_err(),
        "unframed old wallet digest must not authenticate"
    );
    let mut extra = wire.to_vec();
    extra.push(b' ');
    assert!(Request::decode(&extra).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&wire)?;
    value["version"] = 7.into();
    assert!(Request::decode(&serde_json::to_vec(&value)?).is_err());
    value = serde_json::from_slice(&wire)?;
    value["command"]["payout"] = "private canary".into();
    assert!(Request::decode(&serde_json::to_vec(&value)?).is_err());
    assert!(
        Request::sign(
            context.clone(),
            Command::IssueDeposit {
                statement: vec![],
                proof: vec![0; 3]
            },
            &key
        )
        .is_err()
    );
    let ack = Request::sign(
        context.clone(),
        Command::AcceptOrigin {
            state: [8; 32],
            issuance_identity: [9; 32],
        },
        &key,
    )?;
    assert!(ack.command.proof().is_none());
    Request::decode(&ack.encode()?)?.authenticate()?;
    let mut changed = ack.clone();
    changed.command = Command::AcceptOrigin {
        state: [8; 32],
        issuance_identity: [10; 32],
    };
    assert!(changed.authenticate().is_err());
    assert!(Command::decode(br#"{"op":"bootstrap_authorize","statement":[],"proof":[]}"#).is_err());
    assert!(Command::decode(br#"{"op":"accept_origin","proof":[]}"#).is_err());
    let freeze = Request::sign(
        context,
        Command::BootstrapFreeze {
            statement: vec![1; 589],
        },
        &key,
    )?;
    assert!(freeze.command.proof().is_none());
    Request::decode(&freeze.encode()?)?.authenticate()?;
    Ok(())
}
