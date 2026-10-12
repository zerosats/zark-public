//! Synthetic relation oracle, actual HTTPS decoding, shared worker and durable engine.
//! This qualifies transport/recovery behavior, not live proofs or Bitcoin spends.
use super::*;
use crate::host::browser_test_roundtrip as exchange;

#[test]
fn https_issuance_replays_after_restart_and_acknowledges_only_the_issued_record() -> Result<()> {
    let h = Harness::new()?;
    let issue = h.prepare_issue(&h.origin_context, &h.alice)?;
    let before = fs::read(&h.engine.checkpoint)?;
    let issued = exchange(&h.engine, &issue)?;
    assert_eq!(issued["ok"], true);
    assert_ne!(before, fs::read(&h.engine.checkpoint)?);
    assert_eq!(exchange(&h.reopen()?, &issue)?, issued);
    let mut altered = issue.clone();
    match &mut altered.command {
        Command::Issue { proof, .. } | Command::IssueDeposit { proof, .. } => proof[0] ^= 1,
        _ => panic!("expected issuance request"),
    }
    // A fresh signature cannot turn a changed request into an exact replay.
    altered = Request::sign(altered.context, altered.command, &h.alice)?;
    assert_eq!(exchange(&h.reopen()?, &altered)?["ok"], false);
    let wrong_ack = Request::sign(
        h.origin_context.clone(),
        Command::AcceptOrigin {
            state: [9; 32],
            issuance_identity: [8; 32],
        },
        &h.alice,
    )?;
    assert_eq!(exchange(&h.engine, &wrong_ack)?["ok"], false);
    let ack = h.request(
        &h.origin_context,
        Command::AcceptOrigin {
            state: [0; 32],
            issuance_identity: [0; 32],
        },
        &h.alice,
    )?;
    let accepted = exchange(&h.engine, &ack)?;
    assert_eq!(accepted["ok"], true);
    assert_eq!(exchange(&h.reopen()?, &ack)?, accepted);
    Ok(())
}
