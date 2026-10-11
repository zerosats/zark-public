use anyhow::Result;
use k256::schnorr::SigningKey;
use zark_protocol::{
    handoff::TransferContext,
    session::{Purpose, sign_request, verify_request},
};

#[test]
fn request_authentication_binds_role_body_and_complete_session_context() -> Result<()> {
    let key = SigningKey::from_bytes(&[9; 32])?;
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
    let digest = [6; 32];
    let signature = sign_request(&key, &context, Purpose::RecoveryIssuance, &digest)?;
    verify_request(&context, Purpose::RecoveryIssuance, &digest, &signature)?;
    for other in [
        Purpose::SenderReservation,
        Purpose::SenderHandover,
        Purpose::RecipientProposal,
        Purpose::RecoveryPreparation,
        Purpose::OriginAcceptance,
        Purpose::SenderCompletion,
        Purpose::IssuedResponseRecovery,
        Purpose::BootstrapFreeze,
        Purpose::DepositIssuance,
    ] {
        assert!(verify_request(&context, other, &digest, &signature).is_err());
    }
    assert!(verify_request(&context, Purpose::RecoveryIssuance, &[7; 32], &signature).is_err());
    assert!(verify_request(&context, Purpose::RecoveryIssuance, &[0; 32], &signature).is_err());
    for i in 0..6 {
        let mut changed = context.clone();
        match i {
            0 => changed.deployment[0] ^= 1,
            1 => changed.coin[0] ^= 1,
            2 => changed.previous_state[0] ^= 1,
            3 => changed.operation[0] ^= 1,
            4 => changed.recipient_claim[0] ^= 1,
            _ => {
                changed.session_auth = SigningKey::from_bytes(&[10; 32])?
                    .verifying_key()
                    .to_bytes()
                    .into()
            }
        }
        assert!(verify_request(&changed, Purpose::RecoveryIssuance, &digest, &signature).is_err());
    }
    assert!(
        sign_request(
            &SigningKey::from_bytes(&[10; 32])?,
            &context,
            Purpose::RecoveryIssuance,
            &digest
        )
        .is_err()
    );
    assert!(verify_request(&context, Purpose::RecoveryIssuance, &digest, &[0; 64]).is_err());
    Ok(())
}
