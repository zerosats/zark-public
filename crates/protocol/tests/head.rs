use anyhow::Result;
use k256::schnorr::SigningKey;
use zark_protocol::head::{Head, HeadQuery, Phase};

#[test]
fn head_authenticates_query_revision_and_minimal_current_state() -> Result<()> {
    let key = SigningKey::from_bytes(&[13; 32])?;
    let public = key.verifying_key().to_bytes().into();
    let query = HeadQuery::fresh([1; 32], [2; 32], public)?;
    let head = Head {
        query: query.clone(),
        state: [3; 32],
        capability: [4; 32],
        phase: Phase::Accepted,
        revision: 7,
        checkpoint_sequence: 11,
    };
    let signature = head.sign(&key)?;
    head.verify(&query, &public, &signature)?;
    let next_query = HeadQuery::fresh([1; 32], [2; 32], public)?;
    assert!(head.verify(&next_query, &public, &signature).is_err());
    for case in 0..8 {
        let mut changed = head.clone();
        match case {
            0 => changed.state[0] ^= 1,
            1 => changed.capability[0] ^= 1,
            2 => changed.phase = Phase::Issued,
            3 => changed.revision += 1,
            4 => changed.checkpoint_sequence += 1,
            5 => changed.query.coin[0] ^= 1,
            6 => changed.query.deployment[0] ^= 1,
            _ => {
                changed.query.session_auth = SigningKey::from_bytes(&[14; 32])?
                    .verifying_key()
                    .to_bytes()
                    .into()
            }
        }
        assert!(changed.verify(&query, &public, &signature).is_err());
    }
    let mut wire = serde_json::to_value(head)?;
    wire["delta"] = serde_json::json!("not a permitted head field");
    assert!(serde_json::from_value::<Head>(wire).is_err());
    Ok(())
}
