//! Synthetic native offer tests. Placeholder proof bytes are deliberately NOT
//! treated as valid proofs; successful outer verification needs real lineage data.
use bitcoin::{OutPoint, Txid, hashes::Hash};
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    handoff::{
        FundingOpening, HandoverBinding, RecoverySchedule, TransferIntent, bridge_commitment,
        masked_share_commitment, policy_commitment, recipient_claim_commitment,
    },
    hash,
    lineage::{LineageHandoverBinding, LineagePolicy, ROLE_COUNT},
    point_bytes,
    proof::{ArtifactPin, PROOF_BYTES, PinnedVerifier},
    random32,
};
use zark_wallet::{
    bitcoin::{attach_signature, sighash},
    envelope::{OfferContext, encrypt_offer},
    invitation::{InvitationStatus, LocalInvitation},
    offer::{MAX_OFFER_PLAINTEXT_BYTES, OfferParameters, UnverifiedOffer},
    signing::{Blinding, FundingKey},
    types::Input,
};
use zeroize::Zeroizing;

const DEPLOYMENT: [u8; 32] = [91; 32];
pub(crate) struct Home(pub(crate) PathBuf);
impl Home {
    pub(crate) fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("zark-offer-test-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    pub(crate) fn invitation(&self, name: &str) -> LocalInvitation {
        LocalInvitation::create(&self.0.join(name), AddressNetwork::Test, DEPLOYMENT).unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn fixture(
    recipient: &ReceivingAddress,
) -> (UnverifiedOffer, OfferContext, LineagePolicy) {
    fixture_at_slot(recipient, 0)
}

fn fixture_at_slot(
    recipient: &ReceivingAddress,
    slot: u32,
) -> (UnverifiedOffer, OfferContext, LineagePolicy) {
    let context = OfferContext {
        deployment: DEPLOYMENT,
        coin: [92; 32],
        operation: [93; 32],
    };
    let schedule = RecoverySchedule {
        initial: 480,
        gap: 60,
        margin: 6,
    };
    let mut roles = [[0; 32]; ROLE_COUNT];
    for (i, role) in roles.iter_mut().enumerate() {
        role[31] = (i + 1) as u8;
    }
    let policy = LineagePolicy {
        deployment: DEPLOYMENT,
        schedule,
        origin_key: SigningKey::from_bytes(&Scalar::from(41u64).to_bytes())
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into(),
        role_hashes: roles,
    };
    let parent_server = Scalar::from(21u64);
    let parent_key = FundingKey::new(
        ProjectivePoint::GENERATOR * parent_server,
        Scalar::from(31u64),
    )
    .unwrap();
    let key = FundingKey::new(
        ProjectivePoint::GENERATOR * Scalar::from(23u64),
        Scalar::from(7u64),
    )
    .unwrap();
    let activation_input = Input {
        deployment: hex::encode(DEPLOYMENT),
        id: hex::encode([10; 32]),
        funding_salt: hex::encode([11; 32]),
        internal_point: hex::encode(point_bytes(parent_key.internal).unwrap()),
        txid: Txid::from_byte_array([12; 32]).to_string(),
        vout: 0,
        amount: 100_000,
    };
    let mut activation = zark_wallet::bitcoin::activation(
        OutPoint::new(Txid::from_byte_array([12; 32]), 0),
        100_000,
        &[(99_000, key.xonly().unwrap())],
        0,
    )
    .unwrap();
    let blind = Blinding::default();
    let nonce = Scalar::from(17u64);
    let sp = ProjectivePoint::GENERATOR * parent_server;
    let rs = ProjectivePoint::GENERATOR * nonce;
    let session = blind
        .bind(
            &parent_key,
            sp,
            rs,
            sighash(&activation, 100_000, parent_key.xonly().unwrap()).unwrap(),
        )
        .unwrap();
    let signature = blind
        .finish(
            &parent_key,
            &session,
            sp,
            rs,
            nonce + session.challenge * parent_server,
        )
        .unwrap();
    attach_signature(
        &mut activation,
        100_000,
        parent_key.xonly().unwrap(),
        &signature,
    )
    .unwrap();
    let backing = Input {
        deployment: hex::encode(DEPLOYMENT),
        id: hex::encode(context.coin),
        funding_salt: hex::encode([19; 32]),
        internal_point: hex::encode(point_bytes(key.internal).unwrap()),
        txid: activation.compute_txid().to_string(),
        vout: 0,
        amount: 99_000,
    };
    let funding = FundingOpening {
        deployment: DEPLOYMENT,
        coin: context.coin,
        salt: [19; 32],
        txid: activation.compute_txid().to_byte_array(),
        vout: 0,
        amount: 99_000,
        internal_point: point_bytes(key.internal).unwrap(),
    }
    .commitment()
    .unwrap();
    let claim_salt = [20; 32];
    let intent = TransferIntent {
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: DEPLOYMENT,
        coin: context.coin,
        previous_state: [7; 32],
        operation: context.operation,
        recipient_claim: recipient_claim_commitment(
            &DEPLOYMENT,
            &context.coin,
            &context.operation,
            &recipient.claim_key()[1..].try_into().unwrap(),
            &claim_salt,
        )
        .unwrap(),
    };
    let masked_share: [u8; 32] = Scalar::from(17u64).to_bytes().into();
    let masked_share_salt = [21; 32];
    let bridge_salt = [22; 32];
    let old_delay = schedule.delay_after(slot).unwrap();
    let policy_commitment = policy_commitment(schedule).unwrap();
    let handover = LineageHandoverBinding {
        handover: HandoverBinding {
            masked_share: masked_share_commitment(&intent, &masked_share, &masked_share_salt)
                .unwrap(),
            bridge: bridge_commitment(
                &intent,
                &funding,
                old_delay,
                &policy_commitment,
                &bridge_salt,
            )
            .unwrap(),
            draft_access: zark_protocol::handoff::draft_access_commitment(&intent, &[55; 32])
                .unwrap(),
            intent,
            funding,
            mask: [24; 32],
            previous_capability: [25; 32],
            server_share: [26; 32],
            policy: policy_commitment,
        },
        origin_key: policy.origin_key,
        role_hashes: policy.role_hashes,
    };
    let offer = UnverifiedOffer::from_parts(
        OfferParameters {
            predecessor: if slot == 0 {
                zark_protocol::certificate::PredecessorKind::Origin
            } else {
                zark_protocol::certificate::PredecessorKind::Transfer
            },
            token: [55; 32],
            handover,
            proof: vec![0; PROOF_BYTES],
            backing,
            activation_input,
            activation,
            masked_share,
            masked_share_salt,
            bridge_salt,
            old_delay,
            claim_salt,
        },
        recipient,
        &context,
        &policy,
    )
    .unwrap();
    (offer, context, policy)
}

fn edit(offer: &UnverifiedOffer, change: impl FnOnce(&mut Value)) -> Zeroizing<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(&offer.encode().unwrap()).unwrap();
    change(&mut value);
    Zeroizing::new(serde_json::to_vec(&value).unwrap())
}

pub(crate) fn unavailable_verifier(home: &Home, policy: &LineagePolicy) -> PinnedVerifier {
    let path = home.0.join("unavailable-verifier");
    // A deliberately non-executable file, never a fake successful verifier.
    fs::write(&path, b"not a verifier or verification key").unwrap();
    let checksum = hash(&[b"not a verifier or verification key"]);
    let roles = zark_protocol::deployment::RELATIONS;
    PinnedVerifier::new(
        DEPLOYMENT,
        ArtifactPin {
            path: path.clone(),
            sha256: checksum,
        },
        home.0.clone(),
        roles.map(|role| {
            (
                role,
                ArtifactPin {
                    path: path.clone(),
                    sha256: checksum,
                },
            )
        }),
    )
    .unwrap()
    .with_lineage_policy(policy.clone())
    .unwrap()
}

#[test]
fn native_offer_roundtrip_matches_recipient_and_carries_no_private_history() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    let plaintext = offer.encode().unwrap();
    let parsed = UnverifiedOffer::decode(&plaintext, &address, &context, &policy).unwrap();
    assert_eq!(
        parsed.handover().encode().unwrap(),
        offer.handover().encode().unwrap()
    );
    let record: Value = serde_json::from_slice(&plaintext).unwrap();
    let expected = [
        "schema",
        "version",
        "predecessor",
        "token",
        "handover",
        "proof",
        "backing",
        "activation_input",
        "activation",
        "masked_share",
        "masked_share_salt",
        "bridge_salt",
        "old_delay",
        "claim_salt",
    ];
    assert_eq!(record.as_object().unwrap().len(), expected.len());
    assert!(expected.iter().all(|key| record.get(key).is_some()));
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
}

#[test]
fn native_bindings_reject_wrong_claim_backing_bridge_activation_or_policy() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    for case in 0..16 {
        let bytes = edit(&offer, |record| match case {
            0 => record["claim_salt"] = json!(vec![30; 32]),
            1 => record["masked_share"] = json!(vec![0; 32]),
            2 => record["masked_share_salt"] = json!(vec![31; 32]),
            3 => record["bridge_salt"] = json!(vec![32; 32]),
            4 => record["old_delay"] = json!(120),
            5 => record["old_delay"] = json!(60),
            6 => record["backing"]["amount"] = json!(98_999),
            7 => record["backing"]["vout"] = json!(1),
            8 => record["backing"]["id"] = json!(hex::encode([33; 32])),
            9 => record["activation_input"]["amount"] = json!(100_001),
            10 => record["activation_input"]["txid"] = json!(hex::encode([34; 32])),
            11 => {
                let s = record["activation"].as_str().unwrap();
                let mut raw = hex::decode(s).unwrap();
                let i = raw.len() - 5;
                raw[i] ^= 1;
                record["activation"] = json!(hex::encode(raw));
            }
            12 => record["backing"]["internal_point"] = json!("00".repeat(64)),
            13 => record["token"] = json!(vec![0; 32]),
            14 => record["token"] = json!(vec![56; 32]),
            15 => record["predecessor"] = json!("transfer"),
            _ => unreachable!(),
        });
        assert!(
            UnverifiedOffer::decode(&bytes, &address, &context, &policy).is_err(),
            "native case {case}"
        );
    }
    let other = home.invitation("another").public_address().unwrap();
    assert!(UnverifiedOffer::decode(&offer.encode().unwrap(), &other, &context, &policy).is_err());
    for case in 0..3 {
        let mut changed = policy.clone();
        match case {
            0 => {
                changed.origin_key = SigningKey::from_bytes(&Scalar::from(43u64).to_bytes())
                    .unwrap()
                    .verifying_key()
                    .to_bytes()
                    .into()
            }
            1 => changed.role_hashes.swap(0, 1),
            _ => changed.schedule.initial = 181,
        };
        assert!(
            UnverifiedOffer::decode(&offer.encode().unwrap(), &address, &context, &changed)
                .is_err()
        );
    }
}

#[test]
fn malformed_noncanonical_and_history_extended_payloads_fail_closed() {
    let home = Home::new();
    let invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    for case in 0..9 {
        let bytes = edit(&offer, |record| match case {
            0 => record["version"] = json!(1),
            1 => record["history"] = json!([]),
            2 => record["activation_input"]["history"] = json!([]),
            3 => record["old_recovery"] = json!("private predecessor transaction"),
            4 => record["proof"] = json!("00"),
            5 => record["handover"] = json!(record["handover"].as_str().unwrap().to_uppercase()),
            6 => record["backing"]["funding_salt"] = json!("AB".repeat(32)),
            7 => record["masked_share"] = json!(vec![255; 32]),
            8 => record["activation"] = json!("00".repeat(1025)),
            _ => unreachable!(),
        });
        assert!(
            UnverifiedOffer::decode(&bytes, &address, &context, &policy).is_err(),
            "encoding case {case}"
        );
    }
    for bytes in [
        Vec::new(),
        b"{\"version\":".to_vec(),
        vec![b' '; MAX_OFFER_PLAINTEXT_BYTES + 1],
    ] {
        assert!(UnverifiedOffer::decode(&bytes, &address, &context, &policy).is_err());
    }
    let mut wrong = context.clone();
    wrong.operation = [90; 32];
    assert!(UnverifiedOffer::decode(&offer.encode().unwrap(), &address, &wrong, &policy).is_err());
}

#[test]
fn decrypting_valid_native_bytes_cannot_reserve_without_actual_outer_verification() {
    let home = Home::new();
    let mut invitation = home.invitation("receiver");
    let address = invitation.public_address().unwrap();
    let (offer, context, policy) = fixture(&address);
    let verifier = unavailable_verifier(&home, &policy);
    let before = Zeroizing::new(fs::read(home.0.join("receiver/invitation.json")).unwrap());
    let sealed = encrypt_offer(&address, &context, &offer.encode().unwrap()).unwrap();
    assert!(
        invitation
            .decrypt_offer(&context, sealed.as_bytes())
            .is_ok()
    );
    assert!(
        invitation
            .verify_and_reserve_offer(
                &context,
                sealed.as_bytes(),
                &policy,
                &verifier,
                &home.0.join("verify")
            )
            .is_err()
    );
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    assert!(fs::read(home.0.join("receiver/invitation.json")).unwrap() == *before);
    let other = home.invitation("other").public_address().unwrap();
    let (wrong_offer, _, _) = fixture(&other);
    // Correct envelope recipient, but proof claim targets another claim key.
    let wrong = encrypt_offer(&address, &context, &wrong_offer.encode().unwrap()).unwrap();
    assert!(
        invitation
            .verify_and_reserve_offer(
                &context,
                wrong.as_bytes(),
                &policy,
                &verifier,
                &home.0.join("verify")
            )
            .is_err()
    );
    assert_eq!(invitation.status(), InvitationStatus::Fresh);
    assert!(fs::read(home.0.join("receiver/invitation.json")).unwrap() == *before);
}

#[test]
fn offers_accept_all_seven_successor_slots() {
    let home = Home::new();
    let address = home.invitation("receiver").public_address().unwrap();
    for slot in 0..7 {
        let (offer, context, policy) = fixture_at_slot(&address, slot);
        UnverifiedOffer::decode(&offer.encode().unwrap(), &address, &context, &policy).unwrap();
    }
}
