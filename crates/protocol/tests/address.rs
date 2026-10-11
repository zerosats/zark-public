use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use serde_json::Value;
use zark_protocol::address::{AddressNetwork, ReceivingAddress};

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/address.json")).unwrap()
}

fn bytes<const N: usize>(vector: &Value, field: &str) -> [u8; N] {
    hex::decode(vector[field].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn network(vector: &Value) -> AddressNetwork {
    match vector["hrp"].as_str().unwrap() {
        "tzark" => AddressNetwork::Test,
        "zark" => AddressNetwork::MainnetReserved,
        _ => panic!("unknown vector HRP"),
    }
}

#[test]
fn independent_reference_vectors_match_exact_encoding_and_decoding() {
    for vector in vectors()["valid"].as_array().unwrap() {
        let class = network(vector);
        let deployment = bytes(vector, "deployment");
        let envelope = bytes(vector, "envelope_key");
        let claim = bytes(vector, "claim_key");
        let address = ReceivingAddress::new(class, deployment, envelope, claim).unwrap();
        let encoded = address.encode();
        assert_eq!(encoded, vector["address"].as_str().unwrap(), "{vector}");
        assert_eq!(encoded.len(), class.encoded_length());
        assert!(encoded.starts_with(&format!("{}1p", class.hrp())));
        let decoded = ReceivingAddress::decode(&encoded, class, &deployment).unwrap();
        assert_eq!(decoded.network(), class);
        assert_eq!(decoded.deployment(), &deployment);
        assert_eq!(decoded.envelope_key(), &envelope);
        assert_eq!(decoded.claim_key(), &claim);
        assert!(decoded == address);
    }
}

#[test]
fn independent_adversarial_vectors_are_rejected() {
    for vector in vectors()["invalid"].as_array().unwrap() {
        assert!(
            ReceivingAddress::decode(
                vector["address"].as_str().unwrap(),
                network(vector),
                &bytes(vector, "deployment"),
            )
            .is_err(),
            "accepted invalid vector: {}",
            vector["name"]
        );
    }
}

#[test]
fn every_single_symbol_substitution_and_adjacent_transposition_is_rejected() {
    let fixture = vectors();
    let vector = &fixture["valid"][0];
    let encoded = vector["address"].as_str().unwrap().as_bytes();
    let deployment = bytes(vector, "deployment");
    // Includes checksum, format, payload and HRP. These are real decoder calls,
    // not a second assertion using the encoder's checksum implementation.
    for index in 0..encoded.len() {
        for replacement in b"qpzry9x8gf2tvdw0s3jn54khce6mua7l1" {
            if encoded[index] == *replacement {
                continue;
            }
            let mut altered = encoded.to_vec();
            altered[index] = *replacement;
            assert!(
                ReceivingAddress::decode(
                    std::str::from_utf8(&altered).unwrap(),
                    AddressNetwork::Test,
                    &deployment,
                )
                .is_err(),
                "accepted changed character {index}"
            );
        }
        if index + 1 < encoded.len() && encoded[index] != encoded[index + 1] {
            let mut altered = encoded.to_vec();
            altered.swap(index, index + 1);
            assert!(
                ReceivingAddress::decode(
                    std::str::from_utf8(&altered).unwrap(),
                    AddressNetwork::Test,
                    &deployment,
                )
                .is_err()
            );
        }
    }
}

#[test]
fn constructor_enforces_key_roles_and_cannot_create_invalid_encodings() {
    let fixture = vectors();
    let vector = &fixture["valid"][0];
    let envelope: [u8; 33] = bytes(vector, "envelope_key");
    let claim: [u8; 33] = bytes(vector, "claim_key");
    let deployment = bytes(vector, "deployment");
    assert!(ReceivingAddress::new(AddressNetwork::Test, [0; 32], envelope, claim).is_err());
    assert!(ReceivingAddress::new(AddressNetwork::Test, deployment, envelope, envelope).is_err());
    let mut negated = claim;
    negated[0] = 3;
    assert!(ReceivingAddress::new(AddressNetwork::Test, deployment, negated, claim).is_err());
    assert!(ReceivingAddress::new(AddressNetwork::Test, deployment, envelope, negated).is_err());
    for invalid in [[0; 33], [255; 33]] {
        assert!(ReceivingAddress::new(AddressNetwork::Test, deployment, invalid, claim).is_err());
    }
}

#[test]
fn fixed_vector_points_agree_with_an_independent_curve_library() {
    let fixture = vectors();
    let one = ProjectivePoint::GENERATOR
        .to_affine()
        .to_encoded_point(true);
    let two = (ProjectivePoint::GENERATOR * Scalar::from(2u64))
        .to_affine()
        .to_encoded_point(true);
    assert_eq!(
        one.as_bytes(),
        &bytes::<33>(&fixture["valid"][0], "envelope_key")
    );
    let mut even_two: [u8; 33] = two.as_bytes().try_into().unwrap();
    even_two[0] = 2;
    assert_eq!(even_two, bytes::<33>(&fixture["valid"][0], "claim_key"));
}

#[test]
fn deployment_and_network_are_mandatory_context_not_inferred_trust() {
    let fixture = vectors();
    let vector = &fixture["valid"][0];
    let encoded = vector["address"].as_str().unwrap();
    let mut other_deployment = bytes::<32>(vector, "deployment");
    other_deployment[31] ^= 1;
    assert!(ReceivingAddress::decode(encoded, AddressNetwork::Test, &other_deployment).is_err());
    assert!(
        ReceivingAddress::decode(
            encoded,
            AddressNetwork::MainnetReserved,
            &bytes(vector, "deployment")
        )
        .is_err()
    );
}
