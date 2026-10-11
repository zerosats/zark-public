//! V10 application commitments, using the qualified rate-two Poseidon2 wrapper.
//!
//! This is deliberately separate from Bitcoin tagged hashes and SHA256 asset,
//! deployment, transport and storage authentication. Only selected application
//! commitments call this module. Constants come from pinned Noir beta.25.
use k256::elliptic_curve::bigint::{
    Encoding, U256,
    modular::runtime_mod::{DynResidue, DynResidueParams},
};
use std::sync::OnceLock;

type Field = DynResidue<4>;
const MODULUS: U256 =
    U256::from_be_hex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
const PARAMS: DynResidueParams<4> = DynResidueParams::new(&MODULUS);

struct Constants {
    diagonal: [Field; 4],
    rounds: [[Field; 4]; 64],
}

fn constants() -> &'static Constants {
    static CONSTANTS: OnceLock<Constants> = OnceLock::new();
    CONSTANTS.get_or_init(|| {
        let value: serde_json::Value =
            serde_json::from_str(include_str!("application_hash/constants.json"))
                .expect("compiled Poseidon2 constants");
        let field = |v: &serde_json::Value| {
            Field::new(
                &U256::from_be_hex(v.as_str().expect("constant hex")),
                PARAMS,
            )
        };
        Constants {
            diagonal: std::array::from_fn(|i| field(&value["internal_matrix_diagonal"][i])),
            rounds: std::array::from_fn(|i| {
                std::array::from_fn(|j| field(&value["round_constants"][i][j]))
            }),
        }
    })
}

fn matrix([a, b, c, d]: [Field; 4]) -> [Field; 4] {
    let t0 = a + b;
    let t1 = c + d;
    let t2 = b + b + t1;
    let t3 = d + d + t0;
    let t4 = t1 + t1 + t1 + t1 + t3;
    let t5 = t0 + t0 + t0 + t0 + t2;
    [t3 + t5, t5, t2 + t4, t4]
}

fn pow5(x: Field) -> Field {
    let square = x * x;
    square * square * x
}

fn permute(mut state: [Field; 4]) -> [Field; 4] {
    let constants = constants();
    state = matrix(state);
    for (round, rc) in constants.rounds.iter().enumerate() {
        if !(4..60).contains(&round) {
            state = matrix(std::array::from_fn(|i| pow5(state[i] + rc[i])));
        } else {
            state[0] = pow5(state[0] + rc[0]);
            let total = state[0] + state[1] + state[2] + state[3];
            state = std::array::from_fn(|i| state[i] * constants.diagonal[i] + total);
        }
    }
    state
}

fn from_bytes(bytes: &[u8]) -> Field {
    debug_assert!(bytes.len() <= 31);
    let mut encoded = [0; 32];
    encoded[32 - bytes.len()..].copy_from_slice(bytes);
    Field::new(&U256::from_be_slice(&encoded), PARAMS)
}

/// Exact byte preimage, prefixed by the domain and byte length, followed by
/// injective BE31 chunks and a field terminator. Two canonical field elements
/// each contribute their low 128 bits, in big-endian order.
pub(crate) fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let message = parts.concat();
    let mut fields = Vec::with_capacity(4 + message.len().div_ceil(31));
    fields.push(from_bytes(b"ZARK/app-commit/p2/v1"));
    fields.push(from_bytes(&(message.len() as u64).to_be_bytes()));
    fields.extend(message.chunks(31).map(from_bytes));
    fields.push(Field::new(&U256::ONE, PARAMS));
    let zero = Field::new(&U256::ZERO, PARAMS);
    if fields.len() % 2 != 0 {
        fields.push(zero);
    }
    let mut state = [zero; 4];
    for pair in fields.chunks_exact(2) {
        state[0] += pair[0];
        state[1] += pair[1];
        state = permute(state);
    }
    let mut output = [0; 32];
    output[..16].copy_from_slice(&state[0].retrieve().to_be_bytes()[16..]);
    output[16..].copy_from_slice(&state[1].retrieve().to_be_bytes()[16..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_pinned_upstream_permutations_and_independent_application_vectors() {
        let raw = include_bytes!("application_hash/constants.json");
        assert_eq!(
            hex::encode(crate::hash(&[raw])),
            "9818e07435f23729461a657ad42c058790ed7f38fd0929475548e9b1acec209d"
        );
        let constants: serde_json::Value = serde_json::from_slice(raw).unwrap();
        for case in constants["permutation_reference_vectors"]
            .as_array()
            .unwrap()
        {
            let input = std::array::from_fn(|i| {
                Field::new(
                    &U256::from_be_hex(case["input"][i].as_str().unwrap()),
                    PARAMS,
                )
            });
            for (i, field) in permute(input).iter().enumerate() {
                assert_eq!(
                    field.retrieve(),
                    U256::from_be_hex(case["output"][i].as_str().unwrap())
                );
            }
        }
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("application_hash/vectors.json")).unwrap();
        for case in vectors.as_array().unwrap() {
            let input = hex::decode(case["input_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                hex::encode(hash(&[&input])),
                case["output_hex"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
