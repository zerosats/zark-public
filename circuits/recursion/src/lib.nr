// Pinned recursive proof verification and verification-key hashing.
pub fn hash<let N: u32>(values: [Field; N]) -> Field {
    let mut state = [0, 0, 0, (N as Field) * 18446744073709551616];
    for i in 0..N {
        state[i % 3] += values[i];
        if i % 3 == 2 { state = std::hash::poseidon2_permutation(state); }
    }
    if N % 3 != 0 { state = std::hash::poseidon2_permutation(state); }
    state[0]
}

pub fn verify_zk<let N: u32>(vk: [Field;115], proof: [Field;458], inputs: [Field;N], approved: Field, key_hash: Field) {
    let actual = hash(vk);
    assert(actual == approved, "unapproved verification key");
    assert(key_hash == actual, "verification key hash");
    // This literal is the v5.2.0 ZK UltraHonk proof type, not type 0 (non-ZK).
    std::verify_proof_with_type(vk, proof, inputs, key_hash, 6);
}
