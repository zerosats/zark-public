//! Research-only application commitments, paired with protocol version 10.
//! Bitcoin SHA256, SHA256d and tagged hashes must never call this module.
//!
//! Width four, rate two, capacity two. The entire canonical application
//! preimage retains its purpose tag, context, version and salt bytes.
//! One field output or rate-three/capacity-one squeezing would retain only
//! about 126.8 bits of generic collision security over the BN254 field.
//! Here two 128-bit output portions retain the 32-byte application ABI and
//! target about 128-bit collision security, assuming the pinned permutation.
//! This construction has not received independent cryptographic audit.

// ASCII "ZARK/app-commit/p2/v1", interpreted as one big-endian integer.
// The final v1 versions this sponge construction, not the statement protocol.
global DOMAIN: Field = 0x5a41524b2f6170702d636f6d6d69742f70322f7631;

fn encode<let N: u32>(bytes: [u8; N], domain: Field)
    -> [Field; (((N + 30) / 31 + 4) / 2) * 2] {
    let mut words = [0 as Field; (((N + 30) / 31 + 4) / 2) * 2];
    words[0] = domain;
    words[1] = N as Field;
    // Every chunk is at most 248 bits, so this packing cannot reduce modulo p.
    // The final chunk uses its actual bytes, without implicit zero padding.
    // The explicit byte length disambiguates leading zeroes and short chunks.
    for i in 0..N {
        words[2 + i / 31] = words[2 + i / 31] * 256 + bytes[i] as Field;
    }
    // Injective field padding: one, followed by zero if needed to fill a pair.
    // The last block is always nonzero, including for an empty byte string.
    words[2 + (N + 30) / 31] = 1;
    words
}

fn low128(value: Field) -> [u8; 16] {
    // The pinned standard-library helper range-checks both 128-bit limbs,
    // reconstructs value, and constrains the integer decomposition strictly
    // below p. Reconstruction alone would allow an unsound value+p alias.
    let (low, _) = std::field::bn254::decompose(value);
    low.to_be_bytes::<16>()
}

fn digest_in_domain<let N: u32>(bytes: [u8; N], domain: Field) -> [u8; 32] {
    let words = encode(bytes, domain);
    let mut state = [0 as Field; 4];
    for i in 0..(words.len() / 2) {
        state[0] += words[2 * i];
        state[1] += words[2 * i + 1];
        state = std::hash::poseidon2_permutation(state);
    }
    let first = low128(state[0]);
    let second = low128(state[1]);
    let mut output = [0 as u8; 32];
    for i in 0..16 {
        output[i] = first[i];
        output[16 + i] = second[i];
    }
    output
}

pub fn digest<let N: u32>(bytes: [u8; N]) -> [u8; 32] {
    digest_in_domain(bytes, DOMAIN)
}

#[test]
fn domain_encoding_is_literal() {
    assert(DOMAIN == Field::from_be_bytes("ZARK/app-commit/p2/v1".as_bytes()));
}

#[test]
fn be31_encoding_and_padding_boundaries() {
    assert(encode([], DOMAIN) == [DOMAIN, 0, 1, 0]);
    assert(encode([1 as u8], DOMAIN) == [DOMAIN, 1, 1, 1]);
    assert(encode([0 as u8, 1], DOMAIN) == [DOMAIN, 2, 1, 1]);
    let maximal = encode([255 as u8; 31], DOMAIN);
    assert(maximal == [DOMAIN, 31,
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, 1]);
    let mut boundary = [0 as u8; 32];
    boundary[30] = 2;
    boundary[31] = 3;
    assert(encode(boundary, DOMAIN) == [DOMAIN, 32, 2, 3, 1, 0]);
    assert(encode([0 as u8; 61], DOMAIN) == [DOMAIN, 61, 0, 0, 1, 0]);
    assert(encode([0 as u8; 62], DOMAIN) == [DOMAIN, 62, 0, 0, 1, 0]);
    assert(encode([0 as u8; 63], DOMAIN) == [DOMAIN, 63, 0, 0, 0, 1]);
    assert(encode([0 as u8; 93], DOMAIN) == [DOMAIN, 93, 0, 0, 0, 1]);
}

#[test]
fn byte_encoding_never_reduces_a_32_byte_chunk_modulo_p() {
    let modulus: [u8; 32] = std::field::modulus_be_bytes().as_array();
    assert(Field::from_be_bytes(modulus) == 0);
    assert(encode(modulus, DOMAIN) != encode([0 as u8; 32], DOMAIN));
    assert(digest(modulus) != digest([0 as u8; 32]));
}

#[test]
fn low128_is_the_canonical_integer_tail() {
    let two128: Field = 0x100000000000000000000000000000000;
    for value in [0 as Field, 1, two128 - 1, two128, two128 + 1, -1] {
        let canonical = value.to_be_bytes::<32>();
        let tail = low128(value);
        for i in 0..16 { assert(tail[i] == canonical[16 + i]); }
    }
    assert(low128(0) == [0 as u8; 16]);
    assert(low128(two128) == [0 as u8; 16]);
    assert(low128(two128 - 1) == [255 as u8; 16]);
}

#[test(should_fail)]
fn zero_does_not_accept_the_modulus_low_limb() {
    let modulus: [u8; 32] = std::field::modulus_be_bytes().as_array();
    let mut false_tail = [0 as u8; 16];
    for i in 0..16 { false_tail[i] = modulus[16 + i]; }
    // Zero and p reconstruct to the same field, but only integer zero is a
    // canonical representation. Merely constraining reconstruction would
    // permit this false claim and change the commitment's output bytes.
    assert(low128(0) == false_tail);
}

#[test(should_fail)]
fn one_does_not_accept_modulus_plus_one_low_limb() {
    let modulus: [u8; 32] = std::field::modulus_be_bytes().as_array();
    let mut false_tail = [0 as u8; 16];
    for i in 0..16 { false_tail[i] = modulus[16 + i]; }
    // BN254 p ends in byte 1, so this increment cannot overflow the byte.
    false_tail[15] += 1;
    assert(low128(1) == false_tail);
}

#[test]
fn lengths_and_all_byte_positions_are_bound() {
    assert(digest([]) != digest([0 as u8]));
    assert(digest([1 as u8]) != digest([0 as u8, 1]));
    assert(digest([1 as u8]) != digest([1 as u8, 0]));
    let baseline = [0 as u8; 63];
    let expected = digest(baseline);
    for i in [0, 30, 31, 61, 62] {
        let mut changed = baseline;
        changed[i] = 1;
        assert(digest(changed) != expected);
    }
}

#[test]
fn application_domains_and_suite_versions_are_bound() {
    let bytes = "ZARK/private-handoff/state/v1".as_bytes();
    assert(digest(bytes) != digest_in_domain(bytes, DOMAIN + 1));
    assert(digest(bytes) != digest("ZARK/private-handoff/nonce/v1".as_bytes()));
    assert(digest([9 as u8, 0, 0, 0]) != digest([10 as u8, 0, 0, 0]));
}

// Independently generated Python vectors. The oracle was first checked against
// five pinned Noir permutation vectors and three pinned stock-sponge vectors.
#[test]
fn independent_python_golden_vectors() {
    assert(digest([]) == [0x50,0x85,0xb9,0xef,0x69,0x9f,0x5b,0x74,0xb1,0xf7,0x6f,0x2a,0xcc,0xc1,0x30,0x26,0x42,0x4d,0x72,0xf6,0x81,0x67,0x4f,0x80,0x56,0x2c,0x99,0x88,0x88,0x3b,0x40,0x14]);
    assert(digest("abc".as_bytes()) == [0xd4,0xba,0x78,0x39,0x07,0x77,0xc6,0x33,0xc5,0xd0,0x9c,0xbd,0x88,0x2e,0xbc,0x49,0xc6,0x89,0xb7,0xef,0x20,0x3e,0x74,0x18,0xfc,0x47,0xf6,0xfc,0xbe,0xf9,0x37,0xc1]);
    let mut range32 = [0 as u8; 32];
    for i in 0..32 { range32[i] = i as u8; }
    assert(digest(range32) == [0x54,0x77,0x81,0xb2,0xc9,0x25,0x34,0x2d,0x4b,0x0f,0xa7,0x67,0x2c,0x4e,0xba,0x25,0xd5,0x30,0xff,0x9f,0x63,0x98,0x08,0x0f,0x52,0xcd,0x29,0x2d,0xa4,0xe0,0x66,0xb3]);
    let mut range63 = [0 as u8; 63];
    for i in 0..63 { range63[i] = i as u8; }
    assert(digest(range63) == [0xb9,0xa1,0xba,0x72,0xb7,0xad,0xfc,0x47,0x17,0x25,0x18,0x73,0x37,0xf4,0x0c,0x70,0x83,0x5d,0x5d,0x10,0x87,0xb2,0x5c,0xd8,0x93,0xb9,0xc0,0xcb,0x46,0x7c,0xd3,0x22]);
    let tag = "ZARK/private-handoff/state/v1".as_bytes();
    assert(tag.len() == 29);
    let mut state_message = [0 as u8; 33];
    for i in 0..tag.len() { state_message[i] = tag[i]; }
    state_message[tag.len()] = 10;
    assert(digest(state_message) == [0xf4,0xc5,0x43,0xf7,0x06,0x02,0xc0,0x58,0xdd,0xd2,0x88,0xb2,0x80,0xe8,0x91,0xe5,0x0c,0x49,0x0c,0x1e,0x70,0x33,0x6f,0x93,0xa2,0x30,0x4f,0x5a,0x88,0xb7,0x8b,0xca]);
}
