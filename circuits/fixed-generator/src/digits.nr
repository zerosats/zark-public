use bignum::{BigNum, Secp256k1_Fr};

pub fn read(bytes: [u8;32]) -> ([u8;42], [bool;42], u8, bool) {
    let scalar = Secp256k1_Fr::from_be_bytes(bytes);
    assert(scalar < Secp256k1_Fr::modulus(), "non-canonical scalar");

    // Every raw radix64 digit comes directly from constrained byte bits. This
    // is exact integer reconstruction, never equality of 256-bit values modulo
    // the circuit field. Bits above bit255 are literal zero.
    let mut raw = [0 as u8;43];
    for i in 0..43 {
        let mut digit = 0 as u8;
        for j in 0..6 {
            let index = 6*i+j;
            if index < 256 {
                digit = digit | (((bytes[31-index/8] >> ((index%8) as u8)) & 1) << (j as u8));
            }
        }
        raw[i] = digit;
    }
    assert(raw[42] < 16, "top scalar padding");
    let mut indices = [0 as u8;42];
    let mut negative = [false;42];
    for i in 0..42 {
        let sign = (raw[i+1] & 1) == 0;
        let half = raw[i] >> 1;
        indices[i] = if sign { 31-half } else { half };
        negative[i] = sign;
    }
    // Let c_i=1-parity(raw_i), c_43=0 and d_i=raw_i+c_i-64*c_(i+1).
    // Lower d_i are nonzero odd values in[-63,63]; d_42 is positive odd1..15.
    // Telescoping over integer powers gives sum_i d_i*64^i = k+c_0.
    // indices[i] encodes (abs(d_i)-1)/2 and negative[i] encodes d_i<0.
    (indices, negative, raw[42] >> 1, (raw[0] & 1) == 0)
}

#[test]
fn signed_zero_recoding() {
    let (indices, negative, top_index, skew) = read([0;32]);
    assert(indices == [31;42]);
    assert(negative == [true;42]);
    assert(top_index == 0);
    assert(skew);
}

#[test]
fn signed_one_recoding() {
    let mut bytes = [0 as u8;32]; bytes[31] = 1;
    let (indices, negative, top_index, skew) = read(bytes);
    assert(indices == [31;42]);
    assert(negative == [true;42]);
    assert(top_index == 0);
    assert(!skew);
}

#[test(should_fail_with = "non-canonical scalar")]
fn rejects_order() { let _ = read(Secp256k1_Fr::modulus().to_be_bytes()); }
