use bignum::{BigNum, Secp256k1_Fr};
use crate::glv_constants::{LAMBDA, MINUS_B1, MINUS_B2};

// libsecp256k1's fixed reciprocal split is witness generation only. The public
// constrained caller checks both magnitude bounds and the exact modular equation.
pub(crate) unconstrained fn split(k: Secp256k1_Fr) -> (Field, Field, bool, bool) {
    let bytes = k.to_le_bytes();
    let c1 = multiply_shift_round(bytes, [
        0xe893209a45dbb031, 0x3daa8a1471e8ca7f,
        0xe86c90e49284eb15, 0x3086d221a7d46bcd,
    ]);
    let c2 = multiply_shift_round(bytes, [
        0x1571b4ae8ac47f71, 0x221208ac9df506c6,
        0x6f547fa90abfe4c4, 0xe4437ed6010e8828,
    ]);
    let r2 = Secp256k1_Fr::from(c1) * MINUS_B1 + Secp256k1_Fr::from(c2) * MINUS_B2;
    let r1 = k - LAMBDA * r2;
    let (a, negative_a) = signed_magnitude(r1);
    let (b, negative_b) = signed_magnitude(r2);
    (a, b, negative_a, negative_b)
}

// Compute round(k * factor / 2^384), exactly as the upstream integer routine.
// Each schoolbook accumulator is bounded by (2^64-1)^2 + 2*(2^64-1)
// = 2^128-1, so the u128 addition cannot overflow.
unconstrained fn multiply_shift_round(k: [u8; 32], factor: [u64; 4]) -> Field {
    let mut limbs: [u64; 4] = [0; 4];
    for i in 0..4 {
        for j in 0..8 {
            limbs[i] = limbs[i] | ((k[i * 8 + j] as u64) << ((j * 8) as u64));
        }
    }
    let mut product: [u64; 8] = [0; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let partial = (limbs[i] as u128) * (factor[j] as u128)
                + (product[i + j] as u128) + carry;
            product[i + j] = partial as u64;
            carry = partial >> 64;
        }
        product[i + 4] = carry as u64;
    }
    (product[6] as Field) + (product[7] as Field) * 18446744073709551616
        + ((product[5] >> 63) as Field)
}

unconstrained fn signed_magnitude(value: Secp256k1_Fr) -> (Field, bool) {
    // The bignum library also represents zero as n. Normalize that case before
    // extracting the 128-bit magnitude; the constrained relation is modulo n.
    let value = if value == Secp256k1_Fr::zero() { Secp256k1_Fr::zero() } else { value };
    let bytes = value.to_be_bytes();
    let mut upper_zero = true;
    for i in 0..16 { upper_zero = upper_zero & (bytes[i] == 0); }
    let negative = !upper_zero;
    let magnitude = if negative { -value } else { value };
    let bytes = magnitude.to_be_bytes();
    let mut result: Field = 0;
    for i in 0..16 { assert(bytes[i] == 0, "GLV hint magnitude exceeds128bits"); }
    for i in 16..32 { result = result * 256 + bytes[i] as Field; }
    (result, negative)
}
