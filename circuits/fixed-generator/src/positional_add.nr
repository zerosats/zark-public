//! Valid only for the signed-prefix schedule proved in fixed_base. The explicit
//! denominator check uses complete field equality, not native-field compression.
use bigcurve::{BigCurve, Secp256k1};
use bignum::{BigNum, Secp256k1_Fq};
use bignum::bignum::evaluate_quadratic_expression;

/// Specialized exact canonicality guard for secp256k1 Fq. All input limbs
/// retain their120/120/16-bit checks; no canonicality assumption is introduced.
/// Inclusive mode matches the pinned slope guard, which accepts p as zero.
pub fn assert_canonical(value: Secp256k1_Fq, inclusive: bool) {
    value.validate_in_range();
    let top = (value.get_limb(2) == 65535)
        & (value.get_limb(1) == 0xffffffffffffffffffffffffffffff);
    // Let B=2^120,c=2^32+977. If the upper limbs are not both maximal,
    // value<p automatically. Otherwise strictness is low+c<B (or low+c-1<B
    // for inclusive<=p). The sum is nonnegative and below2^121, hence below
    // the native modulus: this120-bit range constraint is an integer bound.
    let boundary = if top {
        (value.get_limb(0) as Field) + 4294968273 - (inclusive as Field)
    } else { 0 };
    boundary.assert_max_bit_size::<120>();
}

/// Crate-private signed-G lower-step helper: both operands must be on curve
/// with canonical x coordinates. The only production caller starts from
/// audited immutable ROM points (exactly unpacked), and each recurrence
/// preserves canonical x through the strict output guard below. Negating
/// a selected y leaves x unchanged. Under this constrained induction,
/// equality modulo p is exactly equality of all three120/120/16 limbs.
/// Do not reuse this denominator check for generic Fq representations.
pub(crate) fn combine_hint(a: Secp256k1, b: Secp256k1, values: [Secp256k1_Fq;3]) -> Secp256k1 {
    assert(!a.is_infinity & !b.is_infinity, "finite affine operands");
    assert((a.x.get_limb(0) != b.x.get_limb(0))
        | (a.x.get_limb(1) != b.x.get_limb(1))
        | (a.x.get_limb(2) != b.x.get_limb(2)), "nonzero affine denominator");
    let slope = values[0]; let x = values[1]; let y = values[2];
    assert_canonical(slope,true);
    assert_canonical(x,false);
    assert_canonical(y,false);
    evaluate_quadratic_expression(
        [[slope]], [[false]], [[b.x,a.x]], [[false,true]],
        [a.y,b.y], [false,true],
    );
    evaluate_quadratic_expression(
        [[slope]], [[false]], [[slope]], [[false]],
        [x,a.x,b.x], [true,true,true],
    );
    evaluate_quadratic_expression(
        [[slope]], [[false]], [[a.x,x]], [[false,true]],
        [a.y,y], [true,true],
    );
    Secp256k1::from_coordinates(x,y,false)
}

#[test(should_fail_with = "nonzero affine denominator")]
fn rejects_equal_operands() {
    let g = Secp256k1::one();
    let _ = combine_hint(g,g,[Secp256k1_Fq::zero();3]);
}

#[test]
fn canonical_zero() {
    assert_canonical(Secp256k1_Fq::zero(),false);
    assert_canonical(Secp256k1_Fq::zero(),true);
}

#[test]
fn accepts_inclusive_modulus_alias() { assert_canonical(Secp256k1_Fq::modulus(),true); }

#[test(should_fail)]
fn rejects_strict_modulus_alias() { assert_canonical(Secp256k1_Fq::modulus(),false); }

#[test(should_fail)]
fn rejects_malformed_high_limb() {
    assert_canonical(Secp256k1_Fq::from_limbs([0,0,65536]),false);
}
