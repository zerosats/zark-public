use bignum::{BigNum, Secp256k1_Fr};
use crate::{BigCurve, ScalarField, Secp256k1};
use crate::glv_constants::LAMBDA;

/// Exact scalar multiplication research candidate. All split and affine
/// transcript hints are untrusted and checked in constrained code.
pub fn mul(point: Secp256k1, scalar: Secp256k1_Fr) -> Secp256k1 {
    scalar.validate_in_field();
    // Safety: bounded magnitudes and signed modular recomposition checked below.
    let (a, b, negative_a, negative_b) = unsafe { crate::glv_split::split(scalar) };
    mul_with_split(point, scalar, a, b, negative_a, negative_b)
}

/// Exposes the untrusted decomposition for adversarial research tests. There is
/// no uniqueness requirement: every accepted split yields the same group result.
pub fn mul_with_split(
    point: Secp256k1, scalar: Secp256k1_Fr,
    a: Field, b: Field, negative_a: bool, negative_b: bool,
) -> Secp256k1 {
    let (first,scalars,negate_second) = prepare_split(point,scalar,a,b,negative_a,negative_b);
    crate::glv_msm::evaluate(first,scalars,negate_second)
}

/// Research-test hook selecting a particular offset. Identical input/split and
/// replay checks apply; a bad selector must fail the constrained denominator.
pub fn mul_with_selector(point: Secp256k1, scalar: Secp256k1_Fr, index: u8) -> Secp256k1 {
    scalar.validate_in_field();
    // Safety: prepare_split constrains the magnitude bounds and modular relation.
    let (a,b,negative_a,negative_b) = unsafe { crate::glv_split::split(scalar) };
    let (first,scalars,negate_second) = prepare_split(point,scalar,a,b,negative_a,negative_b);
    crate::glv_msm::evaluate_with_selector(first,scalars,negate_second,index)
}

/// Isolated research-only adversarial hook. The ordinary multiplier never calls
/// this function. It changes untrusted witness data before identical replay.
pub fn mul_with_selector_test(
    point: Secp256k1, scalar: Secp256k1_Fr,
    actual_index: u8, claimed_index: u8, mutation: u8,
) -> Secp256k1 {
    scalar.validate_in_field();
    // Safety: prepare_split constrains the magnitude bounds and modular relation.
    let (a,b,negative_a,negative_b) = unsafe { crate::glv_split::split(scalar) };
    let (first,scalars,negate_second) = prepare_split(point,scalar,a,b,negative_a,negative_b);
    crate::glv_msm::evaluate_with_selector_test(first,scalars,negate_second,actual_index,claimed_index,mutation)
}

pub(crate) fn prepare_split(
    point: Secp256k1, scalar: Secp256k1_Fr,
    a: Field, b: Field, negative_a: bool, negative_b: bool,
) -> (Secp256k1,[ScalarField<32>;2],bool) {
    scalar.validate_in_field();
    point.x.validate_in_field();
    point.y.validate_in_field();
    point.validate_on_curve();
    a.assert_max_bit_size::<128>();
    b.assert_max_bit_size::<128>();
    let a_fr = Secp256k1_Fr::from(a);
    let b_fr = Secp256k1_Fr::from(b);
    let signed_a = if negative_a { -a_fr } else { a_fr };
    let signed_b = if negative_b { -b_fr } else { b_fr };
    assert(scalar == signed_a + LAMBDA * signed_b, "GLV scalar decomposition mismatch");

    // The second table is phi(first), with an extra sign exactly when the two
    // component signs differ. Infinity is normalized before either table exists.
    let first = Secp256k1::from_coordinates(
        point.x, if negative_a { -point.y } else { point.y }, point.is_infinity,
    );
    let scalars: [ScalarField<32>; 2] = [ScalarField::from(a), ScalarField::from(b)];
    (first,scalars,negative_a != negative_b)
}

/// Allows independent scalar-split oracle checks without running curve arithmetic.
pub unconstrained fn split_hint(scalar: Secp256k1_Fr) -> (Field, Field, bool, bool) {
    crate::glv_split::split(scalar)
}

#[test]
unconstrained fn glv_split_known_values() {
    assert(split_hint(Secp256k1_Fr::zero()) == (0, 0, false, false));
    assert(split_hint(Secp256k1_Fr::one()) == (1, 0, false, false));
    assert(split_hint(-Secp256k1_Fr::one()) == (1, 0, true, false));
    assert(split_hint(LAMBDA) == (0, 1, false, false));
    assert(split_hint(-LAMBDA) == (0, 1, false, true));
    assert(split_hint(Secp256k1_Fr::modulus()) == (0, 0, false, false));
}

#[test]
fn glv_native_recoding_boundaries() {
    let values: [Field; 5] = [0, 1, 2, 340282366920938463463374607431768211454, 340282366920938463463374607431768211455];
    for value in values {
        value.assert_max_bit_size::<128>();
        let encoded: ScalarField<32> = ScalarField::from(value);
        let decoded: Field = encoded.into();
        assert(decoded == value);
    }
}
