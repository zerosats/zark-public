//! Complete affine addition with a directly constrained affine witness.
use bigcurve::{BigCurve, Secp256k1, Secp256k1Scalar};
use bignum::{BigNum, Secp256k1_Fq, Secp256k1_Fr};
use bignum::bignum::evaluate_quadratic_expression;
use std::ops::Neg;

unconstrained fn affine_witness(
    a: Secp256k1, b: Secp256k1, same_x: bool, denominator: Secp256k1_Fq,
) -> [Secp256k1_Fq; 3] {
    let numerator = if same_x { Secp256k1_Fq::from(3) * a.x * a.x } else { b.y - a.y };
    let slope = numerator / denominator;
    let x = slope*slope-a.x-b.x;
    let y = slope*(a.x-x)-a.y;
    [slope,x,y]
}

fn constrain_affine(
    a: Secp256k1, b: Secp256k1, same_x: bool, denominator: Secp256k1_Fq,
    witness: [Secp256k1_Fq; 3],
) -> Secp256k1 {
    let slope = witness[0];let x = witness[1];let y = witness[2];
    slope.validate_in_field();
    // Quadratic expressions range check the limbs independently. Require strict
    // coordinate bounds as well: validate_in_field permits MOD as zero, whose
    // bytes would not be a canonical Bitcoin coordinate.
    assert(x < Secp256k1_Fq::modulus(), "non-canonical addition x");
    assert(y < Secp256k1_Fq::modulus(), "non-canonical addition y");
    // The nonzero denominator makes the slope unique. In particular, opposite
    // points use the same dummy denominator as the original complete addition.
    assert(!denominator.is_zero());
    let tangent_x = if same_x { a.x } else { Secp256k1_Fq::zero() };
    let chord_y1 = if same_x { Secp256k1_Fq::zero() } else { a.y };
    let chord_y2 = if same_x { Secp256k1_Fq::zero() } else { b.y };
    // slope*denominator - 3*x1^2 (doubling), or
    // slope*denominator + y1-y2 (ordinary addition).
    evaluate_quadratic_expression(
        [[slope],[tangent_x]], [[false],[false]],
        [[denominator,Secp256k1_Fq::zero(),Secp256k1_Fq::zero()],
         [tangent_x,tangent_x,tangent_x]],
        [[false,false,false],[true,true,true]],
        [chord_y1,chord_y2], [false,true],
    );
    // Fusing these expressions avoids separately reducing every intermediate.
    evaluate_quadratic_expression(
        [[slope]], [[false]], [[slope]], [[false]],
        [x,a.x,b.x], [true,true,true],
    );
    evaluate_quadratic_expression(
        [[slope]], [[false]], [[a.x,x]], [[false,true]],
        [a.y,y], [true,true],
    );
    Secp256k1::from_coordinates(x,y,same_x & (a.y != b.y))
}

pub fn add(lhs: Secp256k1, rhs: Secp256k1) -> Secp256k1 {
    let a = if lhs.is_infinity { Secp256k1::one() } else { lhs };
    let b = if rhs.is_infinity { Secp256k1::one() } else { rhs };
    let same_x = a.x == b.x;
    let opposite = same_x & (a.y != b.y);
    let denominator = if same_x { Secp256k1_Fq::from(2) * a.y } else { b.x - a.x };
    let denominator = if opposite { Secp256k1_Fq::one() } else { denominator };
    // Safety: all three affine witness values are range checked and constrained
    // modulo the curve field; output coordinates are canonical. No Jacobian
    // conversion or incomplete MSM is assumed.
    let witness = unsafe { affine_witness(a,b,same_x,denominator) };
    let result = constrain_affine(a,b,same_x,denominator,witness);
    if lhs.is_infinity { rhs } else if rhs.is_infinity { lhs } else { result }
}

#[test(should_fail)]
fn rejects_wrong_slope() {
    let g = Secp256k1::one();
    let denominator = Secp256k1_Fq::from(2)*g.y;
    // Safety: the deliberately corrupted witness is checked below.
    let mut witness = unsafe { affine_witness(g,g,true,denominator) };
    witness[0] = witness[0]+Secp256k1_Fq::one();
    let _ = constrain_affine(g,g,true,denominator,witness);
}

#[test(should_fail)]
fn rejects_wrong_x() {
    let g = Secp256k1::one();
    let denominator = Secp256k1_Fq::from(2)*g.y;
    // Safety: the deliberately corrupted witness is checked below.
    let mut witness = unsafe { affine_witness(g,g,true,denominator) };
    witness[1] = witness[1]+Secp256k1_Fq::one();
    let _ = constrain_affine(g,g,true,denominator,witness);
}

#[test(should_fail)]
fn rejects_wrong_y() {
    let g = Secp256k1::one();
    let denominator = Secp256k1_Fq::from(2)*g.y;
    // Safety: the deliberately corrupted witness is checked below.
    let mut witness = unsafe { affine_witness(g,g,true,denominator) };
    witness[2] = witness[2]+Secp256k1_Fq::one();
    let _ = constrain_affine(g,g,true,denominator,witness);
}

#[test]
fn distinct_points_and_cancellation() {
    let g = Secp256k1::one();
    let two = add(g,g);
    let three = g.mul(Secp256k1Scalar::from_bignum(Secp256k1_Fr::from(3)));
    assert(add(g,two) == three);
    assert(add(two,g) == three);
    assert(add(two,g.neg()) == g);
    assert(add(g,two.neg()) == g.neg());
    assert(add(two,two.neg()).is_infinity);
    let zero = Secp256k1::point_at_infinity();
    assert(add(zero,zero).is_infinity);
}

#[test(should_fail)]
fn rejects_out_of_range_witness_limb() {
    let g = Secp256k1::one();
    let denominator = Secp256k1_Fq::from(2)*g.y;
    // Safety: the deliberately malformed witness is checked below.
    let mut witness = unsafe { affine_witness(g,g,true,denominator) };
    witness[0] = Secp256k1_Fq::from_limbs([340282366920938463463374607431768211455,0,0]);
    let _ = constrain_affine(g,g,true,denominator,witness);
}

#[test(should_fail)]
fn rejects_zero_denominator() {
    let g = Secp256k1::one();
    let _ = constrain_affine(g,g,true,Secp256k1_Fq::zero(),[Secp256k1_Fq::zero();3]);
}
