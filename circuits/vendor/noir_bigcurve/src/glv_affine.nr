//! GLV-only incomplete affine replay with exact non-native-field inequality.
//! The generic library path remains untouched for an unchanged micro baseline.
use bignum::{BigNum, Secp256k1_Fq};
use bignum::bignum::evaluate_quadratic_expression;
use crate::{BigCurve, Secp256k1};
use crate::curve_jac::types::AffineTranscript;

type Fq = Secp256k1_Fq;
type P = Secp256k1;

pub(crate) fn add(point: P, other: P, transcript: AffineTranscript<Fq>) -> P {
    assert(!point.is_infinity & !other.is_infinity, "GLV finite add operands");
    let x1 = point.x; let y1 = point.y;
    let x2 = other.x; let y2 = other.y;
    let lambda = transcript.lambda; let x3 = transcript.x3; let y3 = transcript.y3;
    x3.validate_in_range(); y3.validate_in_range(); lambda.validate_in_range();
    // Exact modular Fq equality, not compressed equality in the circuit field.
    assert(x1 != x2, "GLV nonzero add denominator");
    evaluate_quadratic_expression(
        [[lambda]], [[false]], [[x2,x1]], [[false,true]], [y2,y1], [true,false],
    );
    evaluate_quadratic_expression(
        [[lambda]], [[false]], [[lambda]], [[false]], [x3,x2,x1], [true,true,true],
    );
    evaluate_quadratic_expression(
        [[lambda]], [[false]], [[x3,x1]], [[false,true]], [y3,y1], [false,false],
    );
    P::from_coordinates(x3,y3,false)
}

pub(crate) fn subtract(point: P, other: P, transcript: AffineTranscript<Fq>) -> P {
    assert(!point.is_infinity & !other.is_infinity, "GLV finite subtract operands");
    let x1 = point.x; let y1 = point.y;
    let x2 = other.x; let y2 = other.y;
    let lambda = transcript.lambda; let x3 = transcript.x3; let y3 = transcript.y3;
    x3.validate_in_range(); y3.validate_in_range(); lambda.validate_in_range();
    assert(x1 != x2, "GLV nonzero subtract denominator");
    evaluate_quadratic_expression(
        [[lambda]], [[false]], [[x2,x1]], [[false,true]], [y2,y1], [false,false],
    );
    evaluate_quadratic_expression(
        [[lambda]], [[false]], [[lambda]], [[false]], [x3,x2,x1], [true,true,true],
    );
    evaluate_quadratic_expression(
        [[lambda]], [[false]], [[x3,x1]], [[false,true]], [y3,y1], [false,false],
    );
    P::from_coordinates(x3,y3,false)
}
