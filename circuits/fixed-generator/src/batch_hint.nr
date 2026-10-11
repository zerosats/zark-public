//! Witness-only walk for the41 provably nonexceptional lower additions.
//! Complete top addition and skew correction use the pinned BigCurve operators.
use bignum::{BigNum, Secp256k1_Fq};
use bignum::bignum::batch_invert;
use crate::tables;

struct Jacobian { x: Secp256k1_Fq, y: Secp256k1_Fq, z: Secp256k1_Fq }
struct Step { point: Jacobian, numerator: Secp256k1_Fq }

unconstrained fn point(window: u32, index: u8, negative: bool) -> Jacobian {
    let row = tables::POINTS[window][index as u32];
    let y = Secp256k1_Fq::from_limbs(row[1]);
    Jacobian { x: Secp256k1_Fq::from_limbs(row[0]),
               y: if negative { -y } else { y }, z: Secp256k1_Fq::one() }
}

unconstrained fn mixed(a: Jacobian, b: Jacobian) -> Step {
    let z2 = a.z*a.z;
    let h = b.x*z2-a.x;
    let r = b.y*z2*a.z-a.y;
    let h2 = h*h;
    let h3 = h2*h;
    let u = a.x*h2;
    let x = r*r-h3-u-u;
    let y = r*(u-x)-a.y*h3;
    Step { point: Jacobian { x, y, z: a.z*h }, numerator: r }
}

pub unconstrained fn transcript(indices: [u8;42], negative: [bool;42]) -> [[Secp256k1_Fq;3];41] {
    let zero = Secp256k1_Fq::zero();
    let dummy = Step { point: Jacobian { x: zero, y: zero, z: zero }, numerator: zero };
    let mut steps = [dummy;41];
    let mut denominators = [Secp256k1_Fq::one();41];
    let mut accumulator = point(0,indices[0],negative[0]);
    for i in 1..42 {
        let step = mixed(accumulator,point(i,indices[i],negative[i]));
        steps[i-1] = step;
        denominators[i-1] = step.point.z;
        accumulator = step.point;
    }
    let inverse = batch_invert(denominators);
    let mut output = [[Secp256k1_Fq::zero();3];41];
    for i in 0..41 {
        let z = inverse[i];
        let z2 = z*z;
        output[i] = [steps[i].numerator*z, steps[i].point.x*z2, steps[i].point.y*z2*z];
    }
    output
}
