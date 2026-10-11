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
    let raw = fixed_generator_host(indices,negative);
    let mut output = [[Secp256k1_Fq::zero();3];41];
    for i in 0..41 {
        let offset = i*9;
        output[i] = [
            Secp256k1_Fq::from_limbs([raw[offset],raw[offset+1],raw[offset+2]]),
            Secp256k1_Fq::from_limbs([raw[offset+3],raw[offset+4],raw[offset+5]]),
            Secp256k1_Fq::from_limbs([raw[offset+6],raw[offset+7],raw[offset+8]]),
        ];
    }
    output
}

// The deterministic local calculation returns untrusted witness values only.
// All41 affine equations/canonical guards and the complete top add remain in
// the unchanged constrained caller. No private values may leave loopback.
#[pure]
#[oracle(zark_fixed_generator_hint_v1)]
unconstrained fn fixed_generator_host(indices: [u8;42], negative: [bool;42]) -> [u128;369] {}
