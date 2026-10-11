use bignum::{BigNum, Secp256k1_Fq, Secp256k1_Fr};
use crate::{BigCurve, Secp256k1};

pub(crate) global LAMBDA: Secp256k1_Fr = Secp256k1_Fr::from_limbs([0x2e22ea20816678df02967c1b23bd72, 0xad4cc05c30e0a5261c028812645a12, 0x5363]);
pub(crate) global MINUS_B1: Secp256k1_Fr = Secp256k1_Fr::from_limbs([0x437ed6010e88286f547fa90abfe4c3, 0xe4, 0x0]);
pub(crate) global MINUS_B2: Secp256k1_Fr = Secp256k1_Fr::from_limbs([0x280ac50774346dd765cda83db1562c, 0xfffffffffffffffffffffffffffe8a, 0xffff]);
pub(crate) global BETA: Secp256k1_Fq = Secp256k1_Fq::from_limbs([0xf0497512f58995c1396c28719501ee, 0x6a2b657c07106e64479eac3434e99c, 0x7ae9]);

// Independently computed from the pinned offset point O: 2^(4*(32-1))*O.
pub(crate) fn offset_final() -> Secp256k1 {
    Secp256k1::from_coordinates(
        Secp256k1_Fq::from_limbs([0xbc65f7de3f0d1eaa4f86fbcbf68e44, 0xa150fb6b7597cba3b03e65edf92df, 0x6d21]),
        Secp256k1_Fq::from_limbs([0xc81b9b5467a7684cd9787a880591d8, 0xedbe683ca19802fe4efbd51627abd2, 0xa8ba]),
        false,
    )
}

