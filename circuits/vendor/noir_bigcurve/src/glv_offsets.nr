use bignum::{BigNum, Secp256k1_Fq};
use crate::{BigCurve, Secp256k1};

/// Both immutable points are selected by exactly the same constrained byte.
/// POINTS[j][0]=(j+1)*O, POINTS[j][1]=2^124*(j+1)*O.
pub(crate) fn pair(index: u8) -> (Secp256k1, Secp256k1) {
    (index as Field).assert_max_bit_size::<8>();
    let row = crate::glv_offset_table::POINTS[index as u32];
    let initial = Secp256k1::from_coordinates(
        Secp256k1_Fq::from_limbs(row[0][0]), Secp256k1_Fq::from_limbs(row[0][1]), false,
    );
    let final_point = Secp256k1::from_coordinates(
        Secp256k1_Fq::from_limbs(row[1][0]), Secp256k1_Fq::from_limbs(row[1][1]), false,
    );
    (initial,final_point)
}

/// The 512-entry bank for the six-column batch walk; its first 256 rows are
/// exactly the bank above. POINTS[j][0]=(j+1)*O, POINTS[j][1]=2^124*(j+1)*O.
pub(crate) fn pair_wide(index: u16) -> (Secp256k1, Secp256k1) {
    (index as Field).assert_max_bit_size::<9>();
    let row = crate::glv_offset_table_wide::POINTS[index as u32];
    let initial = Secp256k1::from_coordinates(
        Secp256k1_Fq::from_limbs(row[0][0]), Secp256k1_Fq::from_limbs(row[0][1]), false,
    );
    let final_point = Secp256k1::from_coordinates(
        Secp256k1_Fq::from_limbs(row[1][0]), Secp256k1_Fq::from_limbs(row[1][1]), false,
    );
    (initial,final_point)
}
