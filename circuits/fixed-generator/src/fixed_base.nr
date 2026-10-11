use bigcurve::{BigCurve, Secp256k1};
use bignum::{BigNum, Secp256k1_Fq};
use crate::{digits, positional_add, tables};

unconstrained fn split240(value: Field) -> [u128;2] {
    let bytes = value.to_le_bytes::<30>();
    let mut low = 0 as u128; let mut high = 0 as u128;
    for i in 0..15 {
        low = low + (bytes[i] as u128)*(1 as u128 << ((8*i) as u128));
        high = high + (bytes[i+15] as u128)*(1 as u128 << ((8*i) as u128));
    }
    [low,high]
}

unconstrained fn split32(value: Field) -> [u16;2] {
    let bytes = value.to_le_bytes::<4>();
    [bytes[0] as u16+256*(bytes[1] as u16),bytes[2] as u16+256*(bytes[3] as u16)]
}

fn unpack(value: [Field;3]) -> [[u128;3];2] {
    // Safety: each120-bit component is bounded and exactly reconstructed below.
    let x = unsafe { split240(value[0]) };
    // Safety: each120-bit component is bounded and exactly reconstructed below.
    let y = unsafe { split240(value[1]) };
    // Safety: both16-bit components are bounded and exactly reconstructed below.
    let high = unsafe { split32(value[2]) };
    for limb in [x[0],x[1],y[0],y[1]] { assert(limb < (1 as u128 << 120)); }
    (high[0] as Field).assert_max_bit_size::<16>();
    (high[1] as Field).assert_max_bit_size::<16>();
    // The reconstructed values are <2^240 and <2^32, below the native modulus;
    // these are unique integer decompositions, not modular packing aliases.
    assert(value[0] == x[0] as Field + 1329227995784915872903807060280344576*(x[1] as Field));
    assert(value[1] == y[0] as Field + 1329227995784915872903807060280344576*(y[1] as Field));
    assert(value[2] == high[0] as Field + 65536*(high[1] as Field));
    [[x[0],x[1],high[0] as u128],[y[0],y[1],high[1] as u128]]
}

fn select(window: u32, index: u8, negative: bool) -> Secp256k1 {
    assert(index < 32,"table index range");
    let coordinates = unpack(tables::PACKED_POINTS[window][index as u32]);
    let y = Secp256k1_Fq::from_limbs(coordinates[1]);
    Secp256k1::from_coordinates(
        Secp256k1_Fq::from_limbs(coordinates[0]),if negative { -y } else { y },false,
    )
}

fn top_point(index: u8, skew: bool) -> Secp256k1 {
    assert(index < 8,"top table index range");
    // The constrained boolean selects exactly one immutable correction.
    let slot = 2*(index as u32) + (skew as u32);
    let coordinates = unpack(tables::PACKED_TOP[slot]);
    Secp256k1::from_coordinates(
        Secp256k1_Fq::from_limbs(coordinates[0]),Secp256k1_Fq::from_limbs(coordinates[1]),false,
    )
}

pub fn mul_generator(bytes: [u8;32]) -> Secp256k1 {
    let (indices,negative,top_index,skew) = digits::read(bytes);
    // Safety: all41 hints are checked by the qualified affine equations and
    // unchanged canonical coordinate/slope constraints.
    let hints = unsafe { crate::batch_hint::transcript(indices,negative) };
    let mut accumulator = select(0,indices[0],negative[0]);
    // For i<=41, |S_i|<64^i<=|newterm| and S_i is odd/nonzero. Furthermore
    // |S_i +/- newterm|<64^(i+1)<=2^252<n, excluding equal/inverse operands.
    for i in 1..42 {
        accumulator = positional_add::combine_hint(
            accumulator,select(i,indices[i],negative[i]),hints[i-1],
        );
    }
    // The lower sum plus d42*2^252 is k+skew. The selected immutable
    // top point is[d42*2^252-skew]G, so one complete addition yields kG.
    // Its operands may double or cancel (k=0); this operation stays complete.
    accumulator + top_point(top_index,skew)
}

#[test(should_fail_with = "table index range")]
fn rejects_out_of_table_index() { let _ = select(0,32,false); }

#[test(should_fail_with = "top table index range")]
fn rejects_out_of_top_table_index() { let _ = top_point(8,false); }
