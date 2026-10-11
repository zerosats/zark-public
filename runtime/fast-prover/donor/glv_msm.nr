use bignum::{BigNum, Secp256k1_Fq};
use crate::{BigCurve, ScalarField, Secp256k1};
use crate::curve_jac::types::{AffineTranscript, CurveJ, JTranscript};
use crate::curve_jac::point_table::PointTable as JPointTable;
use crate::ops::point_table::PointTable;
use crate::ops::affine::{double_with_hint, sub_with_hint};

type Fq = Secp256k1_Fq;
type P = Secp256k1;
type J = CurveJ<Fq, P>;
type A = AffineTranscript<Fq>;
type T = JTranscript<Fq>;
global ENTRIES: u32 = 199;

fn normalize(mut first: P, mut scalars: [ScalarField<32>;2], negate_second: bool) -> ([P;2],[ScalarField<32>;2]) {
    if first.is_infinity {
        first = P::one();
        scalars = [ScalarField::zero(); 2];
    }
    let second = P::from_coordinates(
        first.x * crate::glv_constants::BETA,
        if negate_second { -first.y } else { first.y }, false,
    );
    ([first,second],scalars)
}

pub(crate) fn evaluate(first: P, scalars: [ScalarField<32>;2], negate_second: bool) -> P {
    let (points,scalars) = normalize(first,scalars,negate_second);
    // Safety: the private selector binds both immutable offsets, and every
    // transcript operation is replayed with exact nonzero-denominator checks.
    let (index,transcript) = unsafe { hint(points,scalars,negate_second) };
    evaluate_with_transcript(points,scalars,negate_second,index,transcript)
}

pub(crate) fn evaluate_with_selector(first: P, scalars: [ScalarField<32>;2], negate_second: bool, index: u8) -> P {
    let (points,scalars) = normalize(first,scalars,negate_second);
    // Safety: even a bad selector reaches the identical constrained replay.
    // A partial hint is intentional here so tests exercise the constraints.
    let transcript = unsafe { fixed_hint(points,scalars,negate_second,index) };
    evaluate_with_transcript(points,scalars,negate_second,index,transcript)
}

// Research-only witness tampering hook; no alternative replay constraints.
pub(crate) fn evaluate_with_selector_test(
    first: P, scalars: [ScalarField<32>;2], negate_second: bool,
    actual_index: u8, claimed_index: u8, mutation: u8,
) -> P {
    assert(mutation <= 3,"GLV unknown transcript mutation");
    let (points,scalars) = normalize(first,scalars,negate_second);
    // Safety: deliberately untrusted test data is checked by the identical replay.
    let mut transcript = unsafe { fixed_hint(points,scalars,negate_second,actual_index) };
    if mutation == 1 { transcript[198].x3 = transcript[198].x3 + Fq::one(); }
    if mutation == 2 { transcript[100].x3 = transcript[100].x3 + Fq::one(); }
    if mutation == 3 { transcript[10].lambda = transcript[10].lambda + Fq::one(); }
    evaluate_with_transcript(points,scalars,negate_second,claimed_index,transcript)
}

pub(crate) unconstrained fn fixed_hint(points: [P;2], scalars: [ScalarField<32>;2], negate_second: bool, index: u8) -> [A;ENTRIES] {
    let (_,transcript) = local_hint(points,scalars,negate_second,true,index);
    transcript
}

pub(crate) fn evaluate_with_transcript(
    points: [P;2], scalars: [ScalarField<32>;2], negate_second: bool,
    index: u8, transcript: [A;ENTRIES],
) -> P {
    let (initial_offset,final_offset) = crate::glv_offsets::pair(index);
    let mut tables: [PointTable<Fq>;2] = [PointTable::empty();2];
    let mut table_tx = [A::new();8];
    for j in 0..8 { table_tx[j] = transcript[j]; }
    tables[0] = PointTable::new_with_exact_hint(points[0],table_tx);
    tables[1] = tables[0].endomorphism(crate::glv_constants::BETA,negate_second);
    let mut accumulator = initial_offset;
    let mut ptr: u32 = 8;
    for j in 0..2 {
        accumulator = crate::glv_affine::add(
            accumulator,tables[j].get::<P>(scalars[j].base4_slices[0] as u32),transcript[ptr],
        );
        ptr += 1;
    }
    for i in 1..32 {
        for _ in 0..4 {
            // Exact inequality on every addition excludes both doubling and
            // cancellation. Thus the accumulator stays finite; finite points
            // in the odd-prime-order secp256k1 group cannot double to infinity.
            accumulator = double_with_hint::<Fq,P>(accumulator,transcript[ptr]);
            ptr += 1;
        }
        for j in 0..2 {
            accumulator = crate::glv_affine::add(
                accumulator,tables[j].get::<P>(scalars[j].base4_slices[i] as u32),transcript[ptr],
            );
            ptr += 1;
        }
    }
    for j in 0..2 {
        // This check is unconditional even when skew=false; selector search
        // must avoid these two denominators as well as all64 addition checks.
        let corrected = crate::glv_affine::subtract(accumulator,points[j],transcript[ptr]);
        accumulator = if scalars[j].skew { corrected } else { accumulator };
        ptr += 1;
    }
    assert(ptr == ENTRIES-1);
    // Removing the matching offset may legitimately produce infinity.
    sub_with_hint::<Fq,P>(accumulator,final_offset,transcript[ptr])
}

// For each fixed input/digit schedule, every checked accumulator is [2^d]O+Q.
// The exponent multiplier is invertible modulo n. Each equality of x against
// a fixed finite operand excludes at most two offset points (A=+/-R).
//64 additions plus2 unconditional skew checks therefore exclude at most132 O.
// Our256 distinct nonzero immutable choices guarantee an admissible selector.
// This is a finite counting argument: no hash/random-oracle or DLog assumption.
pub(crate) unconstrained fn hint(
    points: [P;2], scalars: [ScalarField<32>;2], negate_second: bool,
) -> (u8,[A;ENTRIES]) {
    local_hint(points,scalars,negate_second,false,0)
}

pub(crate) unconstrained fn checked_add(a: J, b: J) -> (bool,J,T) {
    assert(!a.is_infinity & !b.is_infinity,"GLV finite hint operands");
    // The validity check and the incomplete-add formula share these four
    // products. Previously distinct_x and incomplete_add computed them twice.
    let Z1 = a.z; let Z2 = b.z;
    let Z2Z2 = Z2.__mul(Z2);
    let Z1Z1 = Z1.__mul(Z1);
    let U1 = a.x.__mul(Z2Z2);
    let U2 = b.x.__mul(Z1Z1);
    let mut result = (false,a,T::new());
    if U1 != U2 {
        let Z2Z2Z2 = Z2Z2.__mul(Z2);
        let Z1Z1Z1 = Z1Z1.__mul(Z1);
        let S1 = a.y.__mul(Z2Z2Z2);
        let S2 = b.y.__mul(Z1Z1Z1);
        let R = S2.__sub(S1);

        // PP = (U2 - U1)^2
        let (_, PP): (Fq, Fq) = bignum::bignum::compute_quadratic_expression(
            [[U2, U1]],
            [[false, true]],
            [[U2, U1]],
            [[false, true]],
            [],
            [],
        );

        // X3 = -PP * (U1 + U2) + R * R
        let (_, X3): (Fq, Fq) = bignum::bignum::compute_quadratic_expression(
            [[Fq::zero(), PP], [R, Fq::zero()]],
            [[false, true], [false, false]],
            [[U1, U2], [R, Fq::zero()]],
            [[false, false], [false, false]],
            [],
            [],
        );

        // U1S2_minus_U2S1 = U1 * S2 - U2 * S1
        let (_, U1S2_minus_U2S1): (Fq, Fq) = bignum::bignum::compute_quadratic_expression(
            [[U1], [U2]],
            [[false], [true]],
            [[S2], [S1]],
            [[false], [false]],
            [],
            [],
        );

        // Y3 = PP * (U1 * S2 - U2 * S1) + X3 * (-R)
        let (_, Y3): (Fq, Fq) = bignum::bignum::compute_quadratic_expression(
            [[PP], [X3]],
            [[false], [false]],
            [[U1S2_minus_U2S1], [R]],
            [[false], [true]],
            [],
            [],
        );

        let Z1Z2 = Z1.__mul(Z2);

        // Z3 = Z1*Z2 * (U2 - U1)
        let (_, Z3): (Fq, Fq) = bignum::bignum::compute_quadratic_expression(
            [[Z1Z2, Fq::zero()]],
            [[false, false]],
            [[U2, U1]],
            [[false, true]],
            [],
            [],
        );

        result = (true,
            CurveJ { x: X3, y: Y3, z: Z3, is_infinity: false },
            JTranscript { lambda_numerator: R, x3: X3, y3: Y3, z3: Z3 },
        );
    }
    result
}

// Failed candidates are abandoned before a zero-denominator operation. Their
// unfinished transcript is never converted to affine or used by the proof.
pub(crate) unconstrained fn trial(
    inputs: [J;2], tables: [JPointTable<Fq>;2], scalars: [ScalarField<32>;2], index: u8,
) -> (bool,[T;ENTRIES]) {
    let (initial_offset,final_offset) = crate::glv_offsets::pair(index);
    let mut tx = [T::new();ENTRIES];
    for j in 0..8 { tx[j] = tables[0].transcript[j]; }
    let mut ptr: u32 = 8;
    let mut valid = true;
    let mut accumulator = J::from(initial_offset);
    for j in 0..2 {
        if valid {
            let rhs = tables[j].get(scalars[j].base4_slices[0] as u32);
            let (accepted,next,entry) = checked_add(accumulator,rhs);
            valid = accepted;
            if valid {
                accumulator = next; tx[ptr] = entry; ptr += 1;
            }
        }
    }
    for i in 1..32 {
        if valid {
            for _ in 0..4 {
                let (next,entry) = accumulator.dbl();
                accumulator = next; tx[ptr] = entry; ptr += 1;
            }
            for j in 0..2 {
                if valid {
                    let rhs = tables[j].get(scalars[j].base4_slices[i] as u32);
                    let (accepted,next,entry) = checked_add(accumulator,rhs);
                    valid = accepted;
                    if valid {
                        accumulator = next; tx[ptr] = entry; ptr += 1;
                    }
                }
            }
        }
    }
    for j in 0..2 {
        if valid {
            let (accepted,next,entry) = checked_add(accumulator,inputs[j].neg());
            valid = accepted;
            if valid {
                tx[ptr] = entry; ptr += 1;
                if scalars[j].skew { accumulator = next; }
            }
        }
    }
    if valid {
        assert(ptr == ENTRIES-1);
        let (_,entry) = accumulator.sub(J::from(final_offset));
        tx[ptr] = entry;
    }
    (valid,tx)
}

// This is an untrusted local witness accelerator. All foreign-call results
// pass through the byte-identical constrained evaluate_with_transcript replay.
// Array order is part of zark_glv_hint_v1; no private values may leave loopback.
#[oracle(zark_glv_hint_v1)]
unconstrained fn glv_host(
    points: [u128;12], digits: [u8;64], skews: [bool;2],
    negate_second: bool, forced: bool, index: u8,
) -> (u8,[u128;1791]) {}

unconstrained fn local_hint(
    points: [P;2], scalars: [ScalarField<32>;2], negate_second: bool,
    forced: bool, index: u8,
) -> (u8,[A;ENTRIES]) {
    let mut coordinates = [0 as u128;12];
    let mut digits = [0 as u8;64];
    for point in 0..2 {
        assert(!points[point].is_infinity,"GLV local hint expects normalized finite points");
        let x = points[point].x.get_limbs();
        let y = points[point].y.get_limbs();
        for limb in 0..3 {
            coordinates[point*6+limb] = x[limb];
            coordinates[point*6+3+limb] = y[limb];
        }
        for window in 0..32 {
            digits[point*32+window] = scalars[point].base4_slices[window];
        }
    }
    let (selected,raw) = glv_host(coordinates,digits,
        [scalars[0].skew,scalars[1].skew],negate_second,forced,index);
    if forced { assert(selected == index,"GLV local hint selector echo mismatch"); }
    let mut transcript = [A::new();ENTRIES];
    for entry in 0..ENTRIES {
        let offset = entry*9;
        transcript[entry] = AffineTranscript {
            lambda: Fq::from_limbs([raw[offset],raw[offset+1],raw[offset+2]]),
            x3: Fq::from_limbs([raw[offset+3],raw[offset+4],raw[offset+5]]),
            y3: Fq::from_limbs([raw[offset+6],raw[offset+7],raw[offset+8]]),
        };
    }
    (selected,transcript)
}
