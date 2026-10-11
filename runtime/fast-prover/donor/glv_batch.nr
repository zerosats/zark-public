//! One shared-doubling MSM over two GLV-split scalars and two short scalars:
//!     [k0]Q0 + [k1]Q1 + [s0]S0 + [s1]S1,  k_i < n,  0 <= s_i < 2^128.
//! Six 128-bit columns (Q0, phi(Q0), Q1, phi(Q1), S0, S1) share one 124-step
//! doubling chain. Every split, recoding and affine transcript row is an
//! untrusted hint replayed with the exact GLV inequality checks.
use bignum::{BigNum, Secp256k1_Fq, Secp256k1_Fr};
use crate::{BigCurve, ScalarField, Secp256k1};
use crate::curve_jac::types::{AffineTranscript, CurveJ, JTranscript};
use crate::curve_jac::point_table::PointTable as JPointTable;
use crate::ops::point_table::PointTable;
use crate::ops::affine::{double_with_hint, sub_with_hint};
use crate::glv_constants::BETA;

type Fq = Secp256k1_Fq;
type P = Secp256k1;
type J = CurveJ<Fq, P>;
type A = AffineTranscript<Fq>;
type T = JTranscript<Fq>;

global COLUMNS: u32 = 6;
// Tables are built for columns 0, 2, 4 and 5; 1 and 3 are endomorphism images.
global BUILT: [u32; 4] = [0, 2, 4, 5];
global TABLE_ROWS: u32 = 32;
// 32 table rows, 6 first-window additions, 31*(4 doublings + 6 additions),
// 6 unconditional skew checks and the final complete offset removal.
global ENTRIES: u32 = 355;
global BANK: u32 = 512;

pub fn msm(glv_points: [P; 2], glv_scalars: [Secp256k1_Fr; 2], short_points: [P; 2], short_scalars: [Field; 2]) -> P {
    let (columns, slices, negate) = prepare(glv_points, glv_scalars, short_points, short_scalars);
    // Safety: the selector binds both immutable offsets, and every transcript
    // row is replayed below with exact nonzero-denominator checks.
    let (index, transcript) = unsafe { hint(columns, slices, negate) };
    evaluate_with_transcript(columns, slices, negate, index, transcript)
}

/// Isolated research-only adversarial hook; the origin relation never calls it.
/// It builds the hint for `hint_index`, optionally corrupts one transcript row,
/// and replays it under `claimed_index` with the identical constraints.
pub fn msm_with_selector_test(
    glv_points: [P; 2], glv_scalars: [Secp256k1_Fr; 2], short_points: [P; 2], short_scalars: [Field; 2],
    hint_index: u16, claimed_index: u16, mutation: u8,
) -> P {
    assert(mutation <= 5, "batch unknown transcript mutation");
    let (columns, slices, negate) = prepare(glv_points, glv_scalars, short_points, short_scalars);
    // Safety: deliberately untrusted test data is checked by the identical replay.
    let mut transcript = unsafe { fixed_hint(columns, slices, negate, hint_index) };
    if mutation == 1 { transcript[ENTRIES - 1].x3 = transcript[ENTRIES - 1].x3 + Fq::one(); } // final offset removal
    if mutation == 2 { transcript[100].x3 = transcript[100].x3 + Fq::one(); }                 // shared doubling
    if mutation == 3 { transcript[10].lambda = transcript[10].lambda + Fq::one(); }           // second built table
    if mutation == 4 { transcript[350].y3 = transcript[350].y3 + Fq::one(); }                 // skew check
    if mutation == 5 { transcript[TABLE_ROWS].lambda = transcript[TABLE_ROWS].lambda + Fq::one(); } // first offset add
    evaluate_with_transcript(columns, slices, negate, claimed_index, transcript)
}

/// Isolated research-only differential hook; role circuits never call it. It
/// returns the raw hint, forced or searched, as the selected index and the
/// flattened (lambda, x3, y3) limbs of every transcript row, so a native helper
/// can be compared with this Brillig hint without any constrained replay.
pub unconstrained fn hint_for_test(
    glv_points: [P; 2], glv_scalars: [Secp256k1_Fr; 2], short_points: [P; 2], short_scalars: [Field; 2],
    forced: bool, index: u16,
) -> (u16, [u128; ENTRIES * 9]) {
    let (columns, slices, negate) = prepare(glv_points, glv_scalars, short_points, short_scalars);
    let (selected, transcript) = if forced {
        (index, fixed_hint(columns, slices, negate, index))
    } else {
        hint(columns, slices, negate)
    };
    let mut limbs = [0 as u128; ENTRIES * 9];
    for entry in 0..ENTRIES {
        let parts = [transcript[entry].lambda, transcript[entry].x3, transcript[entry].y3];
        for part in 0..3 {
            let values = parts[part].get_limbs();
            for limb in 0..3 { limbs[entry * 9 + part * 3 + limb] = values[limb]; }
        }
    }
    (selected, limbs)
}

fn prepare(glv_points: [P; 2], glv_scalars: [Secp256k1_Fr; 2], short_points: [P; 2], short_scalars: [Field; 2])
    -> ([P; 6], [ScalarField<32>; 6], [bool; 2]) {
    let mut columns: [P; 6] = [P::one(); 6];
    let mut slices: [ScalarField<32>; 6] = [ScalarField::zero(); 6];
    let mut negate: [bool; 2] = [false; 2];
    for i in 0..2 {
        assert(!glv_points[i].is_infinity, "batch GLV finite base");
        // Safety: prepare_split constrains magnitude bounds, point validity and
        // the signed modular recomposition of this untrusted decomposition.
        let (a, b, negative_a, negative_b) = unsafe { crate::glv_split::split(glv_scalars[i]) };
        let (first, scalars, negate_second) =
            crate::glv::prepare_split(glv_points[i], glv_scalars[i], a, b, negative_a, negative_b);
        columns[2 * i] = first;
        columns[2 * i + 1] = P::from_coordinates(
            first.x * BETA, if negate_second { -first.y } else { first.y }, false,
        );
        slices[2 * i] = scalars[0];
        slices[2 * i + 1] = scalars[1];
        negate[i] = negate_second;
    }
    for i in 0..2 {
        let point = short_points[i];
        assert(!point.is_infinity, "batch short finite base");
        point.x.validate_in_field();
        point.y.validate_in_field();
        point.validate_on_curve();
        short_scalars[i].assert_max_bit_size::<128>();
        columns[4 + i] = point;
        slices[4 + i] = ScalarField::from(short_scalars[i]);
    }
    (columns, slices, negate)
}

fn evaluate_with_transcript(
    columns: [P; 6], slices: [ScalarField<32>; 6], negate: [bool; 2], index: u16, transcript: [A; ENTRIES],
) -> P {
    let (initial_offset, final_offset) = crate::glv_offsets::pair_wide(index);
    let mut tables: [PointTable<Fq>; 6] = [PointTable::empty(); 6];
    for t in 0..4 {
        let mut table_tx = [A::new(); 8];
        for j in 0..8 { table_tx[j] = transcript[8 * t + j]; }
        tables[BUILT[t]] = PointTable::new_with_exact_hint(columns[BUILT[t]], table_tx);
    }
    tables[1] = tables[0].endomorphism(BETA, negate[0]);
    tables[3] = tables[2].endomorphism(BETA, negate[1]);
    let mut accumulator = initial_offset;
    let mut ptr: u32 = TABLE_ROWS;
    for j in 0..COLUMNS {
        accumulator = crate::glv_affine::add(
            accumulator, tables[j].get::<P>(slices[j].base4_slices[0] as u32), transcript[ptr],
        );
        ptr += 1;
    }
    for i in 1..32 {
        for _ in 0..4 {
            // Exact inequality on every addition excludes doubling and
            // cancellation, so the accumulator stays finite (odd prime order).
            accumulator = double_with_hint::<Fq, P>(accumulator, transcript[ptr]);
            ptr += 1;
        }
        for j in 0..COLUMNS {
            accumulator = crate::glv_affine::add(
                accumulator, tables[j].get::<P>(slices[j].base4_slices[i] as u32), transcript[ptr],
            );
            ptr += 1;
        }
    }
    for j in 0..COLUMNS {
        // Unconditional, like the two-column walk: selector search must avoid it.
        let corrected = crate::glv_affine::subtract(accumulator, columns[j], transcript[ptr]);
        accumulator = if slices[j].skew { corrected } else { accumulator };
        ptr += 1;
    }
    assert(ptr == ENTRIES - 1);
    // Removing the matching offset may legitimately produce infinity.
    sub_with_hint::<Fq, P>(accumulator, final_offset, transcript[ptr])
}

// This is an untrusted local witness accelerator. All foreign-call results
// pass through the byte-identical constrained evaluate_with_transcript replay.
// Array order is part of zark_glv_batch_hint_v1; no private values may leave
// loopback. Diagnostic strings reuse the reviewed GLV local-hint catalog.
#[oracle(zark_glv_batch_hint_v1)]
unconstrained fn batch_host(
    points: [u128; 36], digits: [u128; 6], skews: [bool; 6], negate: [bool; 2],
    forced: bool, index: u16,
) -> (u16, [u128; 3195]) {}

unconstrained fn local_hint(
    columns: [P; 6], slices: [ScalarField<32>; 6], negate: [bool; 2], forced: bool, index: u16,
) -> (u16, [A; ENTRIES]) {
    let mut coordinates = [0 as u128; 36];
    let mut digits = [0 as u128; 6];
    let mut skews = [false; 6];
    for column in 0..COLUMNS {
        assert(!columns[column].is_infinity, "GLV local hint expects normalized finite points");
        let x = columns[column].x.get_limbs();
        let y = columns[column].y.get_limbs();
        for limb in 0..3 {
            coordinates[column * 6 + limb] = x[limb];
            coordinates[column * 6 + 3 + limb] = y[limb];
        }
        // Digit w of a column occupies bits 4w..4w+4 of its word.
        let mut word = 0 as u128;
        for window in 0..32 {
            word = word | ((slices[column].base4_slices[window] as u128) << ((4 * window) as u128));
        }
        digits[column] = word;
        skews[column] = slices[column].skew;
    }
    let (selected, raw) = batch_host(coordinates, digits, skews, negate, forced, index);
    if forced { assert(selected == index, "GLV local hint selector echo mismatch"); }
    let mut transcript = [A::new(); ENTRIES];
    for entry in 0..ENTRIES {
        let offset = entry * 9;
        transcript[entry] = AffineTranscript {
            lambda: Fq::from_limbs([raw[offset], raw[offset + 1], raw[offset + 2]]),
            x3: Fq::from_limbs([raw[offset + 3], raw[offset + 4], raw[offset + 5]]),
            y3: Fq::from_limbs([raw[offset + 6], raw[offset + 7], raw[offset + 8]]),
        };
    }
    (selected, transcript)
}

// A forced selector keeps the exact Jacobian prefix and a zero suffix when the
// offset is inadmissible; the constrained replay must then reject it.
unconstrained fn fixed_hint(columns: [P; 6], slices: [ScalarField<32>; 6], negate: [bool; 2], index: u16) -> [A; ENTRIES] {
    let (_, transcript) = local_hint(columns, slices, negate, true, index);
    transcript
}

unconstrained fn hint(columns: [P; 6], slices: [ScalarField<32>; 6], negate: [bool; 2]) -> (u16, [A; ENTRIES]) {
    local_hint(columns, slices, negate, false, 0)
}
