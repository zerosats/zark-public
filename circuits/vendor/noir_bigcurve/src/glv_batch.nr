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

// Every checked accumulator is [2^d]O+Q for a fixed input schedule, and each
// x-equality against a fixed finite operand excludes at most two offsets. The
// 192 additions and 6 skew checks exclude at most 396 of 512 distinct choices.
unconstrained fn hint_tables(columns: [P; 6], negate: [bool; 2]) -> ([J; 6], [JPointTable<Fq>; 6]) {
    let mut inputs: [J; 6] = [J::from(columns[0]); 6];
    for j in 0..COLUMNS { inputs[j] = J::from(columns[j]); }
    let mut tables: [JPointTable<Fq>; 6] = [JPointTable::empty(); 6];
    for t in 0..4 { tables[BUILT[t]] = JPointTable::new(inputs[BUILT[t]]); }
    tables[1] = tables[0].endomorphism(BETA, negate[0]);
    tables[3] = tables[2].endomorphism(BETA, negate[1]);
    (inputs, tables)
}

// A forced selector keeps the exact Jacobian prefix and a zero suffix when the
// offset is inadmissible; the constrained replay must then reject it.
unconstrained fn fixed_hint(columns: [P; 6], slices: [ScalarField<32>; 6], negate: [bool; 2], index: u16) -> [A; ENTRIES] {
    let (inputs, tables) = hint_tables(columns, negate);
    let (_, tx) = trial(inputs, tables, slices, index);
    AffineTranscript::from_jacobian_transcript(tx)
}

unconstrained fn hint(columns: [P; 6], slices: [ScalarField<32>; 6], negate: [bool; 2]) -> (u16, [A; ENTRIES]) {
    let (inputs, tables) = hint_tables(columns, negate);
    let mut found = false;
    let mut selected: u16 = 0;
    let mut selected_tx = [T::new(); ENTRIES];
    for candidate in 0..BANK {
        if !found {
            let (valid, tx) = trial(inputs, tables, slices, candidate as u16);
            if valid {
                found = true;
                selected = candidate as u16;
                selected_tx = tx;
            }
        }
    }
    assert(found, "batch GLV no admissible offset in verified bank");
    (selected, AffineTranscript::from_jacobian_transcript(selected_tx))
}

unconstrained fn trial(inputs: [J; 6], tables: [JPointTable<Fq>; 6], slices: [ScalarField<32>; 6], index: u16) -> (bool, [T; ENTRIES]) {
    let (initial_offset, final_offset) = crate::glv_offsets::pair_wide(index);
    let mut tx = [T::new(); ENTRIES];
    for t in 0..4 {
        for j in 0..8 { tx[8 * t + j] = tables[BUILT[t]].transcript[j]; }
    }
    let mut ptr: u32 = TABLE_ROWS;
    let mut valid = true;
    let mut accumulator = J::from(initial_offset);
    for j in 0..COLUMNS {
        if valid {
            let rhs = tables[j].get(slices[j].base4_slices[0] as u32);
            let (accepted, next, entry) = crate::glv_msm::checked_add(accumulator, rhs);
            valid = accepted;
            if valid { accumulator = next; tx[ptr] = entry; ptr += 1; }
        }
    }
    for i in 1..32 {
        if valid {
            for _ in 0..4 {
                let (next, entry) = accumulator.dbl();
                accumulator = next; tx[ptr] = entry; ptr += 1;
            }
            for j in 0..COLUMNS {
                if valid {
                    let rhs = tables[j].get(slices[j].base4_slices[i] as u32);
                    let (accepted, next, entry) = crate::glv_msm::checked_add(accumulator, rhs);
                    valid = accepted;
                    if valid { accumulator = next; tx[ptr] = entry; ptr += 1; }
                }
            }
        }
    }
    for j in 0..COLUMNS {
        if valid {
            let (accepted, next, entry) = crate::glv_msm::checked_add(accumulator, inputs[j].neg());
            valid = accepted;
            if valid {
                tx[ptr] = entry; ptr += 1;
                if slices[j].skew { accumulator = next; }
            }
        }
    }
    if valid {
        assert(ptr == ENTRIES - 1);
        let (_, entry) = accumulator.sub(J::from(final_offset));
        tx[ptr] = entry;
    }
    (valid, tx)
}

#[test]
fn msm_matches_separate_multiplications() {
    let g = P::one();
    let q1 = crate::glv::mul(g, Secp256k1_Fr::from(7));
    let s0 = crate::glv::mul(g, Secp256k1_Fr::from(11));
    let s1 = crate::glv::mul(q1, Secp256k1_Fr::from(13));
    let k0 = -Secp256k1_Fr::one();
    let k1 = Secp256k1_Fr::from(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab);
    let w0: Field = 340282366920938463463374607431768211455; // 2^128 - 1
    let w1: Field = 12345;
    let expected = crate::glv::mul(g, k0) + crate::glv::mul(q1, k1)
        + crate::glv::mul(s0, Secp256k1_Fr::from(w0)) + crate::glv::mul(s1, Secp256k1_Fr::from(w1));
    assert(msm([g, q1], [k0, k1], [s0, s1], [w0, w1]) == expected);
}

#[test]
fn msm_of_zero_scalars_is_infinity() {
    let g = P::one();
    let q1 = crate::glv::mul(g, Secp256k1_Fr::from(5));
    let result = msm([g, q1], [Secp256k1_Fr::zero(); 2], [q1, g], [0, 0]);
    assert(result.is_infinity);
}

#[test]
fn msm_cancels_to_infinity() {
    // [1]G + [n-2]G + [1]G = [n]G = infinity, exercising the final complete step.
    let g = P::one();
    let result = msm([g, g], [Secp256k1_Fr::one(), -Secp256k1_Fr::from(2)], [g, g], [1, 0]);
    assert(result.is_infinity);
}

#[test(should_fail)]
fn msm_rejects_oversized_short_scalar() {
    let g = P::one();
    let _ = msm([g, g], [Secp256k1_Fr::one(); 2], [g, g], [340282366920938463463374607431768211456, 0]);
}

// Adversarial coverage. The non-GLV differential reference is the generic
// BigCurve multiplication: independent of the GLV split, six-column schedule and
// offset bank, but it shares ScalarField, PointTable, AffineTranscript, the
// affine hint operations and noir-bignum with msm.
// Rejection boundaries (checked by running each case as a plain test): every
// corrupted transcript row, the mismatched selector and the off-curve base fail
// in the quadratic-expression check that replays them (surfacing at the bignum
// quotient hint, noir-bignum expressions.nr), so each row is consumed by a
// constrained expression. Selector 512 fails the constrained 9-bit range check.
// Rejecting adversarial quotient witnesses is noir-bignum's carry/range
// argument and is not re-tested here.
#[test]
fn msm_matches_generic_reference() {
    let (points, scalars, shorts, weights) = fixture();
    assert(msm(points, scalars, shorts, weights) == reference(points, scalars, shorts, weights));
}

#[test]
fn msm_zero_weights_match_generic_reference() {
    let (points, scalars, shorts, _) = fixture();
    assert(msm(points, scalars, shorts, [0, 0]) == reference(points, scalars, shorts, [0, 0]));
}

#[test]
fn msm_accepts_selectors_255_256_511() {
    let (points, scalars, shorts, weights) = fixture();
    let expected = reference(points, scalars, shorts, weights);
    for index in [255 as u16, 256, 511] {
        assert(msm_with_selector_test(points, scalars, shorts, weights, index, index, 0) == expected);
    }
}

#[test(should_fail)]
fn msm_rejects_selector_512() {
    let (points, scalars, shorts, weights) = fixture();
    let _ = msm_with_selector_test(points, scalars, shorts, weights, 0, 512, 0);
}

#[test(should_fail)]
fn msm_rejects_mismatched_selector() {
    let (points, scalars, shorts, weights) = fixture();
    let _ = msm_with_selector_test(points, scalars, shorts, weights, 0, 1, 0);
}

#[test(should_fail)]
fn msm_rejects_corrupted_final_offset_removal() { mutated(1); }
#[test(should_fail)]
fn msm_rejects_corrupted_shared_doubling() { mutated(2); }
#[test(should_fail)]
fn msm_rejects_corrupted_table_slope() { mutated(3); }
#[test(should_fail)]
fn msm_rejects_corrupted_skew_check() { mutated(4); }
#[test(should_fail)]
fn msm_rejects_corrupted_first_offset_add() { mutated(5); }

#[test(should_fail_with = "batch short finite base")]
fn msm_rejects_infinite_short_base() {
    let (points, scalars, shorts, weights) = fixture();
    let _ = msm(points, scalars, [shorts[0], P::point_at_infinity()], weights);
}

#[test(should_fail_with = "batch GLV finite base")]
fn msm_rejects_infinite_glv_base() {
    let (points, scalars, shorts, weights) = fixture();
    let _ = msm([P::point_at_infinity(), points[1]], scalars, shorts, weights);
}

#[test(should_fail)]
fn msm_rejects_off_curve_short_base() {
    let (points, scalars, shorts, weights) = fixture();
    let g = P::one();
    let off_curve = P::from_coordinates(g.x, g.y + Fq::one(), false);
    let _ = msm(points, scalars, [shorts[0], off_curve], weights);
}

fn mutated(mutation: u8) {
    let (points, scalars, shorts, weights) = fixture();
    let _ = msm_with_selector_test(points, scalars, shorts, weights, 0, 0, mutation);
}

fn fixture() -> ([P; 2], [Secp256k1_Fr; 2], [P; 2], [Field; 2]) {
    let g = P::one();
    let q1 = crate::glv::mul(g, Secp256k1_Fr::from(7));
    let s0 = crate::glv::mul(g, Secp256k1_Fr::from(11));
    let s1 = crate::glv::mul(q1, Secp256k1_Fr::from(13));
    let k0 = -Secp256k1_Fr::one();
    let k1 = Secp256k1_Fr::from(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab);
    ([g, q1], [k0, k1], [s0, s1], [340282366920938463463374607431768211455, 12345])
}

fn reference(points: [P; 2], scalars: [Secp256k1_Fr; 2], shorts: [P; 2], weights: [Field; 2]) -> P {
    let mut total = P::point_at_infinity();
    for i in 0..2 {
        total = total + points[i].mul(crate::Secp256k1Scalar::from_bignum(scalars[i]));
        total = total + shorts[i].mul(crate::Secp256k1Scalar::from_bignum(Secp256k1_Fr::from(weights[i])));
    }
    total
}
