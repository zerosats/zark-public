//! Lower fixed-generator transcript for `zark_fixed_generator_hint_v1`.
//!
//! The 41 mixed Jacobian additions use the exact formula of the pinned
//! `circuits/fixed-generator/src/batch_hint.nr`, followed by one zero-preserving
//! batch inverse. Each row is an untrusted hint for the unchanged constrained
//! affine replay and complete top addition.
use super::field::{Fp, Point};

pub(super) const WINDOWS: usize = 42;
pub(super) const TABLE_WIDTH: usize = 32;
const ROWS: usize = WINDOWS - 1;
pub(super) const LIMBS: usize = ROWS * 9;

pub(super) type Table = [[Point; TABLE_WIDTH]; WINDOWS];

#[derive(Debug, PartialEq)]
pub(super) enum Failure {
    /// Rejected input; the RPC answers "Invalid parameters".
    Invalid,
    /// A zero denominator contradicts the model's nonexceptional-walk claim.
    /// The reference asserted this, so the RPC answers "Internal error".
    Model,
}

#[derive(Clone, Copy)]
struct Jacobian {
    x: Fp,
    y: Fp,
    z: Fp,
}

fn point(table: &Table, window: usize, index: u8, negative: bool) -> Jacobian {
    let Point { x, y } = table[window][usize::from(index)];
    Jacobian {
        x,
        y: if negative { -y } else { y },
        z: Fp::ONE,
    }
}

/// Exact source formula: 11 modular products and 7 subtractions.
fn mixed(a: Jacobian, b: Jacobian) -> (Jacobian, Fp) {
    let z2 = a.z * a.z;
    let h = b.x * z2 - a.x;
    let r = b.y * z2 * a.z - a.y;
    let h2 = h * h;
    let h3 = h2 * h;
    let u = a.x * h2;
    let x = r * r - h3 - u - u;
    let y = r * (u - x) - a.y * h3;
    (Jacobian { x, y, z: a.z * h }, r)
}

/// Source loop order: prefix products over nonzero entries and one inverse.
fn invert_batch(values: &[Fp]) -> Option<Vec<Fp>> {
    let mut accumulator = Fp::ONE;
    let mut prefixes = Vec::with_capacity(values.len());
    for &value in values {
        prefixes.push(accumulator);
        if !value.is_zero() {
            accumulator = accumulator * value;
        }
    }
    accumulator = accumulator.invert()?;
    let mut inverses = vec![Fp::ZERO; values.len()];
    for i in (0..values.len()).rev() {
        if !values[i].is_zero() {
            inverses[i] = accumulator * prefixes[i];
            accumulator = accumulator * values[i];
        }
    }
    Some(inverses)
}

pub(super) fn transcript(
    table: &Table,
    indices: &[u8; WINDOWS],
    negative: &[bool; WINDOWS],
) -> Result<Vec<u128>, Failure> {
    if indices.iter().any(|&i| usize::from(i) >= TABLE_WIDTH) {
        return Err(Failure::Invalid);
    }
    let mut accumulator = point(table, 0, indices[0], negative[0]);
    let mut steps = Vec::with_capacity(ROWS);
    for i in 1..WINDOWS {
        let step = mixed(accumulator, point(table, i, indices[i], negative[i]));
        accumulator = step.0;
        steps.push(step);
    }
    // Every bounded signed odd positional input has a nonzero denominator.
    // This checks the model; it never substitutes for a replay constraint.
    if steps.iter().any(|(p, _)| p.z.is_zero()) {
        return Err(Failure::Model);
    }
    let denominators: Vec<Fp> = steps.iter().map(|(p, _)| p.z).collect();
    let inverses = invert_batch(&denominators).ok_or(Failure::Invalid)?;
    let mut limbs = Vec::with_capacity(LIMBS);
    for ((Jacobian { x, y, .. }, numerator), inverse) in steps.into_iter().zip(inverses) {
        let z2 = inverse * inverse;
        for coordinate in [numerator * inverse, x * z2, y * z2 * inverse] {
            limbs.extend(coordinate.limbs());
        }
    }
    Ok(limbs)
}
