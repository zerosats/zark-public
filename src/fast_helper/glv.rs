//! GLV offset selection and affine transcript for `zark_glv_hint_v1`.
//!
//! The Jacobian formulas, argument order, selector search and zero-preserving
//! batch inverse follow the donor Brillig (`runtime/fast-prover/donor/glv_msm.nr`)
//! as modelled by the retired Python helper. Results remain untrusted hints:
//! the constrained replay checks every transcript row and both offsets.
use super::field::{Fp, Point};

#[cfg(test)]
#[path = "glv_tests.rs"]
mod tests;

pub(super) const ENTRIES: usize = 199;
pub(super) const LIMBS: usize = ENTRIES * 9;
pub(super) const TABLE_ENTRIES: usize = 8;
const FINAL_ENTRY: usize = ENTRIES - 1;

pub(super) struct HintInput {
    pub(super) points: [Point; 2],
    pub(super) digits: [[u8; 32]; 2],
    pub(super) skews: [bool; 2],
    pub(super) negate_second: bool,
    pub(super) forced: bool,
    pub(super) index: u8,
}

/// Rejected input or no admissible selector; the RPC answers "Invalid parameters".
#[derive(Debug, PartialEq)]
pub(super) struct Invalid;

#[derive(Clone, Copy)]
pub(super) struct Jacobian {
    x: Fp,
    y: Fp,
    z: Fp,
    infinity: bool,
}

/// (numerator, x, y, z) before batch normalization to affine form.
pub(super) type Entry = [Fp; 4];
pub(super) const ZERO: Entry = [Fp::ZERO; 4];

pub(super) fn jacobian(point: Point) -> Jacobian {
    Jacobian {
        x: point.x,
        y: point.y,
        z: Fp::ONE,
        infinity: false,
    }
}

pub(super) fn neg(point: Jacobian) -> Jacobian {
    Jacobian {
        y: -point.y,
        ..point
    }
}

pub(super) fn double(point: Jacobian) -> Result<(Jacobian, Entry), Invalid> {
    if point.infinity || point.y.is_zero() {
        return Err(Invalid);
    }
    let Jacobian { x, y, z, .. } = point;
    let xx = x * x;
    let yy = y * y;
    let m = xx + xx + xx;
    let xy2 = x * yy;
    let twice_xy2 = xy2 + xy2;
    let d = twice_xy2 + twice_xy2;
    let nx = m * m - d - d;
    let y4 = yy * yy;
    let twice_y4 = y4 + y4;
    let four_y4 = twice_y4 + twice_y4;
    let ny = m * (d - nx) - four_y4 - four_y4;
    let yz = y * z;
    let nz = yz + yz;
    let doubled = Jacobian {
        x: nx,
        y: ny,
        z: nz,
        infinity: false,
    };
    Ok((doubled, [m, nx, ny, nz]))
}

/// Reuse the scaled coordinates from the equal-x guard in the addition.
/// These are the original Jacobian formulas, so even the unnormalized
/// transcript prefix of an inadmissible forced selector stays identical.
struct Addition {
    z1_squared: Fp,
    z2_squared: Fp,
    u1: Fp,
    u2: Fp,
}

impl Addition {
    fn new(a: Jacobian, b: Jacobian) -> Self {
        let z1_squared = a.z * a.z;
        let z2_squared = b.z * b.z;
        Self {
            z1_squared,
            z2_squared,
            u1: a.x * z2_squared,
            u2: b.x * z1_squared,
        }
    }

    fn scaled_y(&self, a: Jacobian, b: Jacobian) -> (Fp, Fp) {
        (a.y * self.z2_squared * b.z, b.y * self.z1_squared * a.z)
    }

    fn finish(self, a: Jacobian, b: Jacobian) -> (Jacobian, Entry) {
        let (s1, s2) = self.scaled_y(a, b);
        let Self { u1, u2, .. } = self;
        let r = s2 - s1;
        let h = u2 - u1;
        let pp = h * h;
        let x = r * r - pp * (u1 + u2);
        let y = pp * (u1 * s2 - u2 * s1) - x * r;
        let z = a.z * b.z * h;
        let sum = Jacobian {
            x,
            y,
            z,
            infinity: false,
        };
        (sum, [r, x, y, z])
    }
}

pub(super) fn raw_add(a: Jacobian, b: Jacobian) -> (Jacobian, Entry) {
    Addition::new(a, b).finish(a, b)
}

/// `None` is an excluded equal-x addition: this selector cannot be used.
pub(super) fn checked_add(a: Jacobian, b: Jacobian) -> Result<Option<(Jacobian, Entry)>, Invalid> {
    if a.infinity || b.infinity {
        return Err(Invalid);
    }
    let addition = Addition::new(a, b);
    Ok((addition.u1 != addition.u2).then(|| addition.finish(a, b)))
}

pub(super) fn complete_add(a: Jacobian, b: Jacobian) -> Result<Entry, Invalid> {
    if a.infinity {
        return Ok([Fp::ZERO, b.x, b.y, b.z]);
    }
    if b.infinity {
        return Ok([Fp::ZERO, a.x, a.y, a.z]);
    }
    let addition = Addition::new(a, b);
    if addition.u1 != addition.u2 {
        return Ok(addition.finish(a, b).1);
    }
    let (s1, s2) = addition.scaled_y(a, b);
    if s1 == s2 {
        return Ok(double(a)?.1);
    }
    Ok(ZERO)
}

type Tables = [[Jacobian; 16]; 2];

/// The odd-multiple table `[-15P..15P]` and its 8 transcript entries.
pub(super) fn point_table(
    point: Point,
) -> Result<([Jacobian; 16], [Entry; TABLE_ENTRIES]), Invalid> {
    let initial = jacobian(point);
    let (doubled, first) = double(initial)?;
    let mut table = [initial; 16];
    table[7] = neg(initial);
    let mut entries = [ZERO; TABLE_ENTRIES];
    entries[0] = first;
    let mut current = initial;
    for i in 1..8 {
        let (next, entry) = raw_add(doubled, current);
        current = next;
        entries[i] = entry;
        table[8 + i] = current;
        table[7 - i] = neg(current);
    }
    Ok((table, entries))
}

/// The endomorphism image table, negated exactly when the two signs differ.
pub(super) fn endomorphism(table: &[Jacobian; 16], negate: bool) -> [Jacobian; 16] {
    let beta = Fp::beta();
    table.map(|p| Jacobian {
        x: p.x * beta,
        y: if negate { -p.y } else { p.y },
        ..p
    })
}

fn make_tables(value: &HintInput) -> Result<(Tables, [Entry; TABLE_ENTRIES]), Invalid> {
    let (table, entries) = point_table(value.points[0])?;
    let second = endomorphism(&table, value.negate_second);
    Ok(([table, second], entries))
}

/// A bad selector keeps the exact Jacobian prefix and a zero suffix, which a
/// forced (test) selector returns unchanged for the constrained replay.
fn trial(
    value: &HintInput,
    offsets: [Point; 2],
    tables: &Tables,
    table_entries: &[Entry; TABLE_ENTRIES],
) -> Result<(bool, [Entry; ENTRIES]), Invalid> {
    let mut entries = [ZERO; ENTRIES];
    entries[..TABLE_ENTRIES].copy_from_slice(table_entries);
    let mut ptr = TABLE_ENTRIES;
    let mut accumulator = jacobian(offsets[0]);
    for window in 0..32 {
        if window != 0 {
            for _ in 0..4 {
                let (next, entry) = double(accumulator)?;
                accumulator = next;
                entries[ptr] = entry;
                ptr += 1;
            }
        }
        for (table, digits) in tables.iter().zip(&value.digits) {
            let digit = usize::from(digits[window]);
            let Some((next, entry)) = checked_add(accumulator, table[digit])? else {
                return Ok((false, entries));
            };
            accumulator = next;
            entries[ptr] = entry;
            ptr += 1;
        }
    }
    for j in 0..2 {
        let Some((next, entry)) = checked_add(accumulator, neg(jacobian(value.points[j])))? else {
            return Ok((false, entries));
        };
        entries[ptr] = entry;
        ptr += 1;
        if value.skews[j] {
            accumulator = next;
        }
    }
    if ptr != FINAL_ENTRY {
        return Err(Invalid);
    }
    entries[ptr] = complete_add(accumulator, neg(jacobian(offsets[1])))?;
    Ok((true, entries))
}

/// Zero-preserving batch normalization to (lambda, x, y) limb triples.
pub(super) fn affine_limbs(entries: &[Entry]) -> Result<Vec<u128>, Invalid> {
    let mut product = Fp::ONE;
    let mut prefixes = vec![Fp::ZERO; entries.len()];
    for (prefix, entry) in prefixes.iter_mut().zip(entries) {
        *prefix = product;
        if !entry[3].is_zero() {
            product = product * entry[3];
        }
    }
    let mut inverse = product.invert().ok_or(Invalid)?;
    let mut inverses = vec![Fp::ZERO; entries.len()];
    for i in (0..entries.len()).rev() {
        let z = entries[i][3];
        if !z.is_zero() {
            inverses[i] = inverse * prefixes[i];
            inverse = inverse * z;
        }
    }
    let mut limbs = Vec::with_capacity(entries.len() * 9);
    for ([r, x, y, _], zi) in entries.iter().zip(inverses) {
        let zi2 = zi * zi;
        for coordinate in [*r * zi, *x * zi2, *y * zi2 * zi] {
            limbs.extend(coordinate.limbs());
        }
    }
    Ok(limbs)
}

fn validate(value: &HintInput) -> Result<(), Invalid> {
    if !value.points.iter().all(|p| p.on_curve()) || value.digits.iter().flatten().any(|&d| d >= 16)
    {
        return Err(Invalid);
    }
    let first = value.points[0];
    let second = Point {
        x: first.x * Fp::beta(),
        y: if value.negate_second {
            -first.y
        } else {
            first.y
        },
    };
    if value.points[1] != second || (!value.forced && value.index != 0) {
        return Err(Invalid);
    }
    Ok(())
}

/// The first admissible selector (or the forced one) and its 1791 limbs.
pub(super) fn resolve(value: &HintInput, bank: &[[Point; 2]]) -> Result<(u8, Vec<u128>), Invalid> {
    validate(value)?;
    let (tables, table_entries) = make_tables(value)?;
    let choices = if value.forced {
        value.index..=value.index
    } else {
        0..=u8::MAX
    };
    for index in choices {
        let offsets = *bank.get(usize::from(index)).ok_or(Invalid)?;
        let (valid, entries) = trial(value, offsets, &tables, &table_entries)?;
        if valid || value.forced {
            let limbs = affine_limbs(&entries)?;
            return if limbs.len() == LIMBS {
                Ok((index, limbs))
            } else {
                Err(Invalid)
            };
        }
    }
    Err(Invalid)
}
