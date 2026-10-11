//! Six-column selected-offset transcript for `zark_glv_batch_hint_v1`.
//!
//! Mirrors the Brillig hint of `circuits/vendor/noir_bigcurve/src/glv_batch.nr`:
//! columns are (Q0, phi(Q0), Q1, phi(Q1), S0, S1); tables are built for columns
//! 0, 2, 4 and 5 and the other two are endomorphism images; one doubling chain
//! is shared; all six skew checks are unconditional; the final offset removal
//! is complete. Results remain untrusted hints: the constrained replay checks
//! every transcript row and both offsets selected by the same index.
use super::field::{Fp, Point};
use super::glv::{self, Entry, Invalid, Jacobian, TABLE_ENTRIES, ZERO};

pub(super) const COLUMNS: usize = 6;
pub(super) const ENTRIES: usize = 355;
pub(super) const LIMBS: usize = ENTRIES * 9;
/// 192 checked additions and 6 skew checks exclude at most 396 offsets.
pub(super) const BANK: usize = 512;
const BUILT: [usize; 4] = [0, 2, 4, 5];
const TABLE_ROWS: usize = BUILT.len() * TABLE_ENTRIES;
const FINAL_ENTRY: usize = ENTRIES - 1;

pub(super) struct BatchInput {
    pub(super) points: [Point; COLUMNS],
    pub(super) digits: [[u8; 32]; COLUMNS],
    pub(super) skews: [bool; COLUMNS],
    /// Per GLV pair: the image column carries an extra sign.
    pub(super) negate: [bool; 2],
    pub(super) forced: bool,
    pub(super) index: u16,
}

type Tables = [[Jacobian; 16]; COLUMNS];

fn validate(value: &BatchInput) -> Result<(), Invalid> {
    if !value.points.iter().all(|p| p.on_curve()) || value.digits.iter().flatten().any(|&d| d >= 16)
    {
        return Err(Invalid);
    }
    for pair in 0..2 {
        let first = value.points[2 * pair];
        let image = Point {
            x: first.x * Fp::beta(),
            y: if value.negate[pair] {
                -first.y
            } else {
                first.y
            },
        };
        if value.points[2 * pair + 1] != image {
            return Err(Invalid);
        }
    }
    if usize::from(value.index) >= BANK || (!value.forced && value.index != 0) {
        return Err(Invalid);
    }
    Ok(())
}

fn make_tables(value: &BatchInput) -> Result<(Tables, [Entry; TABLE_ROWS]), Invalid> {
    let mut tables = [[glv::jacobian(value.points[0]); 16]; COLUMNS];
    let mut entries = [ZERO; TABLE_ROWS];
    for (t, &column) in BUILT.iter().enumerate() {
        let (table, rows) = glv::point_table(value.points[column])?;
        tables[column] = table;
        entries[t * TABLE_ENTRIES..(t + 1) * TABLE_ENTRIES].copy_from_slice(&rows);
    }
    tables[1] = glv::endomorphism(&tables[0], value.negate[0]);
    tables[3] = glv::endomorphism(&tables[2], value.negate[1]);
    Ok((tables, entries))
}

/// A failed selector keeps the exact Jacobian prefix and a zero suffix, which a
/// forced (test) selector returns unchanged for the constrained replay.
fn trial(
    value: &BatchInput,
    offsets: [Point; 2],
    tables: &Tables,
    table_entries: &[Entry; TABLE_ROWS],
) -> Result<(bool, Vec<Entry>), Invalid> {
    let mut entries = vec![ZERO; ENTRIES];
    entries[..TABLE_ROWS].copy_from_slice(table_entries);
    let mut ptr = TABLE_ROWS;
    let mut accumulator = glv::jacobian(offsets[0]);
    for window in 0..32 {
        if window != 0 {
            for _ in 0..4 {
                let (next, entry) = glv::double(accumulator)?;
                accumulator = next;
                entries[ptr] = entry;
                ptr += 1;
            }
        }
        for (table, digits) in tables.iter().zip(&value.digits) {
            let digit = usize::from(digits[window]);
            let Some((next, entry)) = glv::checked_add(accumulator, table[digit])? else {
                return Ok((false, entries));
            };
            accumulator = next;
            entries[ptr] = entry;
            ptr += 1;
        }
    }
    for column in 0..COLUMNS {
        let base = glv::neg(glv::jacobian(value.points[column]));
        let Some((next, entry)) = glv::checked_add(accumulator, base)? else {
            return Ok((false, entries));
        };
        entries[ptr] = entry;
        ptr += 1;
        if value.skews[column] {
            accumulator = next;
        }
    }
    if ptr != FINAL_ENTRY {
        return Err(Invalid);
    }
    entries[ptr] = glv::complete_add(accumulator, glv::neg(glv::jacobian(offsets[1])))?;
    Ok((true, entries))
}

/// The first admissible selector (or the forced one) and its 3195 limbs.
pub(super) fn resolve(
    value: &BatchInput,
    bank: &[[Point; 2]],
) -> Result<(u16, Vec<u128>), Invalid> {
    validate(value)?;
    if bank.len() != BANK {
        return Err(Invalid);
    }
    let (tables, table_entries) = make_tables(value)?;
    let last = u16::try_from(BANK - 1).map_err(|_| Invalid)?;
    let choices = if value.forced {
        value.index..=value.index
    } else {
        0..=last
    };
    for index in choices {
        let offsets = *bank.get(usize::from(index)).ok_or(Invalid)?;
        let (valid, entries) = trial(value, offsets, &tables, &table_entries)?;
        if valid || value.forced {
            let limbs = glv::affine_limbs(&entries)?;
            return if limbs.len() == LIMBS {
                Ok((index, limbs))
            } else {
                Err(Invalid)
            };
        }
    }
    Err(Invalid)
}
