//! Immutable public constants compiled into the helper and authenticated before
//! it binds or reports readiness. They are never a cache of answers.
//!
//! The GLV offset bank is maintained beside the donor sources. The 512-entry
//! batch bank is the pinned circuit table itself and must extend that bank
//! exactly. The fixed-
//! generator ROM is the pinned circuit table itself; the two sources whose
//! semantics the fixed-generator model mirrors are pinned with it, so a changed
//! circuit source cannot silently pair with a stale model.
use super::field::{Fp, Point};
use super::fixed::{TABLE_WIDTH, Table, WINDOWS};
use serde::Deserialize;
use zark_protocol::hash;

const BANK: &[u8] = include_bytes!("../../runtime/fast-prover/helper/bank.json");
const BANK_SHA256: &str = "60b8a2215854fe4e402dc5c0bfd2198ea87e110d2415b477e5236db0e5677435";
const BANK_SIZE: usize = 256;
const WIDE_BANK: &[u8] =
    include_bytes!("../../circuits/vendor/noir_bigcurve/src/glv_offset_table_wide.nr");
const WIDE_BANK_SHA256: &str = "230f03bbdc9039c019d325953bd127182ecce73ba07488bca8886fa6d6485736";
const ROM: &[u8] = include_bytes!("../../circuits/fixed-generator/src/tables.nr");
const SOURCE_PINS: [(&[u8], &str); 3] = [
    (
        include_bytes!("../../circuits/fixed-generator/src/batch_hint.nr"),
        "9835f11b0eda11e0c6e674a34373b3d3a590bc4144fa57da5bfc0a5fd87bef48",
    ),
    (
        ROM,
        "f121f3520544f5c4cd1433ef12003eba5723e5d2410bcc6c4ea8e5432e9ab1ce",
    ),
    (
        include_bytes!("../../circuits/fixed-generator/src/digits.nr"),
        "2214e37dd559f3c65a829ad79d5ae839aff76d1410392110069c413b629687f5",
    ),
];
const ROM_DECLARATION: &str = "pub global POINTS:";
const WIDE_BANK_DECLARATION: &str = "pub global POINTS: [[[[u128;3];2];2];512] = ";

type RawPoint = [[u128; 3]; 2];

pub struct Tables {
    pub(super) bank: Vec<[Point; 2]>,
    pub(super) wide_bank: Vec<[Point; 2]>,
    pub(super) fixed: Box<Table>,
}

/// An embedded constant failed authentication or validation.
#[derive(Debug)]
pub(super) struct Corrupt;

impl Tables {
    pub(super) fn load() -> Result<Self, Corrupt> {
        let pinned = |bytes: &[u8], pin: &str| hex::encode(hash(&[bytes])) == pin;
        if !pinned(BANK, BANK_SHA256)
            || !pinned(WIDE_BANK, WIDE_BANK_SHA256)
            || !SOURCE_PINS.iter().all(|(b, pin)| pinned(b, pin))
        {
            return Err(Corrupt);
        }
        let bank = load_bank()?;
        let wide_bank = load_wide_bank()?;
        if wide_bank[..BANK_SIZE] != bank[..] {
            return Err(Corrupt);
        }
        Ok(Self {
            bank,
            wide_bank,
            fixed: load_rom()?,
        })
    }
}

fn point(raw: &RawPoint) -> Result<Point, Corrupt> {
    let x = Fp::from_limbs(raw[0], true).ok_or(Corrupt)?;
    let y = Fp::from_limbs(raw[1], true).ok_or(Corrupt)?;
    let point = Point { x, y };
    point.on_curve().then_some(point).ok_or(Corrupt)
}

fn load_bank() -> Result<Vec<[Point; 2]>, Corrupt> {
    #[derive(Deserialize)]
    struct Bank {
        points: Vec<[RawPoint; 2]>,
    }
    let bank: Bank = serde_json::from_slice(BANK).map_err(|_| Corrupt)?;
    if bank.points.len() != BANK_SIZE {
        return Err(Corrupt);
    }
    bank.points
        .iter()
        .map(|[initial, last]| Ok([point(initial)?, point(last)?]))
        .collect()
}

fn load_wide_bank() -> Result<Vec<[Point; 2]>, Corrupt> {
    let text = std::str::from_utf8(WIDE_BANK).map_err(|_| Corrupt)?;
    let mut declarations = text.lines().filter(|l| l.starts_with(ROM_DECLARATION));
    let (Some(line), None) = (declarations.next(), declarations.next()) else {
        return Err(Corrupt);
    };
    let literal = line
        .strip_prefix(WIDE_BANK_DECLARATION)
        .and_then(|value| value.strip_suffix(';'))
        .ok_or(Corrupt)?;
    let rows: Vec<[RawPoint; 2]> = serde_json::from_str(literal).map_err(|_| Corrupt)?;
    if rows.len() != super::glv_batch::BANK {
        return Err(Corrupt);
    }
    rows.iter()
        .map(|[initial, last]| Ok([point(initial)?, point(last)?]))
        .collect()
}

fn load_rom() -> Result<Box<Table>, Corrupt> {
    let text = std::str::from_utf8(ROM).map_err(|_| Corrupt)?;
    let mut declarations = text.lines().filter(|l| l.starts_with(ROM_DECLARATION));
    let (Some(line), None) = (declarations.next(), declarations.next()) else {
        return Err(Corrupt);
    };
    let literal = line
        .split_once(" = ")
        .and_then(|(_, value)| value.strip_suffix(';'))
        .ok_or(Corrupt)?;
    let rows: Vec<Vec<RawPoint>> = serde_json::from_str(literal).map_err(|_| Corrupt)?;
    if rows.len() != WINDOWS || rows.iter().any(|row| row.len() != TABLE_WIDTH) {
        return Err(Corrupt);
    }
    let mut table = Vec::with_capacity(WINDOWS);
    for row in &rows {
        let mut points = [Point {
            x: Fp::ZERO,
            y: Fp::ZERO,
        }; TABLE_WIDTH];
        for (slot, raw) in points.iter_mut().zip(row) {
            *slot = point(raw)?;
        }
        table.push(points);
    }
    table.into_boxed_slice().try_into().map_err(|_| Corrupt)
}

#[cfg(test)]
#[path = "tables_tests.rs"]
mod tests;
