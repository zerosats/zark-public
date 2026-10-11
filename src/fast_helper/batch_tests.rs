//! `zark_glv_batch_hint_v1`: request shapes, selector bounds, size budgets and
//! an independent k256 check of each transcript endpoint.
use super::*;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use serde_json::{Value as Json, json};
use std::sync::OnceLock;

#[path = "helper_perf_tests.rs"]
mod perf;

/// The endomorphism eigenvalue paired with `Fp::beta()`: phi(x, y) = (beta x, y) = [LAMBDA](x, y).
const LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0, 0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
    0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78, 0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
];

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| Tables::load().unwrap())
}

fn lambda() -> Scalar {
    Scalar::from_repr(LAMBDA.into()).unwrap()
}

fn coordinate(bytes: &[u8]) -> Fp {
    let bytes: [u8; 32] = bytes.try_into().unwrap();
    let high = u128::from_be_bytes(bytes[..16].try_into().unwrap());
    let low = u128::from_be_bytes(bytes[16..].try_into().unwrap());
    let mask = (1 << 120) - 1;
    Fp::from_limbs(
        [low & mask, ((low >> 120) | (high << 8)) & mask, high >> 112],
        true,
    )
    .unwrap()
}

/// `[s]G` as canonical coordinates, or None at infinity.
fn point(s: Scalar) -> Option<Point> {
    let encoded = (ProjectivePoint::GENERATOR * s)
        .to_affine()
        .to_encoded_point(false);
    Some(Point {
        x: coordinate(encoded.x()?),
        y: coordinate(encoded.y()?),
    })
}

struct Case {
    /// Discrete logs of the four independent columns (Q0, Q1, S0, S1).
    logs: [u64; 4],
    negate: [bool; 2],
    digits: [[u8; 32]; 6],
    skews: [bool; 6],
    forced: bool,
    index: u16,
}

impl Case {
    fn new(seed: u64) -> Self {
        let digit = |c: usize, w: usize| ((seed as usize * 7 + c * 5 + w * 3) % 16) as u8;
        Self {
            logs: [seed + 2, seed * 3 + 5, seed * 7 + 11, seed * 13 + 17],
            negate: [seed.is_multiple_of(2), seed.is_multiple_of(3)],
            digits: std::array::from_fn(|c| std::array::from_fn(|w| digit(c, w))),
            skews: std::array::from_fn(|c| (seed as usize + c).is_multiple_of(2)),
            forced: false,
            index: 0,
        }
    }

    /// Each column as a multiple of G: images are [+-lambda] times their base.
    fn column_logs(&self) -> [Scalar; 6] {
        let image = |base: Scalar, negate: bool| {
            let s = base * lambda();
            if negate { -s } else { s }
        };
        let [a, b, c, d] = self.logs.map(Scalar::from);
        [
            a,
            image(a, self.negate[0]),
            b,
            image(b, self.negate[1]),
            c,
            d,
        ]
    }

    fn columns(&self) -> [Point; 6] {
        self.column_logs().map(|s| point(s).unwrap())
    }

    /// The walk's group result: sum of (sum_w (2 d_w - 15) 16^(31-w) - skew) * column.
    fn expected(&self) -> Option<Point> {
        let logs = self.column_logs();
        let mut total = Scalar::ZERO;
        for (column, log) in logs.iter().enumerate() {
            let mut value = Scalar::ZERO;
            for &d in &self.digits[column] {
                value = value * Scalar::from(16u64) + Scalar::from(2 * u64::from(d))
                    - Scalar::from(15u64);
            }
            if self.skews[column] {
                value -= Scalar::ONE;
            }
            total += value * log;
        }
        point(total)
    }

    fn request(&self, id: u64) -> Json {
        let points = self
            .columns()
            .into_iter()
            .flat_map(|p| [p.x, p.y])
            .flat_map(Fp::limbs);
        let words = self.digits.map(|column| {
            column
                .iter()
                .enumerate()
                .fold(0u128, |word, (w, &d)| word | (u128::from(d) << (4 * w)))
        });
        json!({"jsonrpc": "2.0", "id": id, "method": "resolve_foreign_call", "params": [{
            "session_id": 8, "function": BATCH_ORACLE,
            "inputs": [hexes(points), hexes(words), hexes(self.skews.map(u128::from)),
                hexes(self.negate.map(u128::from)), format!("{:x}", u8::from(self.forced)),
                format!("{:x}", self.index)]}]})
    }
}

fn hexes(values: impl IntoIterator<Item = u128>) -> Json {
    values.into_iter().map(|v| format!("{v:064x}")).collect()
}

fn call(request: &Json) -> (Vec<u8>, Json) {
    let raw = respond(tables(), &serde_json::to_vec(request).unwrap());
    let json = serde_json::from_slice(&raw).unwrap();
    (raw, json)
}

/// (selected, transcript limbs) of a successful answer.
fn answer(response: &Json) -> (u128, Vec<u128>) {
    let values = response["result"]["values"].as_array().unwrap();
    let parse = |v: &Json| u128::from_str_radix(v.as_str().unwrap(), 16).unwrap();
    let limbs: Vec<u128> = values[1].as_array().unwrap().iter().map(parse).collect();
    (parse(&values[0]), limbs)
}

fn error_code(response: &Json) -> i64 {
    response["error"]["code"].as_i64().unwrap()
}

fn endpoint(limbs: &[u128]) -> Point {
    let row = &limbs[(glv_batch::ENTRIES - 1) * 9..];
    Point {
        x: Fp::from_limbs([row[3], row[4], row[5]], true).unwrap(),
        y: Fp::from_limbs([row[6], row[7], row[8]], true).unwrap(),
    }
}

#[test]
fn transcript_endpoints_match_independent_group_sums() {
    for seed in 0..12 {
        let case = Case::new(seed);
        let (raw, response) = call(&case.request(seed));
        assert_eq!(response["id"], seed);
        let (selected, limbs) = answer(&response);
        assert_eq!(limbs.len(), glv_batch::LIMBS);
        assert!(selected < 512);
        assert!(
            raw.len() > 192 * 1024 && raw.len() <= 256 * 1024,
            "batch answer needs its own budget"
        );
        assert_eq!(endpoint(&limbs), case.expected().unwrap(), "seed {seed}");
        // A repeated request is answered identically; nothing is cached.
        assert_eq!(call(&case.request(seed)).0, raw);
    }
}

#[test]
fn requests_fit_the_shared_request_budget() {
    let mut case = Case::new(3);
    case.digits = [[15; 32]; 6];
    case.index = 511;
    case.forced = true;
    let mut request = case.request(u64::MAX);
    request["params"][0]["root_path"] = json!("/".repeat(1024));
    request["params"][0]["package_name"] = json!("p".repeat(1024));
    let size = serde_json::to_vec(&request).unwrap().len();
    assert!(size < MAX_REQUEST, "{size} bytes");
}

#[test]
fn forced_selectors_across_the_wide_bank() {
    let mut case = Case::new(5);
    let expected = case.expected().unwrap();
    for index in [255u16, 256, 511] {
        case.forced = true;
        case.index = index;
        let (selected, limbs) = answer(&call(&case.request(1)).1);
        assert_eq!(selected, u128::from(index));
        assert_eq!(endpoint(&limbs), expected, "selector {index}");
    }
    for index in [512u16, 600, u16::MAX] {
        case.index = index;
        assert_eq!(
            error_code(&call(&case.request(1)).1),
            -32602,
            "selector {index}"
        );
    }
    case.forced = false;
    case.index = 1;
    assert_eq!(
        error_code(&call(&case.request(1)).1),
        -32602,
        "unforced selector must be zero"
    );
}

#[test]
fn inadmissible_offset_is_skipped_or_returned_with_zero_suffix() {
    // Put column 0 on offset 0 and make its first digit +1: the first addition
    // of offset 0 has equal x-coordinates.
    let mut case = Case::new(7);
    let offset = tables().wide_bank[0][0];
    let mut response = case.request(2);
    let limbs = |p: Point| {
        [p.x, p.y]
            .into_iter()
            .flat_map(Fp::limbs)
            .collect::<Vec<_>>()
    };
    let image = Point {
        x: offset.x * Fp::beta(),
        y: if case.negate[0] { -offset.y } else { offset.y },
    };
    let mut points: Vec<u128> = response["params"][0]["inputs"][0]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| u128::from_str_radix(v.as_str().unwrap(), 16).unwrap())
        .collect();
    points.splice(0..12, limbs(offset).into_iter().chain(limbs(image)));
    case.digits[0][0] = 8;
    let mut words = case.request(2)["params"][0]["inputs"][1].clone();
    let word = case.digits[0]
        .iter()
        .enumerate()
        .fold(0u128, |w, (i, &d)| w | (u128::from(d) << (4 * i)));
    words[0] = json!(format!("{word:064x}"));
    response["params"][0]["inputs"][0] = hexes(points);
    response["params"][0]["inputs"][1] = words;
    let (selected, _) = answer(&call(&response).1);
    assert!(selected >= 1, "offset 0 must be inadmissible");

    response["params"][0]["inputs"][4] = json!("1");
    response["params"][0]["inputs"][5] = json!("0");
    let (selected, forced) = answer(&call(&response).1);
    assert_eq!(selected, 0);
    let row = |r: usize| &forced[r * 9..(r + 1) * 9];
    assert!(
        (0..32).all(|r| row(r).iter().any(|&l| l != 0)),
        "table prefix"
    );
    assert!(
        (32..glv_batch::ENTRIES).all(|r| row(r).iter().all(|&l| l == 0)),
        "zero suffix"
    );
}

#[test]
fn malformed_and_inconsistent_inputs_fail_without_echo() {
    let case = Case::new(4);
    type Edit = (&'static str, fn(&mut Json));
    let edits: [Edit; 7] = [
        ("short points", |r| {
            r["params"][0]["inputs"][0].as_array_mut().unwrap().pop();
        }),
        ("seven words", |r| {
            r["params"][0]["inputs"][1]
                .as_array_mut()
                .unwrap()
                .push(json!("0"));
        }),
        ("non-bit skew", |r| {
            r["params"][0]["inputs"][2][0] = json!("2")
        }),
        ("non-bit sign", |r| {
            r["params"][0]["inputs"][3][1] = json!("2")
        }),
        ("17-bit selector", |r| {
            r["params"][0]["inputs"][5] = json!("10000")
        }),
        ("wrong image", |r| {
            r["params"][0]["inputs"][0][6] = json!(format!("{:064x}", 1))
        }),
        ("off-curve", |r| {
            r["params"][0]["inputs"][0][33] = json!(format!("{:064x}", 5))
        }),
    ];
    for (name, edit) in edits {
        let mut request = case.request(9);
        edit(&mut request);
        let (raw, response) = call(&request);
        assert_eq!(response["id"], 9, "{name}");
        assert_eq!(error_code(&response), -32602, "{name}");
        assert!(raw.len() < 200, "{name}: errors carry no inputs");
    }
}
