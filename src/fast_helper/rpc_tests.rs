use super::*;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use serde_json::{Value as Json, json};
use std::sync::OnceLock;

/// secp256k1 group order minus one, big-endian.
const N_MINUS_ONE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
];

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| Tables::load().unwrap())
}

fn call_raw(raw: &[u8]) -> Json {
    serde_json::from_slice(&respond(tables(), raw)).unwrap()
}

fn call(request: &Json) -> Json {
    call_raw(&serde_json::to_vec(request).unwrap())
}

fn hexes(values: impl IntoIterator<Item = u128>) -> Json {
    values.into_iter().map(|v| format!("{v:064x}")).collect()
}

fn small_scalar(value: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[31] = value;
    bytes
}

/// The circuit's signed 6-bit windows: 43 raw windows of a canonical scalar.
fn recode(scalar: [u8; 32]) -> ([u8; 42], [bool; 42]) {
    let bit = |i: usize| i < 256 && (scalar[31 - i / 8] >> (i % 8)) & 1 == 1;
    let raw: Vec<u8> = (0..43)
        .map(|w| (0..6).map(|b| u8::from(bit(6 * w + b)) << b).sum())
        .collect();
    let signs: [bool; 42] = std::array::from_fn(|i| raw[i + 1] & 1 == 0);
    let indices = std::array::from_fn(|i| {
        if signs[i] {
            31 - (raw[i] >> 1)
        } else {
            raw[i] >> 1
        }
    });
    (indices, signs)
}

fn fixed_request(scalar: [u8; 32]) -> Json {
    let (indices, signs) = recode(scalar);
    json!({"jsonrpc": "2.0", "id": 7, "method": "resolve_foreign_call", "params": [{
        "session_id": 8, "function": FIXED_ORACLE,
        "inputs": [hexes(indices.map(u128::from)), hexes(signs.map(u128::from))]}]})
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

fn multiple(k: u64) -> Point {
    let point = (ProjectivePoint::GENERATOR * Scalar::from(k))
        .to_affine()
        .to_encoded_point(false);
    Point {
        x: coordinate(point.x().unwrap()),
        y: coordinate(point.y().unwrap()),
    }
}

struct Glv {
    k: u64,
    negate: bool,
    forced: bool,
    index: u8,
    digit_step: u128,
    skews: [u128; 2],
}

fn glv_request(case: &Glv, id: u64) -> Json {
    let first = multiple(case.k);
    let second = Point {
        x: first.x * Fp::beta(),
        y: if case.negate { -first.y } else { first.y },
    };
    let points = [first.x, first.y, second.x, second.y]
        .into_iter()
        .flat_map(Fp::limbs);
    let digits = (0..64).map(|i| (i * case.digit_step + 3) % 16);
    json!({"jsonrpc": "2.0", "id": id, "method": "resolve_foreign_call", "params": [{
        "session_id": 8, "function": GLV_ORACLE,
        "inputs": [hexes(points), hexes(digits), hexes(case.skews),
            format!("{:x}", u8::from(case.negate)), format!("{:x}", u8::from(case.forced)),
            format!("{:x}", case.index)]}]})
}

fn error_of(response: &Json) -> (Json, i64) {
    (
        response["id"].clone(),
        response["error"]["code"].as_i64().unwrap(),
    )
}

#[test]
fn fixed_transcript_matches_independent_affine_steps() {
    let mut scalars: Vec<[u8; 32]> = [0, 1, 2, 31, 32, 63, 64].map(small_scalar).to_vec();
    let mut two_pow_128 = [0; 32];
    two_pow_128[15] = 1;
    let mut two_pow_255 = [0; 32];
    two_pow_255[0] = 0x80;
    scalars.extend([two_pow_128, two_pow_255, N_MINUS_ONE]);
    let table = &tables().fixed;
    for scalar in scalars {
        let (indices, signs) = recode(scalar);
        let signed = |window: usize| {
            let point = table[window][usize::from(indices[window])];
            (point.x, if signs[window] { -point.y } else { point.y })
        };
        let (mut x, mut y) = signed(0);
        let mut expected = Vec::new();
        for window in 1..42 {
            let (u, v) = signed(window);
            let slope = (v - y) * (u - x).invert().unwrap();
            let nx = slope * slope - x - u;
            let ny = slope * (x - nx) - y;
            expected.extend([slope, nx, ny].into_iter().flat_map(Fp::limbs));
            (x, y) = (nx, ny);
        }
        let response = call(&fixed_request(scalar));
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["values"], json!([hexes(expected)]));
        let mut request = fixed_request(scalar);
        request["id"] = json!(u64::MAX);
        request["params"][0]["session_id"] = json!(0);
        let again = call(&request);
        assert_eq!(again["id"], json!(u64::MAX));
        assert_eq!(again["result"], response["result"]);
    }
}

#[test]
fn responses_match_reference_bytes() {
    // SHA-256 of the retired Python helper's responses to the same requests.
    let digest = |raw: Vec<u8>| hex::encode(zark_protocol::hash(&[&respond(tables(), &raw)]));
    let cases = [
        (
            Glv {
                k: 1,
                negate: false,
                forced: false,
                index: 0,
                digit_step: 7,
                skews: [1, 0],
            },
            7,
            "79b62be5c310546404aa49a2a4345ddc6f82f2cbd42f8f5802e4d23e233d2cdd",
        ),
        (
            Glv {
                k: 12345,
                negate: true,
                forced: true,
                index: 200,
                digit_step: 5,
                skews: [0, 1],
            },
            u64::MAX,
            "e8b23e4b6db7d24a24afa1e67dd650fcfd53f93a388735fecb2b170be79d5c05",
        ),
        (
            Glv {
                k: 0xdead_beef,
                negate: false,
                forced: false,
                index: 0,
                digit_step: 11,
                skews: [1, 1],
            },
            0,
            "836e7f607f553f46d4e6abac40056c9187a6f22f202f934b44200410ffe04821",
        ),
    ];
    for (case, id, expected) in cases {
        let raw = serde_json::to_vec(&glv_request(&case, id)).unwrap();
        assert_eq!(digest(raw), expected, "GLV k={}", case.k);
    }
    let mut request = fixed_request(N_MINUS_ONE);
    request["params"][0]["session_id"] = json!(0);
    assert_eq!(
        digest(serde_json::to_vec(&request).unwrap()),
        "51f80bf2124dc44206970c04380ae04a29adf6d20ecb0302dd76c6381f7462b9"
    );
    let mut two_pow_255 = [0; 32];
    two_pow_255[0] = 0x80;
    let mut request = fixed_request(two_pow_255);
    request["id"] = json!(u64::MAX);
    request["params"][0]["session_id"] = json!(0);
    assert_eq!(
        digest(serde_json::to_vec(&request).unwrap()),
        "3aaeaa535d56cb258cc868b10d4de6a718bdcad165c8658ae87e1ecfbfe10e8e"
    );
}

#[test]
fn direct_hex_encoding_preserves_padding_and_full_width_values() {
    let values = vec![0, 1, 15, 16, 1 << 64, 1 << 119, 1 << 127, u128::MAX];
    let fields = values
        .iter()
        .map(|v| format!("\"{v:064x}\""))
        .collect::<Vec<_>>()
        .join(",");
    for id in [0, 1, u64::MAX] {
        for (answer, body) in [
            (Answer::Fixed(values.clone()), format!("[{fields}]")),
            (
                Answer::Glv {
                    selected: 255,
                    transcript: values.clone(),
                },
                format!("\"{:064x}\",[{fields}]", 255),
            ),
            (
                Answer::Batch {
                    selected: 511,
                    transcript: values.clone(),
                },
                format!("\"{:064x}\",[{fields}]", 511),
            ),
        ] {
            let expected =
                format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"values":[{body}]}}}}"#);
            assert_eq!(result(id, &answer), expected.as_bytes());
        }
    }
}

#[test]
fn malformed_private_requests_fail_without_echo() {
    let mut cases = Vec::new();
    for value in [
        json!(-1),
        json!(32),
        json!(false),
        Json::Null,
        json!([]),
        json!({}),
        json!("PRIVATE_SENTINEL"),
        json!("0".repeat(65)),
        json!("-1"),
        json!("20"),
        json!("0X1"),
        json!("0x"),
        json!(" 1"),
    ] {
        let mut request = fixed_request(small_scalar(1));
        request["params"][0]["inputs"][0][0] = value;
        cases.push((request, json!(7), -32602));
    }
    for (key, value, id, code) in [
        ("method", json!("PRIVATE_SENTINEL"), json!(7), -32601),
        ("id", json!("PRIVATE_SENTINEL"), Json::Null, -32600),
        ("jsonrpc", json!("1.0"), json!(7), -32600),
    ] {
        let mut request = fixed_request(small_scalar(1));
        request[key] = value;
        cases.push((request, id, code));
    }
    let mut request = fixed_request(small_scalar(1));
    request["params"][0]["inputs"][0]
        .as_array_mut()
        .unwrap()
        .pop();
    cases.push((request, json!(7), -32602));
    let mut request = fixed_request(small_scalar(1));
    request["params"][0]["function"] = json!("PRIVATE_SENTINEL");
    cases.push((request, json!(7), -32601));
    for (request, id, code) in cases {
        let raw = respond(tables(), &serde_json::to_vec(&request).unwrap());
        assert!(!raw.windows(7).any(|w| w == b"PRIVATE"));
        let response: Json = serde_json::from_slice(&raw).unwrap();
        assert_eq!(error_of(&response), (id, code), "{request}");
    }
    let oversized = b"{}".repeat(MAX_REQUEST);
    let raw_cases: [(&[u8], i64); 6] = [
        (b"", -32600),
        (b"{", -32700),
        (&oversized, -32600),
        (br#"{"id":1,"id":2}"#, -32700),
        (b"NaN", -32700),
        (b"[]", -32600),
    ];
    for (raw, code) in raw_cases {
        assert_eq!(error_of(&call_raw(raw)), (Json::Null, code), "{raw:?}");
    }
}

fn edited(request: &Json, edit: impl Fn(&mut Json)) -> (Json, i64) {
    let mut request = request.clone();
    edit(&mut request);
    error_of(&call(&request))
}

#[test]
fn envelope_checks_follow_the_reference_order() {
    let base = fixed_request(small_scalar(1));
    let invalid_request = (Json::Null, -32600);
    assert_eq!(edited(&base, |r| r["id"] = json!(true)), invalid_request);
    assert_eq!(edited(&base, |r| r["id"] = json!(1.0)), invalid_request);
    assert_eq!(edited(&base, |r| r["id"] = json!(-1)), invalid_request);
    assert_eq!(
        edited(&base, |r| r["id"] =
            serde_json::from_str("18446744073709551616").unwrap()),
        invalid_request
    );
    assert_eq!(edited(&base, |r| r["extra"] = json!(1)), (json!(7), -32600));
    assert_eq!(
        edited(&base, |r| r["method"] = json!(["x"])),
        (json!(7), -32601)
    );
    let without_params = |r: &mut Json| {
        r.as_object_mut().unwrap().remove("params");
    };
    assert_eq!(edited(&base, without_params), (json!(7), -32600));
    let params = (json!(7), -32602);
    assert_eq!(edited(&base, |r| r["params"] = json!({})), params);
    assert_eq!(
        edited(&base, |r| r["params"] =
            json!([r["params"][0], r["params"][0]])),
        params
    );
    assert_eq!(
        edited(&base, |r| r["params"][0]["extra"] = json!(1)),
        params
    );
    assert_eq!(
        edited(&base, |r| r["params"][0]["session_id"] =
            json!(u64::MAX as f64)),
        params
    );
    assert_eq!(
        edited(&base, |r| r["params"][0]["root_path"] =
            json!("r".repeat(1025))),
        params
    );
    assert_eq!(
        edited(&base, |r| r["params"][0]["package_name"] = json!(1)),
        params
    );
    let labelled_unknown = |r: &mut Json| {
        r["params"][0]["root_path"] = json!("r".repeat(1024));
        r["params"][0]["function"] = json!(7);
    };
    assert_eq!(edited(&base, labelled_unknown), (json!(7), -32601));
    let mut request = base;
    request["params"][0]["root_path"] = json!("é".repeat(1024));
    request["params"][0]["package_name"] = json!("");
    request["params"][0]["inputs"][0][0] = json!("0x".to_owned() + &"0".repeat(63) + "1");
    assert!(call(&request)["result"].is_object());
}

#[test]
fn off_curve_and_inconsistent_glv_inputs_fail() {
    let zeros = |n: usize| json!(vec!["0"; n]);
    let mut request = fixed_request(small_scalar(1));
    request["params"][0]["function"] = json!(GLV_ORACLE);
    request["params"][0]["inputs"] = json!([zeros(12), zeros(64), zeros(2), "0", "0", "0"]);
    assert_eq!(error_of(&call(&request)), (json!(7), -32602));
    let case = Glv {
        k: 3,
        negate: false,
        forced: false,
        index: 0,
        digit_step: 7,
        skews: [0, 0],
    };
    let valid = glv_request(&case, 9);
    assert!(call(&valid)["result"].is_object());
    let params = (json!(9), -32602);
    let wrong_sign = |r: &mut Json| r["params"][0]["inputs"][3] = json!("1");
    assert_eq!(edited(&valid, wrong_sign), params);
    let unforced_index = |r: &mut Json| r["params"][0]["inputs"][5] = json!("1");
    assert_eq!(edited(&valid, unforced_index), params);
    let wide_digit = |r: &mut Json| r["params"][0]["inputs"][1][0] = json!("10");
    assert_eq!(edited(&valid, wide_digit), params);
    let wide_limb = |r: &mut Json| {
        r["params"][0]["inputs"][0][0] = json!(format!("{:x}", 1u128 << 120));
    };
    assert_eq!(edited(&valid, wide_limb), params);
    let wide_top_limb = |r: &mut Json| {
        r["params"][0]["inputs"][0][2] = json!(format!("{:x}", 1u128 << 16));
    };
    assert_eq!(edited(&valid, wide_top_limb), params);
    let short = |r: &mut Json| {
        r["params"][0]["inputs"].as_array_mut().unwrap().pop();
    };
    assert_eq!(edited(&valid, short), params);
}
