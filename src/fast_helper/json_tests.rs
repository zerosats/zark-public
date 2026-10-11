use super::*;

fn text(s: &str) -> Vec<u32> {
    s.chars().map(u32::from).collect()
}

fn utf16(s: &str, big_endian: bool) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|unit| {
            if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            }
        })
        .collect()
}

fn utf32(s: &str, big_endian: bool) -> Vec<u8> {
    s.chars()
        .flat_map(|c| {
            if big_endian {
                u32::from(c).to_be_bytes()
            } else {
                u32::from(c).to_le_bytes()
            }
        })
        .collect()
}

#[test]
fn request_shapes_decode_with_types_and_order() {
    let value = parse(br#" {"id": 7, "a": [null, true, false, 1.5, "x"], "b": {}} "#).unwrap();
    assert_eq!(
        value,
        Value::Object(vec![
            (text("id"), Value::Int(Int::U64(7))),
            (
                text("a"),
                Value::Array(vec![
                    Value::Null,
                    Value::Bool,
                    Value::Bool,
                    Value::Float,
                    Value::Str(text("x")),
                ])
            ),
            (text("b"), Value::Object(Vec::new())),
        ])
    );
    assert!(value.has_keys(&["id", "a"], &["b"]));
    assert!(!value.has_keys(&["id", "a"], &[]));
    assert!(!value.has_keys(&["id", "c"], &["a", "b"]));
    assert!(value.field("a").is_some() && value.field("c").is_none());
}

#[test]
fn integers_follow_the_reference_range_and_digit_limit() {
    let int = |raw: &str| parse(raw.as_bytes());
    assert_eq!(int("0"), Ok(Value::Int(Int::U64(0))));
    assert_eq!(int("-0"), Ok(Value::Int(Int::U64(0))));
    assert_eq!(
        int("18446744073709551615"),
        Ok(Value::Int(Int::U64(u64::MAX)))
    );
    assert_eq!(int("18446744073709551616"), Ok(Value::Int(Int::Other)));
    assert_eq!(int("-1"), Ok(Value::Int(Int::Other)));
    assert_eq!(int(&"9".repeat(4300)), Ok(Value::Int(Int::Other)));
    assert_eq!(int(&"9".repeat(4301)), Err(Malformed));
    let long = format!("1{}e1", "0".repeat(5000));
    for float in ["1.0", "1e5", "1E+5", "-0.0", "1.5e-3", long.as_str()] {
        assert_eq!(int(float), Ok(Value::Float), "{float}");
    }
    for bad in [
        "01",
        "1.",
        ".5",
        "-",
        "+1",
        "1e",
        "1e+",
        "0x10",
        "NaN",
        "Infinity",
        "-Infinity",
    ] {
        assert_eq!(int(bad), Err(Malformed), "{bad}");
    }
}

#[test]
fn strings_keep_lone_surrogates_and_reject_controls() {
    let string = |raw: &str| parse(raw.as_bytes());
    assert_eq!(
        string(r#""\"\\\/\b\f\n\r\t\u0041""#),
        Ok(Value::Str(vec![
            0x22, 0x5c, 0x2f, 0x08, 0x0c, 0x0a, 0x0d, 0x09, 0x41
        ]))
    );
    assert_eq!(string(r#""\ud83d\ude00""#), Ok(Value::Str(vec![0x1f600])));
    assert_eq!(string(r#""\ud800""#), Ok(Value::Str(vec![0xd800])));
    assert_eq!(
        string(r#""\udc00\ud800""#),
        Ok(Value::Str(vec![0xdc00, 0xd800]))
    );
    assert_eq!(
        string(r#""\ud800\u0041""#),
        Ok(Value::Str(vec![0xd800, 0x41]))
    );
    assert_eq!(string(r#""\ud800\n""#), Ok(Value::Str(vec![0xd800, 0x0a])));
    assert_eq!(string("\"\u{7f}\u{e9}\""), Ok(Value::Str(vec![0x7f, 0xe9])));
    for bad in [
        "\"\u{1f}\"",
        "\"\t\"",
        r#""\x""#,
        r#""\u12""#,
        r#""\u12g4""#,
        r#""\ud800\u12g4""#,
        r#""abc"#,
        r#""\"#,
    ] {
        assert_eq!(string(bad), Err(Malformed), "{bad:?}");
    }
    assert_eq!(parse(b"\"\xed\xa0\x80\""), Ok(Value::Str(vec![0xd800])));
    for bad in [
        &b"\"\xc0\x80\""[..],
        b"\"\xe0\x80\x80\"",
        b"\"\xed\xa0\"",
        b"\"\xf4\x90\x80\x80\"",
        b"\"\xff\"",
    ] {
        assert_eq!(parse(bad), Err(Malformed), "{bad:?}");
    }
}

#[test]
fn byte_encodings_are_detected_like_json_loads() {
    let document = r#"{"k": ["é", "😀"]}"#;
    let expected = parse(document.as_bytes()).unwrap();
    let mut variants = vec![
        [&b"\xef\xbb\xbf"[..], document.as_bytes()].concat(),
        utf16(document, true),
        utf16(document, false),
        utf32(document, true),
        utf32(document, false),
    ];
    variants.push([&b"\xfe\xff"[..], &utf16(document, true)].concat());
    variants.push([&b"\xff\xfe"[..], &utf16(document, false)].concat());
    variants.push([&b"\0\0\xfe\xff"[..], &utf32(document, true)].concat());
    variants.push([&b"\xff\xfe\0\0"[..], &utf32(document, false)].concat());
    for raw in variants {
        assert_eq!(parse(&raw).as_ref(), Ok(&expected), "{raw:?}");
    }
    assert_eq!(parse(&utf16("7", true)), Ok(Value::Int(Int::U64(7))));
    assert_eq!(parse(&utf16("7", false)), Ok(Value::Int(Int::U64(7))));
    let mut lone = utf16("\"", false);
    lone.extend([0x00, 0xd8]);
    lone.extend(utf16("\"", false));
    assert_eq!(parse(&lone), Ok(Value::Str(vec![0xd800])));
    let mut odd = utf16("[1]", true);
    odd.push(b' ');
    assert_eq!(parse(&odd), Err(Malformed));
    let mut beyond = utf32("\"", false);
    beyond.extend(0x11_0000u32.to_le_bytes());
    beyond.extend(utf32("\"", false));
    assert_eq!(parse(&beyond), Err(Malformed));
    assert_eq!(parse(b"\xef\xbb\xbf\xef\xbb\xbf1"), Err(Malformed));
}

#[test]
fn structure_errors_duplicates_and_constants_are_malformed() {
    for bad in [
        "",
        " ",
        "[1,]",
        "[1 2]",
        "{\"a\" 1}",
        "{\"a\":1,}",
        "{1:2}",
        "{'a':1}",
        "[1]]",
        "{} {}",
        "\u{c}1",
        "nul",
        "True",
        "{\"a\":1,\"a\":2}",
        "[{\"a\":{\"b\":1,\"b\":1}}]",
        "[NaN]",
        "{\"a\":-Infinity}",
    ] {
        assert_eq!(parse(bad.as_bytes()), Err(Malformed), "{bad:?}");
    }
    assert!(parse(b"{\"a\":1,\"\\u0061\\u0062\":2,\"ab\\u0000\":3}").is_ok());
    assert_eq!(
        parse(b"{\"\\u0061\":1,\"a\":2}"),
        Err(Malformed),
        "escaped and literal keys compare as code points"
    );
}

#[test]
fn the_deepest_request_sized_nesting_decodes() {
    let depth = super::super::rpc::MAX_REQUEST / 2;
    let raw = [b"[".repeat(depth), b"]".repeat(depth)].concat();
    assert!(matches!(parse(&raw), Ok(Value::Array(_))));
    let raw = [
        b"[".repeat(depth - 1),
        b"{}".to_vec(),
        b"]".repeat(depth - 1),
    ]
    .concat();
    assert!(matches!(parse(&raw), Ok(Value::Array(_))));
}
