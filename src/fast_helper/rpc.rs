//! JSON-RPC `resolve_foreign_call` dispatch with the reference's exact checks,
//! check order, result encoding and fixed error messages.
//!
//! Errors never include parser details, inputs, field values or identifiers
//! other than a validated numeric request ID.
use super::field::{Fp, Point};
use super::json::{self, Int, Value};
use super::{fixed, glv, glv_batch, tables::Tables};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(super) const MAX_REQUEST: usize = 16 * 1024;
const MAX_RESPONSE: usize = 192 * 1024;
/// 3195 64-hex-digit limbs, a selector and framing: about 214 KB.
const MAX_BATCH_RESPONSE: usize = 256 * 1024;
const MAX_LABEL: usize = 1024;
pub(super) const GLV_ORACLE: &str = "zark_glv_hint_v1";
pub(super) const FIXED_ORACLE: &str = "zark_fixed_generator_hint_v1";
pub(super) const BATCH_ORACLE: &str = "zark_glv_batch_hint_v1";

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Code {
    Parse,
    Request,
    Method,
    Params,
    Internal,
}

impl Code {
    fn wire(self) -> (i32, &'static str) {
        match self {
            Self::Parse => (-32700, "Parse error"),
            Self::Request => (-32600, "Invalid request"),
            Self::Method => (-32601, "Method not found"),
            Self::Params => (-32602, "Invalid parameters"),
            Self::Internal => (-32603, "Internal error"),
        }
    }
}

enum Answer {
    Glv {
        selected: u8,
        transcript: Vec<u128>,
    },
    Batch {
        selected: u16,
        transcript: Vec<u128>,
    },
    Fixed(Vec<u128>),
}

/// The complete response body for one request body.
pub fn respond(tables: &Tables, raw: &[u8]) -> Vec<u8> {
    let (encoded, limit) = match dispatch(tables, raw) {
        Ok((id, answer @ Answer::Batch { .. })) => (result(id, &answer), MAX_BATCH_RESPONSE),
        Ok((id, answer)) => (result(id, &answer), MAX_RESPONSE),
        Err((id, code)) => (error(id, code), MAX_RESPONSE),
    };
    if encoded.len() > limit {
        error(None, Code::Internal)
    } else {
        encoded
    }
}

/// The body sent with HTTP-level rejections.
pub(super) fn rejected() -> Vec<u8> {
    error(None, Code::Request)
}

fn error(id: Option<u64>, code: Code) -> Vec<u8> {
    let (number, message) = code.wire();
    let id = id.map_or_else(|| "null".to_owned(), |id| id.to_string());
    format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{number},"message":"{message}"}}}}"#)
        .into_bytes()
}

fn result(id: u64, answer: &Answer) -> Vec<u8> {
    // Preserve the existing 64-digit field encoding. Every returned limb is
    // u128: write the fixed zero prefix and the 16 value bytes directly rather
    // than running the general padding formatter for thousands of fields.
    fn field(out: &mut Vec<u8>, value: u128) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [b'0'; 66];
        encoded[0] = b'"';
        encoded[65] = b'"';
        for (digits, byte) in encoded[33..65].chunks_exact_mut(2).zip(value.to_be_bytes()) {
            digits[0] = HEX[usize::from(byte >> 4)];
            digits[1] = HEX[usize::from(byte & 15)];
        }
        out.extend_from_slice(&encoded);
    }
    fn limbs(out: &mut Vec<u8>, limbs: &[u128]) {
        out.push(b'[');
        for (i, limb) in limbs.iter().enumerate() {
            if i != 0 {
                out.push(b',');
            }
            field(out, *limb);
        }
        out.push(b']');
    }
    let fields = match answer {
        Answer::Glv { transcript, .. } | Answer::Batch { transcript, .. } => transcript.len() + 1,
        Answer::Fixed(output) => output.len(),
    };
    let mut out = Vec::with_capacity(100 + fields * 67);
    out.extend_from_slice(
        format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"values":["#).as_bytes(),
    );
    match answer {
        Answer::Glv {
            selected,
            transcript,
        } => {
            field(&mut out, u128::from(*selected));
            out.push(b',');
            limbs(&mut out, transcript);
        }
        Answer::Batch {
            selected,
            transcript,
        } => {
            field(&mut out, u128::from(*selected));
            out.push(b',');
            limbs(&mut out, transcript);
        }
        Answer::Fixed(output) => limbs(&mut out, output),
    }
    out.extend_from_slice(b"]}}");
    out
}

type Failure = (Option<u64>, Code);

fn dispatch(tables: &Tables, raw: &[u8]) -> Result<(u64, Answer), Failure> {
    if raw.is_empty() || raw.len() > MAX_REQUEST {
        return Err((None, Code::Request));
    }
    let request = json::parse(raw).map_err(|_| (None, Code::Parse))?;
    if !matches!(request, Value::Object(_)) {
        return Err((None, Code::Request));
    }
    // jsonrpsee's HTTP client uses numeric request IDs. Never echo arbitrary text.
    let Some(&Value::Int(Int::U64(id))) = request.field("id") else {
        return Err((None, Code::Request));
    };
    let fail = |code| (Some(id), code);
    if !request.has_keys(&["jsonrpc", "id", "method", "params"], &[])
        || !request.field("jsonrpc").is_some_and(|v| v.is_str("2.0"))
    {
        return Err(fail(Code::Request));
    }
    if !request
        .field("method")
        .is_some_and(|v| v.is_str("resolve_foreign_call"))
    {
        return Err(fail(Code::Method));
    }
    let params = request.field("params").ok_or(fail(Code::Params))?;
    // An unexpected panic is answered like the reference's catch-all handler.
    match catch_unwind(AssertUnwindSafe(|| call(tables, params))) {
        Ok(Ok(answer)) => Ok((id, answer)),
        Ok(Err(code)) => Err(fail(code)),
        Err(_) => Err(fail(Code::Internal)),
    }
}

fn call(tables: &Tables, params: &Value) -> Result<Answer, Code> {
    let Value::Array(params) = params else {
        return Err(Code::Params);
    };
    let [call @ Value::Object(_)] = params.as_slice() else {
        return Err(Code::Params);
    };
    if !call.has_keys(
        &["session_id", "function", "inputs"],
        &["root_path", "package_name"],
    ) || !matches!(call.field("session_id"), Some(Value::Int(Int::U64(_))))
    {
        return Err(Code::Params);
    }
    for label in ["root_path", "package_name"] {
        match call.field(label) {
            None => {}
            Some(Value::Str(text)) if text.len() <= MAX_LABEL => {}
            Some(_) => return Err(Code::Params),
        }
    }
    let function = call.field("function").ok_or(Code::Params)?;
    let inputs = call.field("inputs").ok_or(Code::Params)?;
    if function.is_str(GLV_ORACLE) {
        let value = glv_input(inputs)?;
        let (selected, transcript) =
            glv::resolve(&value, &tables.bank).map_err(|glv::Invalid| Code::Params)?;
        Ok(Answer::Glv {
            selected,
            transcript,
        })
    } else if function.is_str(BATCH_ORACLE) {
        let value = batch_input(inputs)?;
        let (selected, transcript) =
            glv_batch::resolve(&value, &tables.wide_bank).map_err(|glv::Invalid| Code::Params)?;
        Ok(Answer::Batch {
            selected,
            transcript,
        })
    } else if function.is_str(FIXED_ORACLE) {
        let Value::Array(inputs) = inputs else {
            return Err(Code::Params);
        };
        let [indices, negative] = inputs.as_slice() else {
            return Err(Code::Params);
        };
        let indices = array::<{ fixed::WINDOWS }>(indices, 5)?.map(|i| i as u8);
        let negative = array::<{ fixed::WINDOWS }>(negative, 1)?.map(|v| v != 0);
        let output =
            fixed::transcript(&tables.fixed, &indices, &negative).map_err(
                |failure| match failure {
                    fixed::Failure::Invalid => Code::Params,
                    fixed::Failure::Model => Code::Internal,
                },
            )?;
        if output.len() == fixed::LIMBS {
            Ok(Answer::Fixed(output))
        } else {
            Err(Code::Params)
        }
    } else {
        Err(Code::Method)
    }
}

/// A string matching `(?:0x)?[0-9a-fA-F]{1,64}` whose value is below 2^bits.
fn integer(value: &Value, bits: u32) -> Result<u128, Code> {
    let Value::Str(text) = value else {
        return Err(Code::Params);
    };
    let digits = match text.as_slice() {
        [zero, x, rest @ ..] if *zero == u32::from('0') && *x == u32::from('x') => rest,
        all => all,
    };
    if digits.is_empty() || digits.len() > 64 {
        return Err(Code::Params);
    }
    let mut result: u128 = 0;
    for &c in digits {
        let nibble = char::from_u32(c)
            .and_then(|c| c.to_digit(16))
            .ok_or(Code::Params)?;
        result = result
            .checked_mul(16)
            .and_then(|r| r.checked_add(u128::from(nibble)))
            .ok_or(Code::Params)?;
    }
    if bits < 128 && result >> bits != 0 {
        return Err(Code::Params);
    }
    Ok(result)
}

fn array<const N: usize>(value: &Value, bits: u32) -> Result<[u128; N], Code> {
    let Value::Array(items) = value else {
        return Err(Code::Params);
    };
    if items.len() != N {
        return Err(Code::Params);
    }
    let mut out = [0; N];
    for (slot, item) in out.iter_mut().zip(items) {
        *slot = integer(item, bits)?;
    }
    Ok(out)
}

fn glv_input(inputs: &Value) -> Result<glv::HintInput, Code> {
    let Value::Array(inputs) = inputs else {
        return Err(Code::Params);
    };
    let [points, digits, skews, negate_second, forced, index] = inputs.as_slice() else {
        return Err(Code::Params);
    };
    let raw = array::<12>(points, 128)?;
    // Incoming Fq values may use a range-bounded representative at or above p.
    // Reduce only in this untrusted hint; the unchanged replay owns modular validity.
    let mut coordinates = [Fp::ZERO; 4];
    for (coordinate, limbs) in coordinates.iter_mut().zip(raw.chunks_exact(3)) {
        *coordinate = Fp::from_limbs([limbs[0], limbs[1], limbs[2]], false).ok_or(Code::Params)?;
    }
    let digits = array::<64>(digits, 4)?.map(|d| d as u8);
    let skews = array::<2>(skews, 1)?.map(|v| v != 0);
    Ok(glv::HintInput {
        points: [
            Point {
                x: coordinates[0],
                y: coordinates[1],
            },
            Point {
                x: coordinates[2],
                y: coordinates[3],
            },
        ],
        digits: [
            digits[..32].try_into().expect("32 digits"),
            digits[32..].try_into().expect("32 digits"),
        ],
        skews,
        negate_second: integer(negate_second, 1)? != 0,
        forced: integer(forced, 1)? != 0,
        index: integer(index, 8)? as u8,
    })
}

/// `zark_glv_batch_hint_v1` inputs, in the donor's array order: 36 coordinate
/// limbs (x then y per column), one word per column packing its 32 4-bit digits
/// with digit w at bits 4w..4w+4, 6 skews, 2 image signs, forced, and a 16-bit
/// selector that must name one of the 512 bank entries.
fn batch_input(inputs: &Value) -> Result<glv_batch::BatchInput, Code> {
    let Value::Array(inputs) = inputs else {
        return Err(Code::Params);
    };
    let [points, digits, skews, negate, forced, index] = inputs.as_slice() else {
        return Err(Code::Params);
    };
    let raw = array::<{ 6 * glv_batch::COLUMNS }>(points, 128)?;
    let mut coordinates = [Fp::ZERO; 2 * glv_batch::COLUMNS];
    for (coordinate, limbs) in coordinates.iter_mut().zip(raw.chunks_exact(3)) {
        *coordinate = Fp::from_limbs([limbs[0], limbs[1], limbs[2]], false).ok_or(Code::Params)?;
    }
    let words = array::<{ glv_batch::COLUMNS }>(digits, 128)?;
    let index = integer(index, 16)?;
    if index >= glv_batch::BANK as u128 {
        return Err(Code::Params);
    }
    Ok(glv_batch::BatchInput {
        points: std::array::from_fn(|c| Point {
            x: coordinates[2 * c],
            y: coordinates[2 * c + 1],
        }),
        digits: words.map(|word| std::array::from_fn(|w| ((word >> (4 * w)) & 15) as u8)),
        skews: array::<{ glv_batch::COLUMNS }>(skews, 1)?.map(|v| v != 0),
        negate: array::<2>(negate, 1)?.map(|v| v != 0),
        forced: integer(forced, 1)? != 0,
        index: index as u16,
    })
}

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "batch_tests.rs"]
mod batch_tests;
