//! The JSON the retired helper accepted: CPython 3.12 `json.loads(bytes)` with
//! duplicate keys and the NaN/Infinity constants rejected.
//!
//! Its byte-encoding detection (UTF-8 with an optional BOM, UTF-16, UTF-32),
//! `surrogatepass` decoding, lone-surrogate escapes and 4300-digit integer
//! limit are reproduced so every request gets exactly the answer or error code
//! the reference gave. Strings are sequences of code points and may contain
//! lone surrogates; values the helper never inspects keep only their type.
//!
//! There is no nesting limit: the 16 KiB request bound allows at most 8192
//! levels, all of which the reference decoded inside its request handler
//! without reaching CPython's recursion guard (measured with 3.12.14).

#[derive(Debug, PartialEq)]
pub(super) enum Value {
    Null,
    Bool,
    Int(Int),
    Float,
    Str(Vec<u32>),
    Array(Vec<Value>),
    Object(Vec<(Vec<u32>, Value)>),
}

/// A Python `int`: either in the wire range `0 <= v < 2^64`, or any other.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Int {
    U64(u64),
    Other,
}

#[derive(Debug, PartialEq)]
pub(super) struct Malformed;

/// CPython's `sys.int_max_str_digits` default; `-I` ignores the override.
const MAX_INT_DIGITS: usize = 4300;

fn named(text: &[u32], name: &str) -> bool {
    text.iter().copied().eq(name.chars().map(u32::from))
}

impl Value {
    pub(super) fn is_str(&self, expected: &str) -> bool {
        matches!(self, Self::Str(text) if named(text, expected))
    }

    /// The value of `key`; decoded objects never contain duplicate keys.
    pub(super) fn field(&self, key: &str) -> Option<&Value> {
        let Self::Object(pairs) = self else {
            return None;
        };
        pairs.iter().find(|(k, _)| named(k, key)).map(|(_, v)| v)
    }

    /// Whether this is an object whose keys include all of `required` and are
    /// otherwise drawn from `optional`.
    pub(super) fn has_keys(&self, required: &[&str], optional: &[&str]) -> bool {
        let Self::Object(pairs) = self else {
            return false;
        };
        required.iter().all(|name| self.field(name).is_some())
            && pairs
                .iter()
                .all(|(key, _)| required.iter().chain(optional).any(|name| named(key, name)))
    }
}

pub(super) fn parse(raw: &[u8]) -> Result<Value, Malformed> {
    let text = decode(raw)?;
    let mut parser = Parser {
        text: &text,
        pos: 0,
    };
    parser.skip_whitespace();
    let value = parser.value()?;
    parser.skip_whitespace();
    if parser.pos == text.len() {
        Ok(value)
    } else {
        Err(Malformed)
    }
}

/// `json.detect_encoding` followed by `bytes.decode(encoding, "surrogatepass")`.
fn decode(raw: &[u8]) -> Result<Vec<u32>, Malformed> {
    match raw {
        [0, 0, 0xfe, 0xff, rest @ ..] => utf32(rest, true),
        [0xff, 0xfe, 0, 0, rest @ ..] => utf32(rest, false),
        [0xfe, 0xff, rest @ ..] => utf16(rest, true),
        [0xff, 0xfe, rest @ ..] => utf16(rest, false),
        [0xef, 0xbb, 0xbf, rest @ ..] => utf8(rest),
        [0, second, _, _, ..] if *second != 0 => utf16(raw, true),
        [0, _, _, _, ..] => utf32(raw, true),
        [_, 0, third, fourth, ..] if *third != 0 || *fourth != 0 => utf16(raw, false),
        [_, 0, _, _, ..] => utf32(raw, false),
        [0, _] => utf16(raw, true),
        [_, 0] => utf16(raw, false),
        _ => utf8(raw),
    }
}

/// Strict UTF-8, except that `surrogatepass` admits encoded surrogates (ED A0-BF).
fn utf8(bytes: &[u8]) -> Result<Vec<u32>, Malformed> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let lead = bytes[i];
        let (length, second) = match lead {
            0x00..=0x7f => {
                out.push(u32::from(lead));
                i += 1;
                continue;
            }
            0xc2..=0xdf => (2, 0x80..=0xbf),
            0xe0 => (3, 0xa0..=0xbf),
            0xe1..=0xef => (3, 0x80..=0xbf),
            0xf0 => (4, 0x90..=0xbf),
            0xf1..=0xf3 => (4, 0x80..=0xbf),
            0xf4 => (4, 0x80..=0x8f),
            _ => return Err(Malformed),
        };
        let sequence = bytes.get(i..i + length).ok_or(Malformed)?;
        if !second.contains(&sequence[1]) || sequence[2..].iter().any(|b| b & 0xc0 != 0x80) {
            return Err(Malformed);
        }
        let mut point = u32::from(lead) & (0x7f >> length);
        for byte in &sequence[1..] {
            point = (point << 6) | u32::from(byte & 0x3f);
        }
        out.push(point);
        i += length;
    }
    Ok(out)
}

/// Pairs combine; `surrogatepass` keeps any other surrogate unit as a code point.
fn utf16(bytes: &[u8], big_endian: bool) -> Result<Vec<u32>, Malformed> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Malformed);
    }
    let units: Vec<u32> = bytes
        .chunks_exact(2)
        .map(|unit| {
            let unit = [unit[0], unit[1]];
            u32::from(if big_endian {
                u16::from_be_bytes(unit)
            } else {
                u16::from_le_bytes(unit)
            })
        })
        .collect();
    let mut out = Vec::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        match (units[i], units.get(i + 1)) {
            (high @ 0xd800..=0xdbff, Some(&low @ 0xdc00..=0xdfff)) => {
                out.push(0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00));
                i += 2;
            }
            (unit, _) => {
                out.push(unit);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn utf32(bytes: &[u8], big_endian: bool) -> Result<Vec<u32>, Malformed> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Malformed);
    }
    bytes
        .chunks_exact(4)
        .map(|unit| {
            let unit = [unit[0], unit[1], unit[2], unit[3]];
            let point = if big_endian {
                u32::from_be_bytes(unit)
            } else {
                u32::from_le_bytes(unit)
            };
            (point < 0x11_0000).then_some(point).ok_or(Malformed)
        })
        .collect()
}

const fn code(c: char) -> u32 {
    c as u32
}

fn digit(c: u32) -> bool {
    (code('0')..=code('9')).contains(&c)
}

enum Open {
    Array(Vec<Value>),
    Object {
        pairs: Vec<(Vec<u32>, Value)>,
        key: Vec<u32>,
    },
}

struct Parser<'a> {
    text: &'a [u32],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u32> {
        self.text.get(self.pos).copied()
    }

    fn eat(&mut self, c: char) -> bool {
        let found = self.peek() == Some(code(c));
        self.pos += usize::from(found);
        found
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(0x20 | 0x09 | 0x0a | 0x0d)) {
            self.pos += 1;
        }
    }

    fn literal(&mut self, word: &str) -> bool {
        let found = self.text[self.pos..]
            .iter()
            .copied()
            .take(word.len())
            .eq(word.chars().map(u32::from));
        if found {
            self.pos += word.len();
        }
        found
    }

    /// Iterative, so nesting never depends on this thread's stack.
    fn value(&mut self) -> Result<Value, Malformed> {
        let mut open: Vec<Open> = Vec::new();
        loop {
            let mut value = if self.peek() == Some(code('{')) || self.peek() == Some(code('[')) {
                let object = self.eat('{');
                self.pos += usize::from(!object);
                self.skip_whitespace();
                if object && self.eat('}') {
                    Value::Object(Vec::new())
                } else if object {
                    let key = self.key()?;
                    open.push(Open::Object {
                        pairs: Vec::new(),
                        key,
                    });
                    continue;
                } else if self.eat(']') {
                    Value::Array(Vec::new())
                } else {
                    open.push(Open::Array(Vec::new()));
                    continue;
                }
            } else {
                self.scalar()?
            };
            // Attach the finished value, closing every container it completes.
            loop {
                let Some(container) = open.last_mut() else {
                    return Ok(value);
                };
                self.skip_whitespace();
                match container {
                    Open::Array(items) => {
                        items.push(value);
                        if self.eat(',') {
                            self.skip_whitespace();
                            break;
                        }
                        if !self.eat(']') {
                            return Err(Malformed);
                        }
                        value = Value::Array(std::mem::take(items));
                    }
                    Open::Object {
                        pairs,
                        key: pending,
                    } => {
                        let key = std::mem::take(pending);
                        if pairs.iter().any(|(existing, _)| *existing == key) {
                            return Err(Malformed);
                        }
                        pairs.push((key, value));
                        if self.eat(',') {
                            self.skip_whitespace();
                            *pending = self.key()?;
                            break;
                        }
                        if !self.eat('}') {
                            return Err(Malformed);
                        }
                        value = Value::Object(std::mem::take(pairs));
                    }
                }
                open.pop();
            }
        }
    }

    fn key(&mut self) -> Result<Vec<u32>, Malformed> {
        if !self.eat('"') {
            return Err(Malformed);
        }
        let key = self.string()?;
        self.skip_whitespace();
        if !self.eat(':') {
            return Err(Malformed);
        }
        self.skip_whitespace();
        Ok(key)
    }

    fn scalar(&mut self) -> Result<Value, Malformed> {
        if self.eat('"') {
            self.string().map(Value::Str)
        } else if self.literal("null") {
            Ok(Value::Null)
        } else if self.literal("true") || self.literal("false") {
            Ok(Value::Bool)
        } else {
            // NaN, Infinity and -Infinity are rejected here like any non-number.
            self.number()
        }
    }

    fn number(&mut self) -> Result<Value, Malformed> {
        let negative = self.eat('-');
        let start = self.pos;
        match self.peek() {
            Some(c) if c == code('0') => self.pos += 1,
            Some(c) if digit(c) => {
                while self.peek().is_some_and(digit) {
                    self.pos += 1;
                }
            }
            _ => return Err(Malformed),
        }
        let digits = &self.text[start..self.pos];
        let mut float = false;
        if self.peek() == Some(code('.')) && self.text.get(self.pos + 1).copied().is_some_and(digit)
        {
            float = true;
            self.pos += 2;
            while self.peek().is_some_and(digit) {
                self.pos += 1;
            }
        }
        if self.peek() == Some(code('e')) || self.peek() == Some(code('E')) {
            let exponent = self.pos;
            self.pos += 1;
            if self.peek() == Some(code('+')) || self.peek() == Some(code('-')) {
                self.pos += 1;
            }
            let first = self.pos;
            while self.peek().is_some_and(digit) {
                self.pos += 1;
            }
            if self.pos == first {
                self.pos = exponent;
            } else {
                float = true;
            }
        }
        if float {
            return Ok(Value::Float);
        }
        if digits.len() > MAX_INT_DIGITS {
            return Err(Malformed);
        }
        let magnitude = digits.iter().try_fold(0u64, |value, &d| {
            value.checked_mul(10)?.checked_add(u64::from(d - code('0')))
        });
        Ok(Value::Int(match magnitude {
            Some(0) => Int::U64(0),
            Some(value) if !negative => Int::U64(value),
            _ => Int::Other,
        }))
    }

    fn string(&mut self) -> Result<Vec<u32>, Malformed> {
        let mut out = Vec::new();
        loop {
            let c = self.peek().ok_or(Malformed)?;
            self.pos += 1;
            if c == code('"') {
                return Ok(out);
            }
            if c <= 0x1f {
                return Err(Malformed);
            }
            if c != code('\\') {
                out.push(c);
                continue;
            }
            let escape = self.peek().ok_or(Malformed)?;
            self.pos += 1;
            let decoded = match char::from_u32(escape).ok_or(Malformed)? {
                '"' => code('"'),
                '\\' => code('\\'),
                '/' => code('/'),
                'b' => 0x08,
                'f' => 0x0c,
                'n' => 0x0a,
                'r' => 0x0d,
                't' => 0x09,
                'u' => self.unicode_escape()?,
                _ => return Err(Malformed),
            };
            out.push(decoded);
        }
    }

    /// A `\u` escape; a high surrogate joins only an immediately escaped low one.
    fn unicode_escape(&mut self) -> Result<u32, Malformed> {
        let high = self.hex4()?;
        if (0xd800..=0xdbff).contains(&high)
            && self.pos + 6 < self.text.len()
            && self.text[self.pos] == code('\\')
            && self.text[self.pos + 1] == code('u')
        {
            let resume = self.pos;
            self.pos += 2;
            let low = self.hex4()?;
            if (0xdc00..=0xdfff).contains(&low) {
                return Ok(0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00));
            }
            self.pos = resume;
        }
        Ok(high)
    }

    /// Four hex digits that must be followed by at least one more code point.
    fn hex4(&mut self) -> Result<u32, Malformed> {
        if self.pos + 4 >= self.text.len() {
            return Err(Malformed);
        }
        let mut value = 0;
        for &c in &self.text[self.pos..self.pos + 4] {
            let nibble = char::from_u32(c)
                .and_then(|c| c.to_digit(16))
                .ok_or(Malformed)?;
            value = (value << 4) | nibble;
        }
        self.pos += 4;
        Ok(value)
    }
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
