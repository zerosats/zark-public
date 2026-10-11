//! One HTTP/1.0 request per connection, framed exactly as the retired host.py
//! server (CPython 3.12 `BaseHTTPRequestHandler`) framed it: request-line
//! checks and their order, the 64 KiB line and 100-line header limits, the
//! stdlib email parser's reading of the header block, the POST checks, status
//! codes, and bare bodies for requests it treated as HTTP/0.9. Only its
//! informational `Server` and `Date` response headers are not reproduced.
use super::rpc::MAX_REQUEST;
use std::io::{BufRead, Read, Write};

const MAX_LINE: usize = 65536;
const MAX_HEADER_LINES: usize = 100;

/// Whether a response has a status line and headers. The reference omits both
/// when a request never established an HTTP version, treating it as HTTP/0.9.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Framing {
    Http10,
    Bare,
}

#[derive(Debug, PartialEq)]
pub(super) enum Request {
    Body(Vec<u8>, Framing),
    /// Answer with this status and the fixed "Invalid request" body.
    Reject(u16, Framing),
    /// Close without a response: no request line, a timeout or an I/O error.
    Drop,
}

enum Line {
    Text(Vec<u8>),
    TooLong,
    End,
}

/// `readline(65537)`: at most one byte past the limit, to detect overflow.
fn read_line(reader: &mut impl BufRead) -> std::io::Result<Line> {
    let mut line = Vec::new();
    reader
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut line)?;
    Ok(match line.len() {
        0 => Line::End,
        n if n > MAX_LINE => Line::TooLong,
        _ => Line::Text(line),
    })
}

/// `str.isspace()` for Latin-1 text, as used by `str.split()` and `strip()`.
fn python_space(byte: u8) -> bool {
    matches!(byte, b'\t'..=b'\r' | 0x1c..=0x20 | 0x85 | 0xa0)
}

fn python_strip(text: &[u8]) -> &[u8] {
    let start = text.iter().position(|&b| !python_space(b));
    let end = text.iter().rposition(|&b| !python_space(b));
    match (start, end) {
        (Some(start), Some(end)) => &text[start..=end],
        _ => &[],
    }
}

fn trim_end(text: &[u8], strip: impl Fn(u8) -> bool) -> &[u8] {
    let end = text.iter().rposition(|&b| !strip(b)).map_or(0, |i| i + 1);
    &text[..end]
}

/// `HTTP/<major>.<minor>` with at most ten ASCII digits per component.
fn major_version(word: &[u8]) -> Option<u64> {
    let number = word.strip_prefix(b"HTTP/")?;
    let dot = number.iter().position(|&b| b == b'.')?;
    let (major, minor) = (&number[..dot], &number[dot + 1..]);
    let number = |part: &[u8]| {
        (!part.is_empty() && part.len() <= 10 && part.iter().all(u8::is_ascii_digit))
            .then(|| std::str::from_utf8(part).ok()?.parse::<u64>().ok())
            .flatten()
    };
    number(minor)?;
    number(major)
}

enum Block {
    Read(Vec<u8>),
    TooLarge,
    Failed,
}

/// `http.client.parse_headers`' line loop, through a blank line or EOF.
fn read_header_block(reader: &mut impl BufRead) -> Block {
    let mut block = Vec::new();
    for count in 1.. {
        let line = match read_line(reader) {
            Ok(Line::Text(line)) => line,
            Ok(Line::End) => Vec::new(),
            Ok(Line::TooLong) => return Block::TooLarge,
            Err(_) => return Block::Failed,
        };
        // The terminating line, even EOF, counts toward the limit.
        if count > MAX_HEADER_LINES {
            return Block::TooLarge;
        }
        let last = matches!(line.as_slice(), b"" | b"\n" | b"\r\n");
        block.extend(line);
        if last {
            break;
        }
    }
    Block::Read(block)
}

/// Lines split at `\r\n`, `\r` or `\n`, each keeping its terminator.
fn universal_lines(mut text: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        if text.is_empty() {
            return None;
        }
        let end = match text.iter().position(|&b| b == b'\n' || b == b'\r') {
            None => text.len(),
            Some(i) if text[i] == b'\r' && text.get(i + 1) == Some(&b'\n') => i + 2,
            Some(i) => i + 1,
        };
        let (line, rest) = text.split_at(end);
        text = rest;
        Some(line)
    })
}

/// The email parser's `^(From |[\041-\071\073-\176]*:|[\t ])`.
fn field_line(line: &[u8]) -> bool {
    line.starts_with(b"From ")
        || matches!(line.first(), Some(b' ' | b'\t'))
        || line
            .iter()
            .find(|&&b| b == b':' || !(0x21..=0x7e).contains(&b))
            == Some(&b':')
}

struct Header {
    name: Vec<u8>,
    value: Vec<u8>,
}

/// The fields the stdlib email parser (compat32 policy) takes from a header
/// block. It never rejects one: the fields end at the first line that is
/// neither a field nor a continuation, a continuation extends the open field
/// verbatim, and envelope (`From `) and nameless lines are skipped.
fn fields(block: &[u8]) -> Vec<Header> {
    let mut fields: Vec<Header> = Vec::new();
    let mut open = false;
    for line in universal_lines(block).take_while(|line| field_line(line)) {
        if matches!(line[0], b' ' | b'\t') {
            if open {
                let field = fields.last_mut().expect("an open field");
                field.value.extend_from_slice(line);
            }
            continue;
        }
        open = false;
        if line.starts_with(b"From ") {
            continue;
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .expect("field lines contain a colon");
        if colon == 0 {
            continue;
        }
        let value = &line[colon + 1..];
        let start = value
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .unwrap_or(value.len());
        fields.push(Header {
            name: line[..colon].to_vec(),
            value: value[start..].to_vec(),
        });
        open = true;
    }
    for field in &mut fields {
        let end = trim_end(&field.value, |b| b == b'\r' || b == b'\n').len();
        field.value.truncate(end);
    }
    fields
}

/// `Message.get_content_type()`: the first Content-Type's media type.
fn content_type(headers: &[Header]) -> Vec<u8> {
    let Some(header) = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(b"content-type"))
    else {
        return b"text/plain".to_vec();
    };
    let media = header
        .value
        .split(|&b| b == b';')
        .next()
        .unwrap_or_default();
    python_strip(media).to_ascii_lowercase()
}

pub(super) fn read_request(reader: &mut impl BufRead) -> Request {
    let line = match read_line(reader) {
        Ok(Line::Text(line)) => line,
        Ok(Line::TooLong) => return Request::Reject(414, Framing::Http10),
        Ok(Line::End) | Err(_) => return Request::Drop,
    };
    let words: Vec<&[u8]> = trim_end(&line, |b| b == b'\r' || b == b'\n')
        .split(|&b| python_space(b))
        .filter(|w| !w.is_empty())
        .collect();
    if words.is_empty() {
        return Request::Drop;
    }
    // The version is checked first, from the last of three or more words. Bare
    // framing follows the version text being exactly the default "HTTP/0.9".
    let mut framing = Framing::Bare;
    if words.len() >= 3 {
        let version = words[words.len() - 1];
        match major_version(version) {
            None => return Request::Reject(400, framing),
            Some(major) if major >= 2 => return Request::Reject(505, framing),
            Some(_) if version == b"HTTP/0.9" => {}
            Some(_) => framing = Framing::Http10,
        }
    }
    if !(2..=3).contains(&words.len()) || (words.len() == 2 && words[0] != b"GET") {
        return Request::Reject(400, framing);
    }
    let (method, mut path) = (words[0], words[1]);
    // The reference collapses a leading run of slashes to one.
    if path.starts_with(b"//") {
        path = &path[path.iter().position(|&b| b != b'/').unwrap_or(path.len()) - 1..];
    }
    let headers = match read_header_block(reader) {
        Block::Read(block) => fields(&block),
        Block::TooLarge => return Request::Reject(431, framing),
        Block::Failed => return Request::Drop,
    };
    if method != b"POST" {
        return Request::Reject(501, framing);
    }
    let reject = Request::Reject(400, framing);
    let named = |name: &'static [u8]| {
        headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
    };
    let lengths: Vec<&Header> = named(b"content-length").collect();
    let [length] = lengths.as_slice() else {
        return reject;
    };
    let length = &length.value;
    if path != b"/"
        || named(b"transfer-encoding").next().is_some()
        || named(b"content-encoding").next().is_some()
        || content_type(&headers) != b"application/json"
        || !(1..=6).contains(&length.len())
        || !length.iter().all(u8::is_ascii_digit)
    {
        return reject;
    }
    let length: usize = std::str::from_utf8(length)
        .expect("ASCII digits")
        .parse()
        .expect("at most six digits");
    if !(1..=MAX_REQUEST).contains(&length) {
        return Request::Reject(413, framing);
    }
    let mut body = Vec::with_capacity(length);
    match reader.take(length as u64).read_to_end(&mut body) {
        Ok(n) if n == length => Request::Body(body, framing),
        Ok(_) => reject,
        Err(_) => Request::Drop,
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

pub(super) fn write_response(
    out: &mut impl Write,
    status: u16,
    framing: Framing,
    body: &[u8],
) -> std::io::Result<()> {
    if framing == Framing::Http10 {
        let head = format!(
            "HTTP/1.0 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reason(status),
            body.len()
        );
        out.write_all(head.as_bytes())?;
    }
    out.write_all(body)?;
    out.flush()
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
