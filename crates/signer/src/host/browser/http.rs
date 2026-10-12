//! Small, deliberately strict HTTP/1.1 boundary: one Content-Length body, then close.
//! No chunked encoding, compression, pipelining, cookies or HTTP authentication.
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    io::{BufRead, Read, Write},
};
use zeroize::Zeroizing;

const MAX_HEADERS: usize = 16_384;
pub(super) struct Head {
    pub(super) method: String,
    pub(super) path: String,
    headers: BTreeMap<String, String>,
}
impl Head {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
    pub(super) fn empty(&self) -> bool {
        self.header("content-length").is_none_or(|v| v == "0")
    }
    pub(super) fn json(&self) -> bool {
        self.header("content-type").is_some_and(|v| {
            let mut parts = v.split(';');
            parts
                .next()
                .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json"))
                && parts.all(|s| s.trim().eq_ignore_ascii_case("charset=utf-8"))
        })
    }
    pub(super) fn preflight(&self, method: &str) -> bool {
        self.empty()
            && self.header("access-control-request-method") == Some(method)
            && self
                .header("access-control-request-headers")
                .is_none_or(|v| {
                    v.split(',')
                        .all(|name| name.trim().eq_ignore_ascii_case("content-type"))
                })
    }
}
pub(super) fn read_head(reader: &mut impl BufRead) -> Result<Head> {
    let mut bytes = Vec::new();
    // Bound aggregate headers and individual lines before parsing or allocating a body.
    loop {
        let start = bytes.len();
        (&mut *reader)
            .take((MAX_HEADERS + 1 - start) as u64)
            .read_until(b'\n', &mut bytes)?;
        ensure!(
            bytes.len() <= MAX_HEADERS && bytes.len() > start && bytes[start..].ends_with(b"\r\n"),
            "invalid HTTP headers"
        );
        if &bytes[start..] == b"\r\n" {
            break;
        }
    }
    let text = std::str::from_utf8(&bytes)?;
    let mut lines = text.split("\r\n");
    let request: Vec<_> = lines.next().unwrap_or_default().split(' ').collect();
    ensure!(
        request.len() == 3
            && request[2] == "HTTP/1.1"
            && request[0].bytes().all(|b| b.is_ascii_uppercase())
            && request[1].starts_with('/')
            && request[1].len() <= 512,
        "invalid HTTP request"
    );
    let mut headers = BTreeMap::new();
    for line in lines.take_while(|s| !s.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid HTTP header"))?;
        ensure!(
            !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && value.bytes().all(|b| (32..=126).contains(&b))
                && headers.len() < 64,
            "invalid HTTP header"
        );
        ensure!(
            headers
                .insert(name.to_ascii_lowercase(), value.trim().to_string())
                .is_none(),
            "duplicate HTTP header"
        );
    }
    for forbidden in [
        "transfer-encoding",
        "content-encoding",
        "expect",
        "cookie",
        "authorization",
    ] {
        ensure!(!headers.contains_key(forbidden), "unsupported HTTP header");
    }
    Ok(Head {
        method: request[0].into(),
        path: request[1].into(),
        headers,
    })
}
pub(super) fn read_body(
    reader: &mut impl BufRead,
    head: &Head,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let length = head
        .header("content-length")
        .ok_or_else(|| anyhow::anyhow!("HTTP length required"))?;
    ensure!(
        !length.is_empty() && length.bytes().all(|b| b.is_ascii_digit()),
        "invalid HTTP length"
    );
    let length: usize = length.parse()?;
    ensure!((1..=limit).contains(&length), "HTTP body size");
    let mut body = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut body)?;
    Ok(body)
}
pub(super) fn write_response(
    stream: &mut impl Write,
    status: u16,
    origin: Option<&str>,
    body: &[u8],
    preflight: bool,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nVary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n",
        if status == 200 {
            "OK"
        } else if status == 204 {
            "No Content"
        } else {
            "Request Rejected"
        },
        body.len()
    )?;
    if let Some(origin) = origin {
        write!(stream, "Access-Control-Allow-Origin: {origin}\r\n")?;
        if preflight {
            write!(
                stream,
                "Access-Control-Allow-Methods: POST, GET\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Max-Age: 60\r\n"
            )?;
        }
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()
}
