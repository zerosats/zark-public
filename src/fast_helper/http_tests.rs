use super::*;

const JSON: &str = "Content-Type: application/json\r\n";

fn read(raw: &[u8]) -> Request {
    read_request(&mut &raw[..])
}

fn post(headers: &str, body: &str) -> Request {
    read(format!("POST / HTTP/1.1\r\n{headers}\r\n{body}").as_bytes())
}

fn reject(status: u16) -> Request {
    Request::Reject(status, Framing::Http10)
}

#[test]
fn a_well_formed_post_yields_its_exact_body() {
    let body = "{\"a\":1}";
    let headers = format!("Host: x\r\n{JSON}Content-Length: 7\r\n");
    assert_eq!(
        post(&headers, body),
        Request::Body(body.as_bytes().to_vec(), Framing::Http10)
    );
    let lenient = "content-type:  Application/JSON ; charset=utf-8\r\ncontent-length:\t7\n";
    assert_eq!(
        post(lenient, body),
        Request::Body(body.as_bytes().to_vec(), Framing::Http10)
    );
    assert_eq!(
        read(b"POST // HTTP/01.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"),
        Request::Body(b"{}".to_vec(), Framing::Http10)
    );
}

#[test]
fn request_lines_follow_the_reference_order() {
    let bare = |status| Request::Reject(status, Framing::Bare);
    assert_eq!(read(b""), Request::Drop);
    assert_eq!(read(b"\r\n"), Request::Drop);
    assert_eq!(read(b" \t\r\n"), Request::Drop);
    assert_eq!(read(&[b'P'; MAX_LINE + 1]), reject(414));
    assert_eq!(read(b"POST\r\n\r\n"), bare(400));
    assert_eq!(read(b"POST /\r\n\r\n"), bare(400));
    assert_eq!(read(b"GET /\r\n\r\n"), bare(501));
    assert_eq!(read(b"GET / HTTP/1.0\r\n\r\n"), reject(501));
    assert_eq!(read(b"post / HTTP/1.0\r\n\r\n"), reject(501));
    assert_eq!(read(b"POST / HTTP/2.0\r\n\r\n"), bare(505));
    assert_eq!(read(b"POST / x HTTP/2.0\r\n\r\n"), bare(505));
    assert_eq!(read(b"POST / x HTTP/1.0\r\n\r\n"), reject(400));
    for version in [
        "HTTPS/1.0",
        "HTTP/1",
        "HTTP/1.0.0",
        "HTTP/1.x",
        "HTTP/12345678901.0",
        "HTTP/",
    ] {
        let line = format!("POST / {version}\r\n\r\n");
        assert_eq!(read(line.as_bytes()), bare(400), "{version}");
    }
    let explicit = format!("POST / HTTP/0.9\r\n{JSON}Content-Length: 2\r\n\r\n{{}}");
    assert_eq!(
        read(explicit.as_bytes()),
        Request::Body(b"{}".to_vec(), Framing::Bare)
    );
    assert_eq!(read(b"GET / HTTP/0.9\r\n\r\n"), bare(501));
    assert_eq!(read(b"GET / HTTP/00.9\r\n\r\n"), reject(501));
    let path = format!("POST /x HTTP/1.0\r\n{JSON}Content-Length: 2\r\n\r\n{{}}");
    assert_eq!(read(path.as_bytes()), reject(400));
}

#[test]
fn header_limits_and_post_checks_use_the_reference_statuses() {
    let many = "X: y\r\n".repeat(MAX_HEADER_LINES);
    assert_eq!(post(&many, ""), reject(431));
    let at_limit = format!("{}{JSON}Content-Length: 2\r\n", "X: y\r\n".repeat(97));
    assert_eq!(
        post(&at_limit, "{}"),
        Request::Body(b"{}".to_vec(), Framing::Http10)
    );
    let long = format!("X: {}\r\n", "y".repeat(MAX_LINE));
    assert_eq!(post(&long, ""), reject(431));
    for headers in [
        JSON.to_owned(),
        format!("{JSON}Content-Length: 2\r\nContent-Length: 2\r\n"),
        format!("{JSON}Content-Length: +2\r\n"),
        format!("{JSON}Content-Length: 2 \r\n"),
        format!("{JSON}Content-Length: 1234567\r\n"),
        format!("{JSON}Content-Length: 2\r\nTransfer-Encoding: chunked\r\n"),
        format!("{JSON}Content-Length: 2\r\nContent-Encoding: gzip\r\n"),
        "Content-Type: text/plain\r\nContent-Length: 2\r\n".to_owned(),
        "Content-Length: 2\r\n".to_owned(),
        format!("{JSON}Content-Length: 3\r\n"),
    ] {
        assert_eq!(post(&headers, "{}"), reject(400), "{headers:?}");
    }
    for length in ["0", "16385", "999999"] {
        let headers = format!("{JSON}Content-Length: {length}\r\n");
        assert_eq!(post(&headers, "{}"), reject(413), "{length}");
    }
}

#[test]
fn header_blocks_are_read_like_the_stdlib_email_parser() {
    let ok = Request::Body(b"{}".to_vec(), Framing::Http10);
    // Folded continuation lines join the open field.
    let folded = "Content-Type: application/json\r\n ; charset=x\r\nContent-Length: 2\r\n";
    assert_eq!(post(folded, "{}"), ok);
    assert_eq!(
        post(&format!("{JSON}Content-Length: 2\r\n 3\r\n"), "{}"),
        reject(400)
    );
    // Envelope, nameless and leading continuation lines are skipped.
    let skipped = format!(" lead\r\nFrom someone\r\n: nameless\r\n{JSON}Content-Length: 2\r\n");
    assert_eq!(post(&skipped, "{}"), ok);
    // The first line that is not a field ends the fields; later lines are ignored.
    let ended = format!("{JSON}Content-Length: 2\r\nnot a field\r\nContent-Length: 9\r\n");
    assert_eq!(post(&ended, "{}"), ok);
    let hidden = format!("Content-Length: 2\r\nbad line\r\n{JSON}");
    assert_eq!(post(&hidden, "{}"), reject(400));
    // A bare CR also ends a line.
    let split = "Content-Type: application/json\rContent-Length: 2\r\n";
    assert_eq!(post(split, "{}"), ok);
    let non_post = b"GET / HTTP/1.0\r\nbad line\r\n\r\n";
    assert_eq!(read(non_post), reject(501));
}

#[test]
fn responses_are_framed_like_the_reference() {
    let mut out = Vec::new();
    write_response(&mut out, 413, Framing::Http10, b"{}").unwrap();
    assert_eq!(
        out,
        b"HTTP/1.0 413 Request Entity Too Large\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
    );
    let mut out = Vec::new();
    write_response(&mut out, 501, Framing::Bare, b"{}").unwrap();
    assert_eq!(out, b"{}");
}
