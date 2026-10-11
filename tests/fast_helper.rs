//! Process lifecycle of the private witness-hint helper binary.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HELPER: &str = env!("CARGO_BIN_EXE_zark-fast-helper");

fn ready_port(line: &str) -> u16 {
    let value: serde_json::Value = serde_json::from_str(line).unwrap();
    let port = value["port"].as_u64().unwrap();
    assert_eq!(
        line,
        format!(
            "{{\"ready\": true, \"host\": \"127.0.0.1\", \"port\": {port}, \"url\": \"http://127.0.0.1:{port}/\", \"cache\": false}}\n"
        )
    );
    port.try_into().unwrap()
}

fn post(port: u16, body: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn serves_after_one_readiness_line_and_stops_cleanly() {
    let mut child = Command::new(HELPER)
        .args(["--port", "0"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let port = ready_port(&line);
    let response = post(
        port,
        br#"{"jsonrpc":"2.0","id":3,"method":"other","params":[]}"#,
    );
    let body = r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found"}}"#;
    let expected = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    assert_eq!(String::from_utf8(response).unwrap(), expected);
    let rejected = post(port, b"");
    assert!(rejected.starts_with(b"HTTP/1.0 413 "));
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert!(child.wait().unwrap().success());
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    child.stderr.take().unwrap().read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "the helper wrote after readiness");
}

#[test]
fn exits_when_its_parent_dies() {
    // The shell is the helper's parent; it reports the helper's PID first.
    let mut parent = Command::new("/bin/sh")
        .args(["-c", "\"$0\" --port 0 & echo $!; exec sleep 60", HELPER])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(parent.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let helper: i32 = line.trim().parse().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    ready_port(&line);
    assert!(alive(helper));
    parent.kill().unwrap();
    parent.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(helper) {
        assert!(Instant::now() < deadline, "orphaned helper kept running");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn rejects_unknown_arguments() {
    let output = Command::new(HELPER)
        .arg("--verbose")
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
