use super::*;
use std::{net::TcpListener, thread};

fn reply(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn parse(bytes: Vec<u8>) -> Result<(Value, bool)> {
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let socket = TcpStream::connect(server.local_addr()?)?;
    let worker = thread::spawn(move || {
        let (mut socket, _) = server.accept().unwrap();
        let _ = socket.write_all(&bytes);
    });
    let result = response(
        &mut BufReader::new(socket),
        Instant::now() + Duration::from_secs(1),
    );
    worker.join().unwrap();
    result
}

#[test]
fn parameter_types_match_cli_and_hashes_stay_strings() {
    assert_eq!(
        parameters("gettxout", &["1234".into(), "0".into(), "true".into()]).unwrap(),
        json!(["1234", 0, true]).as_array().unwrap().clone()
    );
    assert_eq!(
        parameters("getblockhash", &["0".into()]).unwrap(),
        vec![json!(0)]
    );
    assert_eq!(
        parameters("getrawtransaction", &["00000000".into(), "true".into()]).unwrap(),
        vec![json!("00000000"), json!(true)]
    );
    assert_eq!(
        parameters("testmempoolaccept", &["[\"0123\"]".into()]).unwrap(),
        vec![json!(["0123"])]
    );
    assert!(parameters("unknown", &[]).is_err());
    assert!(parameters("gettxout", &[]).is_err());
}

#[test]
fn bounded_framing_and_exact_reply_binding() {
    assert_eq!(
        parse(reply(r#"{"id":"zark","result":null,"error":null}"#)).unwrap(),
        (Value::Null, true)
    );
    for body in [
        r#"{"id":"other","result":1,"error":null}"#,
        r#"{"id":"zark","result":1}"#,
        r#"{"id":"zark","error":null}"#,
        r#"{"id":"zark","result":null,"error":{"message":"private secret"}}"#,
    ] {
        let error = parse(reply(body)).unwrap_err().to_string();
        assert!(!error.contains("private secret"));
    }
    for bytes in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 4000001\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ] {
        assert!(parse(bytes).is_err());
    }
}

#[test]
fn persistent_stream_keeps_response_boundaries_and_absolute_deadline() {
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let socket = TcpStream::connect(server.local_addr().unwrap()).unwrap();
    let worker = thread::spawn(move || {
        let (mut socket, _) = server.accept().unwrap();
        for value in [1, 2] {
            socket
                .write_all(&reply(
                    &json!({"id":"zark","result":value,"error":null}).to_string(),
                ))
                .unwrap();
        }
        for _ in 0..20 {
            if socket.write_all(b"x").is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
    let mut reader = BufReader::new(socket);
    for value in [1, 2] {
        assert_eq!(
            response(&mut reader, Instant::now() + Duration::from_secs(1))
                .unwrap()
                .0,
            value
        );
    }
    let start = Instant::now();
    assert!(response(&mut reader, start + Duration::from_millis(50)).is_err());
    assert!(start.elapsed() < Duration::from_millis(200));
    drop(reader);
    worker.join().unwrap();
}
