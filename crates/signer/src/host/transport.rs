//! Bounded framed TLS requests, absolute I/O deadlines and privacy-preserving error responses.
use super::{
    BufRead, BufReader, Deserialize, Duration, Instant, MAX_WIRE, OUTER_LIMIT, Read, Request,
    Result, ServerConnection, StreamOwned, TcpStream, Value, Write, Zeroize, Zeroizing, ensure,
    hash, io, json,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outer {
    method: String,
    #[serde(default)]
    credential: String,
    request: String,
}
impl Drop for Outer {
    fn drop(&mut self) {
        self.credential.zeroize();
        self.request.zeroize();
    }
}
pub(super) fn decode(bytes: &[u8]) -> Result<(Request, Option<String>)> {
    ensure!(bytes.len() <= OUTER_LIMIT, "private transport size");
    let outer: Outer =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid private transport"))?;
    ensure!(
        outer.method == "zark_request"
            && (outer.credential.is_empty()
                || ((32..=256).contains(&outer.credential.len())
                    && outer.credential.bytes().all(|b| b.is_ascii_graphic()))),
        "private transport method or credential"
    );
    let request = Request::decode(outer.request.as_bytes())?;
    request.authenticate()?;
    let digest =
        (!outer.credential.is_empty()).then(|| hex::encode(hash(&[outer.credential.as_bytes()])));
    Ok((request, digest))
}
pub(super) fn unexpired(deadline: Instant) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "private request deadline exceeded"
    );
    Ok(())
}

pub(super) struct DeadlineStream {
    pub(super) stream: TcpStream,
    pub(super) deadline: Instant,
}
impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(
            self.deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request deadline"))?,
        ))?;
        self.stream.read(buf)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(
            self.deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "response deadline"))?,
        ))?;
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
pub(super) type Tls = StreamOwned<ServerConnection, DeadlineStream>;
pub(super) fn read_request(stream: &mut Tls, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut reader = BufReader::new(stream);
    (&mut reader)
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    ensure!(
        bytes.len() <= limit && bytes.last() == Some(&b'\n') && reader.buffer().is_empty(),
        "private request framing"
    );
    Ok(bytes)
}
pub(super) fn failure(code: &str, retryable: bool) -> Value {
    // The remote error's text never contains an internal exception or witness.
    json!({"ok":false,"error":{"code":code,"retryable":retryable,"message":"Private request was not completed; retain the exact request."}})
}
pub(super) fn reply(stream: &mut Tls, response: Value) -> bool {
    let _timing = zark_protocol::timing::Span::new(zark_protocol::timing::Phase::SignerReply);
    let Ok(mut bytes) = serde_json::to_vec(&response).map(Zeroizing::new) else {
        return false;
    };
    let limit = if zark_protocol::mail::is_alpn(stream.conn.alpn_protocol()) {
        zark_protocol::mail::MAX_WIRE
    } else {
        MAX_WIRE
    };
    if bytes.len() >= limit {
        return false;
    }
    bytes.push(b'\n');
    stream.sock.deadline = Instant::now() + Duration::from_secs(5);
    stream
        .write_all(&bytes)
        .and_then(|_| stream.flush())
        .is_ok()
}
pub(super) fn classify(error: &anyhow::Error) -> Value {
    for cause in error.chain() {
        if let Some(rusqlite::Error::SqliteFailure(e, _)) = cause.downcast_ref::<rusqlite::Error>()
            && matches!(
                e.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
        {
            return failure("overloaded", true);
        }
    }
    match error.to_string().as_str() {
        "private credential rejected" => failure("unauthorized", false),
        "private admission capacity"
        | "private admission unavailable"
        | "checkpoint busy: admission capacity"
        | "checkpoint busy: admission deadline"
        | "checkpoint busy: lock deadline"
        | "proof verification busy: lock deadline" => failure("overloaded", true),
        "private request deadline exceeded" | "proof verification deadline exceeded" => {
            failure("timeout", true)
        }
        _ => failure("invalid_request", false),
    }
}
