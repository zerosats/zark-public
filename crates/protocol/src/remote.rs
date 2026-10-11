//! Authenticated remote signer client. Configuration and credentials stay local.
//!
//! TLS validates the configured CA, server name and certificate validity. A second
//! exact certificate pin is checked before any bearer credential is transmitted.
use crate::hex32;
use anyhow::{Context, Result, ensure};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
mod sessions;

pub const ALPN: &[u8] = b"statechain/10";
/// Same canonical messages, with sequential requests on authenticated TLS.
pub const SESSION_ALPN: &[u8] = b"statechain/10-session";
/// Session semantics for a connection opened before its first request is
/// ready, and offered alone. A signer selecting it holds the connection outside
/// its network workers until request bytes arrive. Older signers reject it in
/// the hello, so none of their workers waits on an idle early connection.
pub const EARLY_SESSION_ALPN: &[u8] = b"statechain/10-early-session";

pub fn is_session_alpn(protocol: Option<&[u8]>) -> bool {
    protocol == Some(SESSION_ALPN) || protocol == Some(EARLY_SESSION_ALPN)
}

fn default_timeout() -> u64 {
    180
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEndpoint {
    /// Numeric endpoint avoids an unbounded resolver in the request path.
    pub address: SocketAddr,
    pub server_name: String,
    pub ca_certificate: PathBuf,
    pub certificate_sha256: String,
    /// Omit for a public signer; private deployments still require a bearer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_file: Option<PathBuf>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug)]
pub struct RemoteFailure {
    pub code: &'static str,
    pub retryable: bool,
}
impl std::fmt::Display for RemoteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Remote signer request failed ({})", self.code)
    }
}
impl std::error::Error for RemoteFailure {}

impl RemoteEndpoint {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.address.ip().is_unspecified() && self.address.port() != 0,
            "A concrete signer endpoint is required"
        );
        ensure!(
            (1..=300).contains(&self.timeout_secs),
            "Signer timeout must be 1..300 seconds"
        );
        hex32(&self.certificate_sha256).context("Invalid signer certificate fingerprint")?;
        rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .context("Invalid TLS server name")?;
        Ok(())
    }

    fn connect_protocol(
        &self,
        deadline: Instant,
        offered: &[&[u8]],
    ) -> Result<StreamOwned<ClientConnection, DeadlineSocket>> {
        let _timing = crate::timing::Span::new(crate::timing::Phase::SignerConnect);
        self.validate()?;
        let mut pem = Vec::new();
        File::open(&self.ca_certificate)
            .context("Cannot read signer trust certificate")?
            .take(1_000_001)
            .read_to_end(&mut pem)?;
        ensure!(
            pem.len() <= 1_000_000,
            "Signer trust certificate is too large"
        );
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            roots.add(cert.context("Invalid signer trust certificate")?)?;
        }
        ensure!(!roots.is_empty(), "Signer trust certificate file is empty");
        let provider = rustls::crypto::ring::default_provider();
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = offered.iter().map(|protocol| protocol.to_vec()).collect();
        config.enable_early_data = false;
        let name = rustls::pki_types::ServerName::try_from(self.server_name.clone())?;
        let connection = ClientConnection::new(Arc::new(config), name)?;
        let tcp = TcpStream::connect_timeout(&self.address, remaining(deadline)?)
            .context("Remote signer unavailable; retry the saved operation")?;
        tcp.set_nodelay(true)?;
        let mut stream = StreamOwned::new(
            connection,
            DeadlineSocket {
                socket: tcp,
                deadline,
            },
        );
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .context("Signer TLS authentication failed")?;
        }
        ensure!(
            stream
                .conn
                .alpn_protocol()
                .is_some_and(|protocol| offered.contains(&protocol)),
            "Signer TLS protocol negotiation failed"
        );
        let peer = stream
            .conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .context("Signer supplied no TLS certificate")?;
        let fingerprint: [u8; 32] = Sha256::digest(peer.as_ref()).into();
        ensure!(
            fingerprint == hex32(&self.certificate_sha256)?,
            "Signer certificate fingerprint mismatch"
        );
        Ok(stream)
    }

    /// Opens this thread's next connection in the background while the caller
    /// finishes local work. It is pinned and negotiated exactly as for a
    /// request, but carries no credential or request until one adopts it.
    /// Best effort: without a usable early connection a request connects itself.
    pub fn preconnect(&self) {
        if self.validate().is_ok()
            && let Ok(key) = sessions::key(self)
        {
            sessions::open_early(self, key);
        }
    }

    /// The exact protocol negotiation and certificate pin precede credentials.
    pub fn request(&self, request: &crate::wire::Request) -> Result<Value> {
        self.validate()?;
        let encoded = request.encode()?;
        let deadline = Instant::now() + Duration::from_secs(self.timeout_secs);
        let key = sessions::key(self)?;
        let mut reader = match sessions::take(&key, deadline) {
            Some(stream) => stream,
            None => BufReader::new(self.connect_protocol(deadline, &[SESSION_ALPN, ALPN])?),
        };
        #[derive(Serialize)]
        struct WireRequest<'a> {
            method: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            credential: Option<&'a str>,
            request: &'a str,
        }
        let credential = self.credential()?;
        let mut body = Zeroizing::new(serde_json::to_vec(&WireRequest {
            method: "zark_request",
            credential: credential.as_ref().map(|token| token.as_str()),
            request: std::str::from_utf8(&encoded)?,
        })?);
        drop(credential);
        drop(encoded);
        ensure!(
            body.len() <= crate::wire::MAX_WIRE * 2,
            "private TLS request size"
        );
        body.push(b'\n');
        let _timing = crate::timing::Span::new(crate::timing::Phase::SignerExchange);
        let stream = reader.get_mut();
        stream.write_all(&body)?;
        stream.flush()?;
        drop(body);
        let mut response = Zeroizing::new(Vec::new());
        loop {
            let buffer = reader.fill_buf()?;
            ensure!(
                !buffer.is_empty(),
                "incomplete private signer response; retry exact request"
            );
            let newline = buffer.iter().position(|b| *b == b'\n');
            let take = newline.map_or(buffer.len(), |i| i + 1);
            ensure!(
                response.len() + take <= crate::wire::MAX_WIRE,
                "private signer response size"
            );
            response.extend_from_slice(&buffer[..take]);
            reader.consume(take);
            if newline.is_some() {
                break;
            }
        }
        let reply = decode_response(&response)?;
        ensure!(
            reply["version"] == crate::handoff::PROTOCOL_VERSION,
            "private signer response version"
        );
        let result = reply
            .get("response")
            .cloned()
            .context("missing private signer response")?;
        sessions::put(key, reader);
        Ok(result)
    }

    fn credential(&self) -> Result<Option<Zeroizing<String>>> {
        let Some(path) = &self.credential_file else {
            return Ok(None);
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context("Cannot open signer credential file")?;
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no preconditions and does not access caller memory.
        let uid = unsafe { libc::geteuid() };
        ensure!(
            metadata.is_file()
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.uid() == uid,
            "Signer credentials must be an owner-only regular file"
        );
        let mut token = Zeroizing::new(String::new());
        file.take(1025).read_to_string(&mut token)?;
        ensure!(token.len() <= 1024, "Signer credential file is too large");
        let length = token.trim_end_matches(['\r', '\n']).len();
        token.truncate(length);
        ensure!(
            (32..=256).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic()),
            "Signer credential must contain 32..256 printable ASCII bytes"
        );
        Ok(Some(token))
    }
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .context("Signer request deadline exceeded; retry the saved operation")
}
/// Reapply the remaining absolute budget before every underlying TLS socket IO.
/// A peer sending one byte per timeout cannot extend the total request lifetime.
struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
}
impl DeadlineSocket {
    fn timeout(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Signer request deadline exceeded",
                )
            })
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.socket.set_read_timeout(Some(self.timeout()?))?;
        self.socket.read(buffer)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.socket.set_write_timeout(Some(self.timeout()?))?;
        self.socket.write(buffer)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.set_write_timeout(Some(self.timeout()?))?;
        self.socket.flush()
    }
}

fn decode_response(bytes: &[u8]) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        ok: bool,
        result: Option<Value>,
        error: Option<Value>,
    }
    // Typed JSON diagnostics can echo an unexpected field name or value. The
    // remote peer may put credentials there, so discard the parser's cause.
    let reply: Reply =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("Invalid signer response"))?;
    if reply.ok {
        ensure!(reply.error.is_none(), "Ambiguous signer response");
        return reply.result.context("Missing signer result");
    }
    ensure!(reply.result.is_none(), "Ambiguous signer response");
    let error = reply.error.context("Missing signer error")?;
    // Server messages are untrusted and may echo tokens, proof bytes or paths.
    // Expose only known codes with client-defined retry semantics.
    let (code, retryable) = match error["code"].as_str() {
        Some("overloaded" | "busy" | "rate_limited") => ("overloaded", true),
        Some("timeout" | "unavailable") => ("unavailable", true),
        Some("unauthorized" | "forbidden" | "credential_expired") => ("unauthorized", false),
        Some("conflict" | "stale_revision") => ("conflict", true),
        Some("invalid_request" | "proof_rejected") => ("invalid_request", false),
        _ => ("remote_rejected", false),
    };
    Err(RemoteFailure { code, retryable }.into())
}

#[cfg(test)]
mod tests;
