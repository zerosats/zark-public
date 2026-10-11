//! Cookie-authenticated loopback RPC. Reuse connections, never observations.
//! Failed calls are not automatically replayed (a broadcast may have succeeded).
use super::ChainConfig;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    fs::File,
    io::{BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY: usize = 4_000_000;
static IDLE: Mutex<VecDeque<Connection>> = Mutex::new(VecDeque::new());

struct Connection {
    key: [u8; 32],
    reader: BufReader<TcpStream>,
    idle_since: Instant,
}

pub(super) fn call(chain: &ChainConfig, method: &str, args: &[String]) -> Result<Value> {
    // Match bitcoin-cli: explicit relative cookie paths are relative to the
    // network data directory; an absolute path replaces that prefix.
    let network_dir = chain.datadir.join(match chain.deployment.network {
        zark_protocol::network::Network::Regtest => "regtest",
        zark_protocol::network::Network::CustomSignet => "signet",
    });
    let cookie_path = network_dir.join(
        chain
            .rpc_cookie
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new(".cookie")),
    );
    let mut cookie = Zeroizing::new(Vec::new());
    File::open(cookie_path)
        .context("Bitcoin RPC cookie unavailable")?
        .take(4097)
        .read_to_end(&mut cookie)?;
    ensure!(cookie.len() <= 4096, "Bitcoin RPC cookie exceeds limit");
    let cookie = std::str::from_utf8(&cookie)
        .context("invalid Bitcoin RPC cookie")?
        .trim();
    ensure!(
        cookie.contains(':') && !cookie.contains(['\r', '\n']),
        "invalid Bitcoin RPC cookie"
    );
    // Include the whole configuration and current credential. Cookie rotation
    // must not reuse a connection authenticated under the old credential.
    let key = zark_protocol::hash(&[&serde_json::to_vec(chain)?, cookie.as_bytes()]);
    let deadline = Instant::now() + TIMEOUT;
    let cached = {
        let mut idle = IDLE
            .lock()
            .map_err(|_| anyhow::anyhow!("Bitcoin RPC pool unavailable"))?;
        idle.retain(|c| c.idle_since.elapsed() < Duration::from_secs(1));
        idle.iter()
            .position(|c| c.key == key)
            .and_then(|index| idle.remove(index))
    };
    let mut connection = match cached {
        Some(connection) => connection,
        None => {
            let address = SocketAddr::from((Ipv4Addr::LOCALHOST, chain.rpc_port));
            let socket = TcpStream::connect_timeout(&address, remaining(deadline)?)
                .context("Bitcoin RPC connection failed")?;
            socket.set_nodelay(true)?;
            Connection {
                key,
                reader: BufReader::new(socket),
                idle_since: Instant::now(),
            }
        }
    };
    let body = Zeroizing::new(serde_json::to_vec(&json!({
        "jsonrpc":"1.0", "id":"zark", "method":method, "params":parameters(method, args)?
    }))?);
    ensure!(body.len() <= MAX_BODY, "Bitcoin RPC request exceeds limit");
    let authorization = Zeroizing::new(STANDARD.encode(cookie));
    let header = Zeroizing::new(format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        chain.rpc_port,
        &*authorization,
        body.len()
    ));
    write_deadline(connection.reader.get_mut(), header.as_bytes(), deadline)?;
    write_deadline(connection.reader.get_mut(), &body, deadline)?;
    let (value, keep) = response(&mut connection.reader, deadline)?;
    if keep {
        connection.idle_since = Instant::now();
        let mut idle = IDLE
            .lock()
            .map_err(|_| anyhow::anyhow!("Bitcoin RPC pool unavailable"))?;
        if idle.len() == 8 {
            idle.pop_front();
        }
        idle.push_back(connection);
    }
    Ok(value)
}

// Match bitcoin-cli's argument conversions for exactly the wallet's methods.
// In particular a hexadecimal transaction/hash must remain a JSON string.
fn parameters(method: &str, args: &[String]) -> Result<Vec<Value>> {
    let count = match method {
        "getblockchaininfo" | "zark_prepare" => 0,
        "getblockhash" | "getmempoolentry" | "sendrawtransaction" | "testmempoolaccept" => 1,
        "getrawtransaction" => 2,
        "gettxout" => 3,
        "zark_observe" => 5,
        _ => anyhow::bail!("unsupported Bitcoin RPC method"),
    };
    ensure!(args.len() == count, "invalid Bitcoin RPC argument count");
    args.iter()
        .enumerate()
        .map(|(index, value)| {
            let parsed = matches!(
                (method, index),
                ("getblockhash", 0)
                    | ("getrawtransaction", 1)
                    | ("gettxout", 1 | 2)
                    | ("testmempoolaccept", 0)
            );
            if parsed {
                serde_json::from_str(value).context("invalid Bitcoin RPC argument")
            } else {
                Ok(Value::String(value.clone()))
            }
        })
        .collect()
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .context("Bitcoin RPC exceeded its time limit")
}

fn write_deadline(socket: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        socket.set_write_timeout(Some(remaining(deadline)?))?;
        let count = socket.write(bytes).context("Bitcoin RPC write failed")?;
        ensure!(count != 0, "Bitcoin RPC connection closed");
        bytes = &bytes[count..];
    }
    Ok(())
}

fn read(reader: &mut BufReader<TcpStream>, bytes: &mut [u8], deadline: Instant) -> Result<usize> {
    reader
        .get_ref()
        .set_read_timeout(Some(remaining(deadline)?))?;
    reader.read(bytes).context("Bitcoin RPC read failed")
}

fn response(reader: &mut BufReader<TcpStream>, deadline: Instant) -> Result<(Value, bool)> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        ensure!(
            header.len() < 16_384,
            "Bitcoin RPC response headers exceed limit"
        );
        let mut byte = [0];
        ensure!(
            read(reader, &mut byte, deadline)? == 1,
            "Bitcoin RPC truncated headers"
        );
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header).context("Bitcoin RPC invalid headers")?;
    let mut lines = text.split("\r\n");
    let status = lines.next().context("Bitcoin RPC missing status")?;
    let mut words = status.split_whitespace();
    let version = words.next();
    ensure!(
        matches!(version, Some("HTTP/1.1" | "HTTP/1.0")),
        "Bitcoin RPC invalid HTTP version"
    );
    ensure!(words.next() == Some("200"), "Bitcoin RPC HTTP failure");
    let mut length = None;
    let mut keep = version == Some("HTTP/1.1");
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .context("Bitcoin RPC malformed header")?;
        if name.eq_ignore_ascii_case("content-length") {
            ensure!(length.is_none(), "Bitcoin RPC duplicate content length");
            let value = value.trim();
            ensure!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "Bitcoin RPC invalid content length"
            );
            length = Some(
                value
                    .parse::<usize>()
                    .context("Bitcoin RPC invalid content length")?,
            );
        }
        ensure!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "Bitcoin RPC unsupported transfer encoding"
        );
        if name.eq_ignore_ascii_case("connection") && value.trim().eq_ignore_ascii_case("close") {
            keep = false;
        }
    }
    let length = length.context("Bitcoin RPC missing content length")?;
    ensure!(length <= MAX_BODY, "Bitcoin RPC response exceeds limit");
    let mut bytes = vec![0; length];
    let mut filled = 0;
    while filled < length {
        let count = read(reader, &mut bytes[filled..], deadline)?;
        ensure!(count > 0, "Bitcoin RPC truncated body");
        filled += count;
    }
    let mut value: Value =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Bitcoin RPC invalid JSON"))?;
    ensure!(
        value["id"] == "zark"
            && value.get("error").is_some_and(Value::is_null)
            && value.get("result").is_some(),
        "Bitcoin RPC response failed or mismatched"
    );
    Ok((value["result"].take(), keep))
}

#[cfg(test)]
#[path = "rpc_http_tests.rs"]
mod tests;
