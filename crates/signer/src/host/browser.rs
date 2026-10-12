//! Browser HTTPS ingress feeds the existing signer and mail workers. It owns no wallet state.
mod config;
mod http;
use super::{
    HostedConfig, NETWORK_LIFETIME, OUTER_LIMIT,
    dispatch::Dispatch,
    reply::Reply,
    transport::{DeadlineStream, Tls, classify, failure, tls_config, unexpired},
    workers,
};
use anyhow::Result;
pub use config::Config;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};
use std::{
    io::BufReader,
    net::{TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(super) struct Listener {
    socket: TcpListener,
    tls: Arc<ServerConfig>,
}
impl Listener {
    pub(super) fn bind(config: &Config) -> Result<Self> {
        let tls = tls_config(
            &config.certificate,
            &config.private_key,
            vec![b"http/1.1".to_vec()],
        )?;
        Ok(Self {
            socket: TcpListener::bind(config.listen)?,
            tls: Arc::new(tls),
        })
    }
    pub(super) fn start(self, dispatch: Dispatch, count: usize, capacity: usize) {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        workers(
            receiver,
            count,
            move |(socket, accepted): (TcpStream, Instant)| {
                if accepted.elapsed() >= NETWORK_LIFETIME {
                    return;
                }
                let Ok(connection) = ServerConnection::new(self.tls.clone()) else {
                    return;
                };
                let _ = socket.set_nodelay(true);
                let stream = StreamOwned::new(
                    connection,
                    DeadlineStream {
                        stream: socket,
                        deadline: accepted + NETWORK_LIFETIME,
                    },
                );
                handle(stream, accepted, &dispatch);
            },
        );
        thread::spawn(move || {
            for socket in self.socket.incoming() {
                match socket {
                    Ok(socket) => {
                        let _ = sender.try_send((socket, Instant::now()));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(100)),
                }
            }
        });
    }
}
pub(super) struct Response {
    stream: Tls,
    origin: Option<String>,
    limit: usize,
}
impl Response {
    pub(super) fn send(mut self, status: u16, value: Value) {
        let Ok(bytes) = serde_json::to_vec(&value).map(Zeroizing::new) else {
            return;
        };
        if bytes.len() >= self.limit {
            return;
        }
        self.stream.sock.deadline = Instant::now() + Duration::from_secs(5);
        let written = http::write_response(
            &mut self.stream,
            status,
            self.origin.as_deref(),
            &bytes,
            false,
        )
        .is_ok();
        if written {
            use std::io::Write;
            self.stream.conn.send_close_notify();
            let _ = self.stream.flush();
        }
    }
    fn preflight(mut self) {
        self.stream.sock.deadline = Instant::now() + Duration::from_secs(5);
        let _ = http::write_response(&mut self.stream, 204, self.origin.as_deref(), &[], true);
    }
}
fn reject(stream: Tls, origin: Option<String>, status: u16, code: &str) {
    Response {
        stream,
        origin,
        limit: OUTER_LIMIT,
    }
    .send(status, failure(code, false));
}
fn handle(stream: Tls, accepted: Instant, dispatch: &Dispatch) {
    let peer = match stream.sock.stream.peer_addr() {
        Ok(peer) => peer.ip(),
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let head = match http::read_head(&mut reader) {
        Ok(head) => head,
        Err(_) => return reject(reader.into_inner(), None, 400, "invalid_request"),
    };
    let origin = HostedConfig::load(&dispatch.path)
        .ok()
        .and_then(|c| c.browser)
        .and_then(|c| {
            c.response_origin(
                head.header("host"),
                head.header("origin"),
                head.method == "GET"
                    && head.path == "/health"
                    && head.header("sec-fetch-site") == Some("same-origin"),
            )
        });
    if origin.is_none() {
        return reject(reader.into_inner(), None, 403, "origin_denied");
    }
    let method = match head.path.as_str() {
        "/v1/signer" | "/v1/mail" => "POST",
        "/health" => "GET",
        _ => return reject(reader.into_inner(), origin, 404, "not_found"),
    };
    if head.method == "OPTIONS" {
        if !head.preflight(method) {
            return reject(reader.into_inner(), origin, 400, "invalid_request");
        }
        return Response {
            stream: reader.into_inner(),
            origin,
            limit: OUTER_LIMIT,
        }
        .preflight();
    }
    if head.method != method {
        return reject(reader.into_inner(), origin, 405, "method_not_allowed");
    }
    if method == "GET" {
        if !head.empty() {
            return reject(reader.into_inner(), origin, 400, "invalid_request");
        }
        // Identity is for configuration checking, not a replacement for pinned
        // deployment files or protocol signatures at the wallet.
        return Response {
            stream: reader.into_inner(),
            origin,
            limit: OUTER_LIMIT,
        }
        .send(
            200,
            json!({"service":"zark-browser","version":1,"protocol_version":10}),
        );
    }
    if !head.json() {
        return reject(reader.into_inner(), origin, 415, "json_required");
    }
    let mail = head.path == "/v1/mail";
    let limit = if mail {
        zark_protocol::mail::MAX_WIRE
    } else {
        OUTER_LIMIT
    };
    let body = match http::read_body(&mut reader, &head, limit) {
        Ok(body) => body,
        Err(_) => return reject(reader.into_inner(), origin, 400, "invalid_request"),
    };
    let stream = reader.into_inner();
    let reply = Reply::Browser(Response {
        stream,
        origin,
        limit: if mail {
            zark_protocol::mail::MAX_WIRE
        } else {
            zark_protocol::wire::MAX_WIRE
        },
    });
    if let Err(error) = unexpired(accepted + NETWORK_LIFETIME) {
        return reply.reject(classify(&error));
    }
    if mail {
        // The native and HTTPS envelope, tokens and registration signatures are identical.
        let parsed = dispatch.mail_permits(peer).and_then(|permits| {
            let request = serde_json::from_slice(&body)
                .map_err(|_| anyhow::anyhow!("invalid mail request"))?;
            Ok((request, permits))
        });
        match parsed {
            Ok((request, permits)) => dispatch.messaging(reply, request, permits, accepted),
            Err(error) => reply.reject(classify(&error)),
        }
    } else {
        dispatch.browser_signing(&body, reply, accepted, peer);
    }
}

#[cfg(test)]
pub(super) mod tests;
