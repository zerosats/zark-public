//! Small thread-local pool: no shared requests, credentials or automatic replay.
use super::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    sync::{Mutex, PoisonError},
    thread::JoinHandle,
};

pub(super) type Connection = BufReader<StreamOwned<ClientConnection, DeadlineSocket>>;
type Saved = ([u8; 32], Instant, Connection);
/// A connection opened on a helper thread for this thread's next request.
struct Early {
    key: [u8; 32],
    started: Instant,
    connection: JoinHandle<Result<StreamOwned<ClientConnection, DeadlineSocket>>>,
}
thread_local! {
    static POOL: RefCell<VecDeque<Saved>> = const { RefCell::new(VecDeque::new()) };
    static EARLY: RefCell<Option<Early>> = const { RefCell::new(None) };
}
/// Endpoints whose signer refused [`EARLY_SESSION_ALPN`] in this process.
static REFUSED: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());
const POOL_LIFETIME: Duration = Duration::from_secs(20);
/// Well inside the signer's 8 s network lifetime, which bounds how long it
/// holds an accepted connection before the first request arrives.
const EARLY_LIFETIME: Duration = Duration::from_secs(4);

fn early_deadline(started: Instant, timeout_secs: u64) -> Instant {
    started + Duration::from_secs(timeout_secs).min(EARLY_LIFETIME)
}

pub(super) fn key(endpoint: &RemoteEndpoint) -> Result<[u8; 32]> {
    // Re-read trust bytes before reusing a channel; a changed CA, pin, address,
    // credential path or configuration must never select another profile's TLS.
    let pem = crate::assets::read_bounded(&endpoint.ca_certificate, 1_000_000)?;
    Ok(crate::hash(&[&serde_json::to_vec(endpoint)?, &pem]))
}
pub(super) fn take(key: &[u8; 32], deadline: Instant) -> Option<Connection> {
    let pooled = POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        pool.retain(|(_, saved, _)| saved.elapsed() < POOL_LIFETIME);
        let position = pool.iter().position(|(context, _, _)| context == key)?;
        pool.remove(position).map(|(_, _, connection)| connection)
    });
    let mut connection = pooled
        .and_then(|mut connection| open(&mut connection).then_some(connection))
        .or_else(|| take_early(key))?;
    connection.get_mut().sock.deadline = deadline;
    Some(connection)
}
pub(super) fn put(key: [u8; 32], connection: Connection) {
    // Legacy peers retain one-request-per-connection semantics. No speculative
    // reuse: a session ALPN must have been authenticated in the TLS handshake.
    if !is_session_alpn(connection.get_ref().conn.alpn_protocol())
        || !connection.buffer().is_empty()
    {
        return;
    }
    POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if pool.len() == 4 {
            pool.pop_front();
        }
        pool.push_back((key, Instant::now(), connection));
    });
}

pub(super) fn open_early(endpoint: &RemoteEndpoint, key: [u8; 32]) {
    let pooled = POOL.with(|pool| {
        pool.borrow_mut()
            .iter_mut()
            .any(|(context, saved, connection)| {
                *context == key && saved.elapsed() < POOL_LIFETIME && open(connection)
            })
    });
    let pending = EARLY.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|early| early.key == key && early.started.elapsed() < EARLY_LIFETIME)
    });
    if pooled || pending || refused().contains(&key) {
        return;
    }
    let endpoint = endpoint.clone();
    let started = Instant::now();
    // A speculative connection is only useful during EARLY_LIFETIME. Giving
    // its background handshake the full request timeout lets take_early block
    // on a dead peer long after this connection should have expired.
    let deadline = early_deadline(started, endpoint.timeout_secs);
    let Ok(connection) = std::thread::Builder::new().spawn(move || {
        let connection = endpoint.connect_protocol(deadline, &[EARLY_SESSION_ALPN]);
        if connection.as_ref().is_err_and(refused_protocol) {
            refuse(key);
        }
        connection
    }) else {
        return;
    };
    EARLY.with(|slot| {
        *slot.borrow_mut() = Some(Early {
            key,
            started,
            connection,
        })
    });
}
fn take_early(key: &[u8; 32]) -> Option<Connection> {
    let early = EARLY.with(|slot| slot.borrow_mut().take_if(|early| early.key == *key))?;
    let _timing = crate::timing::Span::new(crate::timing::Phase::SignerConnectWait);
    let mut connection = BufReader::new(early.connection.join().ok()?.ok()?);
    (early.started.elapsed() < EARLY_LIFETIME && open(&mut connection)).then_some(connection)
}
/// A peer that already closed an idle connection never received this request,
/// so connecting again is not a replay. Later losses stay uncertain. Records
/// that already arrived, such as session tickets, are processed first so they
/// cannot hide a close behind them.
fn open(connection: &mut Connection) -> bool {
    if !connection.buffer().is_empty() {
        return false;
    }
    let stream = connection.get_mut();
    if stream.sock.socket.set_nonblocking(true).is_err() {
        return false;
    }
    let open = loop {
        match stream.conn.read_tls(&mut stream.sock.socket) {
            Ok(0) => break false,
            Ok(_) => match stream.conn.process_new_packets() {
                Ok(state) if state.plaintext_bytes_to_read() == 0 && !state.peer_has_closed() => {}
                _ => break false,
            },
            Err(error) => break error.kind() == std::io::ErrorKind::WouldBlock,
        }
    };
    stream.sock.socket.set_nonblocking(false).is_ok() && open
}
fn refused_protocol(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::AlertReceived(
                rustls::AlertDescription::NoApplicationProtocol
            ))
        )
    })
}

fn refused() -> std::sync::MutexGuard<'static, Vec<[u8; 32]>> {
    REFUSED.lock().unwrap_or_else(PoisonError::into_inner)
}
fn refuse(key: [u8; 32]) {
    let mut refused = refused();
    if !refused.contains(&key) {
        if refused.len() == 8 {
            refused.remove(0);
        }
        refused.push(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speculative_handshake_never_uses_the_full_request_timeout() {
        let started = Instant::now();
        assert_eq!(
            early_deadline(started, 300).duration_since(started),
            EARLY_LIFETIME
        );
        assert_eq!(
            early_deadline(started, 1).duration_since(started),
            Duration::from_secs(1)
        );
    }
}
