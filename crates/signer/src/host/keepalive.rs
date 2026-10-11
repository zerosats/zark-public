//! Bounded idle TLS pools. Idle peers occupy neither ingress nor proof workers.
use super::{Duration, Instant, Result, TcpStream, Tls, mpsc, thread};
use std::os::fd::AsRawFd;

pub(super) enum Ingress {
    New(TcpStream),
    Reused(Box<Tls>),
    /// A new connection after its handshake. It keeps the network deadline set
    /// when it was accepted, so holding it never extends its first request.
    Handshaken(Box<Tls>),
}
pub(super) type IngressQueue = mpsc::SyncSender<(Ingress, Instant)>;

/// The connections one pool holds until they become readable.
#[derive(Clone, Copy)]
pub(super) enum Held {
    /// Sessions between requests, for at most 30 s. A full pool closes them.
    Sessions,
    /// Early connections before their first request, until their network
    /// deadline. A full pool returns them to a network worker, which waits for
    /// the request exactly as it does for any other new connection.
    FirstRequests,
}

pub(super) fn start(ingress: IngressQueue, capacity: usize, held: Held) -> mpsc::SyncSender<Tls> {
    let capacity = capacity.clamp(1, 64);
    let (sender, receiver) = mpsc::sync_channel::<Tls>(capacity);
    thread::spawn(move || {
        let mut idle: Vec<(Tls, Instant)> = Vec::new();
        loop {
            // Both queue and parked set are bounded, independent of traffic.
            for _ in 0..capacity {
                match receiver.try_recv() {
                    Ok(stream) if idle.len() < capacity => {
                        let expires = match held {
                            Held::Sessions => Instant::now() + Duration::from_secs(30),
                            Held::FirstRequests => stream.sock.deadline,
                        };
                        idle.push((stream, expires));
                    }
                    Ok(stream) => {
                        // Close excess idle sessions; never replay work.
                        if let Held::FirstRequests = held {
                            let _ = ingress
                                .try_send((Ingress::Handshaken(Box::new(stream)), Instant::now()));
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return,
                }
            }
            idle.retain(|(_, expires)| Instant::now() < *expires);
            let mut polls: Vec<libc::pollfd> = idle
                .iter()
                .map(|(stream, _)| libc::pollfd {
                    fd: stream.sock.stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            // SAFETY: the descriptors and contiguous array remain live through
            // poll. All I/O and TLS parsing stay in the bounded ingress workers.
            let ready = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 10) };
            if ready > 0 {
                for i in (0..polls.len()).rev() {
                    if polls[i].revents != 0 {
                        let (stream, _) = idle.swap_remove(i);
                        let stream = Box::new(stream);
                        let resumed = match held {
                            Held::Sessions => Ingress::Reused(stream),
                            Held::FirstRequests => Ingress::Handshaken(stream),
                        };
                        let _ = ingress.try_send((resumed, Instant::now()));
                    }
                }
            }
        }
    });
    sender
}

pub(super) fn park(sender: &mpsc::SyncSender<Tls>, stream: Tls, written: bool) {
    if written
        && (zark_protocol::remote::is_session_alpn(stream.conn.alpn_protocol())
            || stream.conn.alpn_protocol() == Some(zark_protocol::mail::SESSION_ALPN))
    {
        let _ = sender.try_send(stream);
    }
}

/// Whether any of the first request has arrived, in TLS buffers or the socket.
pub(super) fn request_started(stream: &mut Tls) -> Result<bool> {
    if stream.conn.process_new_packets()?.plaintext_bytes_to_read() > 0 {
        return Ok(true);
    }
    let mut poll = libc::pollfd {
        fd: stream.sock.stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live descriptor and one pollfd for the duration of the call.
    Ok(unsafe { libc::poll(&mut poll, 1, 0) } != 0)
}

/// Holds an early connection until its first request starts to arrive.
pub(super) fn hold(pool: &mpsc::SyncSender<Tls>, ingress: &IngressQueue, stream: Tls) {
    if let Err(mpsc::TrySendError::Full(stream) | mpsc::TrySendError::Disconnected(stream)) =
        pool.try_send(stream)
    {
        let _ = ingress.try_send((Ingress::Handshaken(Box::new(stream)), Instant::now()));
    }
}
