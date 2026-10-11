//! Helper process lifecycle: parent watch, authenticated constants, loopback
//! bind, exactly one readiness line, then one connection at a time.
use super::{http, rpc, tables::Tables};
use std::{
    ffi::OsString,
    io::{BufReader, Write},
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::fd::{FromRawFd, OwnedFd},
    time::Duration,
};

const BIND: Ipv4Addr = Ipv4Addr::LOCALHOST;
const BACKLOG: libc::c_int = 8;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);
const PARENT_POLL: Duration = Duration::from_millis(250);

/// Run the helper with `respond` producing each response body. Exits only:
/// on bad arguments (2), a corrupt build, bind failure or parent death (1), or
/// SIGINT/SIGTERM (0). It writes nothing after its readiness line.
pub fn run(respond: impl Fn(&Tables, &[u8]) -> Vec<u8>) -> ! {
    // A panic message could describe internal state; never print one.
    std::panic::set_hook(Box::new(|_| {}));
    let Some(port) = port_argument(std::env::args_os().skip(1)) else {
        eprintln!("usage: zark-fast-helper [--port PORT]");
        std::process::exit(2);
    };
    watch_parent();
    // Authenticate the embedded pins and ROM before binding or readiness.
    let Ok(tables) = Tables::load() else {
        std::process::exit(1)
    };
    let Ok((listener, port)) = bind(port) else {
        std::process::exit(1)
    };
    let ready = format!(
        "{{\"ready\": true, \"host\": \"{BIND}\", \"port\": {port}, \"url\": \"http://{BIND}:{port}/\", \"cache\": false}}\n"
    );
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(ready.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        std::process::exit(1);
    }
    drop(stdout);
    stop_on_signals();
    loop {
        if let Ok((stream, peer)) = listener.accept() {
            serve(&stream, peer, |raw| respond(&tables, raw));
        }
    }
}

/// `--port N` or `--port=N` (decimal, last one wins); the default is 0.
fn port_argument(mut args: impl Iterator<Item = OsString>) -> Option<u16> {
    let mut port = 0;
    while let Some(arg) = args.next() {
        let value = match arg.to_str()? {
            "--port" => args.next()?.into_string().ok()?,
            other => other.strip_prefix("--port=")?.to_owned(),
        };
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        port = value.parse().ok()?;
    }
    Some(port)
}

/// If the wallet is killed, release this helper's inherited proof-job lock.
/// An executor still running retains its own lock until it exits, and a failed
/// foreign call cannot commit an incomplete proof. Checked before loading so a
/// helper whose parent already died never opens a socket.
fn watch_parent() {
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        unsafe { libc::_exit(1) };
    }
    std::thread::spawn(move || {
        loop {
            if unsafe { libc::getppid() } != parent {
                unsafe { libc::_exit(1) };
            }
            std::thread::sleep(PARENT_POLL);
        }
    });
}

extern "C" fn stop(_: libc::c_int) {
    // Async-signal-safe; there is no state to flush or persist.
    unsafe { libc::_exit(0) };
}

fn stop_on_signals() {
    let handler = stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

/// Bind exactly 127.0.0.1 without SO_REUSEADDR and with the reference's
/// backlog, which `std::net::TcpListener::bind` would not preserve.
fn bind(port: u16) -> std::io::Result<(TcpListener, u16)> {
    let error = std::io::Error::last_os_error;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_vendor = "apple")]
    {
        address.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    }
    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_port = port.to_be();
    address.sin_addr = libc::in_addr {
        s_addr: u32::from(BIND).to_be(),
    };
    let bound = unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) == 0
            && libc::bind(
                fd,
                (&raw const address).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) == 0
            && libc::listen(fd, BACKLOG) == 0
    };
    if !bound {
        return Err(error());
    }
    let listener = TcpListener::from(socket);
    let local = listener.local_addr()?;
    if local.ip() != IpAddr::V4(BIND) || local.port() == 0 {
        return Err(std::io::ErrorKind::AddrNotAvailable.into());
    }
    Ok((listener, local.port()))
}

fn serve(stream: &TcpStream, peer: SocketAddr, respond: impl Fn(&[u8]) -> Vec<u8>) {
    // Like the reference's verify_request: only the exact loopback client.
    if peer.ip() != IpAddr::V4(BIND)
        || stream.set_read_timeout(Some(SOCKET_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(SOCKET_TIMEOUT)).is_err()
    {
        return;
    }
    let (status, framing, body) = match http::read_request(&mut BufReader::new(stream)) {
        http::Request::Body(raw, framing) => (200, framing, respond(&raw)),
        http::Request::Reject(status, framing) => (status, framing, rpc::rejected()),
        http::Request::Drop => return,
    };
    let mut writer = stream;
    if http::write_response(&mut writer, status, framing, &body).is_ok() {
        let _ = stream.shutdown(Shutdown::Write);
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
