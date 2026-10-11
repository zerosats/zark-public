//! Restricted prover process environment, resource limits and cleanup.
//! The caller retains the proof-job lock; its explicit inheritance survives exec.
use anyhow::{Context, Result, ensure};
use std::{
    io,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use zark_protocol::timing::{Phase, Span};

const WALL_SECONDS: u32 = 3600;

pub(super) struct Running(pub(super) Child);
impl Drop for Running {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.wait();
    }
}
pub(super) fn prepare(
    command: &mut Command,
    directory: &Path,
    threads: u16,
    fast_msm: bool,
) -> Result<()> {
    let _span = Span::new(Phase::ProverProcessPrepare);
    ensure!((1..=64).contains(&threads), "invalid prover worker count");
    let home = std::env::var_os("HOME").context("prover dependency cache home")?;
    let descriptors = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    ensure!(
        descriptors > 0 && descriptors <= i32::MAX as _,
        "prover descriptor limit"
    );
    // A lower soft limit does not close descriptors inherited above it. Scan
    // those too, while covering concurrent opens below the unchanged soft limit.
    let mut descriptor_end = descriptors as i32;
    for entry in std::fs::read_dir("/dev/fd").context("inspect inherited prover descriptors")? {
        if let Some(fd) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        {
            descriptor_end = descriptor_end.max(fd.saturating_add(1));
        }
    }
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", directory)
        .env("HARDWARE_CONCURRENCY", threads.to_string())
        .env("BB_HARDWARE_CONCURRENCY", threads.to_string())
        .env("RAYON_NUM_THREADS", threads.to_string())
        .env("OMP_NUM_THREADS", threads.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Presence selects the backend path. env_clear also removes legacy, bench,
    // and experimental QoS flags; setting them to "0" would still enable them.
    if fast_msm {
        command.env("BB_MSM_NEW", "1");
    }
    // Async-signal-safe operations only. Credentials and open wallet/network
    // descriptors do not survive exec. The alarm also bounds an orphaned job.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            for fd in 3..descriptor_end {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EBADF) {
                        return Err(error);
                    }
                } else if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::signal(libc::SIGALRM, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            if libc::sigemptyset(signals.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut signals = signals.assume_init();
            if libc::sigaddset(&mut signals, libc::SIGALRM) != 0
                || libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::alarm(WALL_SECONDS);
            for (resource, max) in [
                (libc::RLIMIT_CORE, 0u64),
                (libc::RLIMIT_CPU, WALL_SECONDS as u64),
                (libc::RLIMIT_FSIZE, 1024 * 1024 * 1024),
            ] {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(resource, &mut limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                limit.rlim_cur = limit.rlim_cur.min(max as _);
                limit.rlim_max = limit.rlim_max.min(max as _);
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Register after descriptor cleanup: only the current proof-job lock is
    // deliberately inherited. An orphaned prover must exclude a competing retry.
    zark_protocol::local::inherit_operation_lock(command);
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
#[path = "process_tests.rs"]
mod tests;

pub(super) fn run(
    command: &mut Command,
    directory: &Path,
    message: &str,
    threads: u16,
    fast_msm: bool,
) -> Result<()> {
    prepare(command, directory, threads, fast_msm)?;
    let mut child = {
        let _span = Span::new(Phase::ProverProcessSpawn);
        Running(command.spawn().context("start private prover")?)
    };
    let _span = Span::new(Phase::ProverProcessWait);
    let deadline = Instant::now() + Duration::from_secs(WALL_SECONDS as u64);
    loop {
        if let Some(status) = child.0.try_wait()? {
            ensure!(status.success(), "{message}");
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "private prover deadline exceeded"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}
