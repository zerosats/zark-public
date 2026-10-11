//! Defense-in-depth limits for the pinned verifier executable.
//!
//! These are process resource limits, not a filesystem or network sandbox.
//! NPROC is a per-UID ceiling (and is ineffective for privileged Linux users),
//! so a hosted signer must run under its own unprivileged service account.
//! Linux no_new_privs prevents exec-derived privileges; it does not drop any
//! existing capabilities. The service account must have none to begin with.
//! Linux AS limits address space. macOS RSS/thread monitoring is sampled every
//! 20ms by the verifier loop and can overshoot between samples; it is not a hard
//! mmap-memory ceiling. Darwin rejects a pre-exec DATA rlimit below the parent's
//! inherited virtual mappings. Operator sandboxing is still required for a
//! hostile verifier binary, particularly on macOS.
use anyhow::{Context, Result, ensure};
use std::{
    io,
    os::unix::process::CommandExt,
    process::{Child, Command, ExitStatus},
};

pub(crate) const CPU_SECONDS: u64 = 30;
pub(crate) const WALL_SECONDS: u64 = 60;
#[cfg(target_os = "linux")]
pub(crate) const ADDRESS_SPACE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
#[cfg(target_os = "macos")]
pub(crate) const RESIDENT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
#[cfg(target_os = "macos")]
pub(crate) const THREADS: i32 = 16;
pub(crate) const FILE_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const FILE_DESCRIPTORS: u64 = 256;
pub(crate) const USER_PROCESSES: u64 = 1024;

// glibc uses an unsigned resource identifier; macOS and musl use c_int.
#[cfg(all(target_os = "linux", any(target_env = "gnu", target_env = "uclibc")))]
type LimitResource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", any(target_env = "gnu", target_env = "uclibc"))))]
type LimitResource = libc::c_int;

/// Apply only async-signal-safe syscalls in the forked child's pre-exec hook.
/// CLOEXEC preserves Rust's spawn-error pipe until exec but prevents unrelated
/// signer sockets, files, database handles, and credentials reaching bb.
pub(crate) fn restrict(command: &mut Command) -> Result<()> {
    let lock = crate::local::operation_lock_fd();
    #[cfg(target_os = "linux")]
    let parent_pid = unsafe { libc::getpid() };
    // Query before fork. Iterate the soft descriptor namespace, plus any
    // existing descriptors above it. This also covers concurrent opens while
    // the process keeps its descriptor limit unchanged, as this service does.
    let mut nofile = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut nofile) } == 0,
        "read verifier descriptor limit: {}",
        io::Error::last_os_error()
    );
    let open_max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    ensure!(
        open_max > 0 && open_max <= i32::MAX as _,
        "unbounded descriptor namespace"
    );
    let mut fd_end = open_max as i32;
    for entry in std::fs::read_dir("/dev/fd").context("inspect inherited verifier descriptors")? {
        if let Some(fd) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        {
            fd_end = fd_end.max(fd.saturating_add(1));
        }
    }
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("OMP_NUM_THREADS", "2")
        .env("RAYON_NUM_THREADS", "2")
        .env("HARDWARE_CONCURRENCY", "2")
        .env("BB_HARDWARE_CONCURRENCY", "2")
        .env("OPENBLAS_NUM_THREADS", "2");
    // SAFETY: the closure only uses libc syscalls and captured integer values.
    // It does not allocate, acquire a mutex, or call a non-signal-safe runtime.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            // The alarm survives exec, so an idle verifier also has a deadline
            // if its wallet/service parent dies and cannot run the wait loop.
            if libc::signal(libc::SIGALRM, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            if libc::signal(libc::SIGXCPU, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            if libc::sigemptyset(signals.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut signals = signals.assume_init();
            if libc::sigaddset(&mut signals, libc::SIGALRM) != 0
                || libc::sigaddset(&mut signals, libc::SIGXCPU) != 0
                || libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::alarm(WALL_SECONDS as u32);
            #[cfg(target_os = "linux")]
            linux_descriptors_cloexec(fd_end, close_range_cloexec)?;
            #[cfg(not(target_os = "linux"))]
            scan_descriptors_cloexec(fd_end)?;
            if let Some(fd) = lock {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for (resource, ceiling) in [
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_CPU, CPU_SECONDS),
                (libc::RLIMIT_FSIZE, FILE_BYTES),
                (libc::RLIMIT_NOFILE, FILE_DESCRIPTORS),
                (libc::RLIMIT_NPROC, USER_PROCESSES),
            ] {
                lower_limit(resource, ceiling)?;
            }
            #[cfg(target_os = "linux")]
            {
                lower_limit(libc::RLIMIT_AS, ADDRESS_SPACE_BYTES)?;
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(io::Error::from_raw_os_error(libc::ECHILD));
                }
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn close_range_cloexec() -> io::Result<()> {
    // Invoke the syscall directly so this does not require glibc >= 2.34.
    // CLOEXEC retains Rust's exec-error pipe until the actual exec succeeds.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
unsafe fn linux_descriptors_cloexec(
    fd_end: i32,
    close_range: unsafe fn() -> io::Result<()>,
) -> io::Result<()> {
    match unsafe { close_range() } {
        Ok(()) => Ok(()),
        // Old kernels lack the syscall/flag; some container seccomp profiles
        // return EPERM. The full captured namespace scan preserves isolation.
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
            ) =>
        unsafe { scan_descriptors_cloexec(fd_end) },
        Err(error) => Err(error),
    }
}

unsafe fn scan_descriptors_cloexec(fd_end: i32) -> io::Result<()> {
    for fd in 3..fd_end {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
        } else if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

unsafe fn lower_limit(resource: LimitResource, ceiling: u64) -> io::Result<()> {
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(resource, &mut old) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let hard = old.rlim_max.min(ceiling as libc::rlim_t);
    let new = libc::rlimit {
        rlim_cur: old.rlim_cur.min(hard),
        rlim_max: hard,
    };
    if unsafe { libc::setrlimit(resource, &new) } != 0 {
        let error = io::Error::last_os_error();
        // Static, non-secret diagnostics use an async-signal-safe syscall.
        let label: &[u8] = match resource {
            libc::RLIMIT_CORE => b"verifier RLIMIT_CORE rejected\n",
            libc::RLIMIT_CPU => b"verifier RLIMIT_CPU rejected\n",
            libc::RLIMIT_FSIZE => b"verifier RLIMIT_FSIZE rejected\n",
            libc::RLIMIT_NOFILE => b"verifier RLIMIT_NOFILE rejected\n",
            libc::RLIMIT_NPROC => b"verifier RLIMIT_NPROC rejected\n",
            _ => b"verifier memory rlimit rejected\n",
        };
        unsafe {
            libc::write(libc::STDERR_FILENO, label.as_ptr().cast(), label.len());
        }
        return Err(error);
    }
    Ok(())
}

/// Every exit path kills the verifier's process group and reaps the direct child.
/// The process group also contains any descendants created by the backend.
pub(crate) struct Process(pub Child);
impl Process {
    pub(crate) fn spawn(command: &mut Command) -> Result<Self> {
        let _span = crate::timing::Span::new(crate::timing::Phase::VerifierProcessSpawn);
        Ok(Self(
            command
                .spawn()
                .context("start resource-limited proof verifier")?,
        ))
    }
    pub(crate) fn enforce_runtime_limits(&mut self) -> Result<Option<ExitStatus>> {
        #[cfg(target_os = "macos")]
        {
            let info = match task_info(self.0.id()) {
                Ok(info) => info,
                Err(error) => {
                    return exit_after_monitor_error(&mut self.0, error);
                }
            };
            ensure!(
                info.pti_resident_size <= RESIDENT_BYTES,
                "proof verifier resident-memory limit exceeded"
            );
            ensure!(
                info.pti_threadnum <= THREADS,
                "proof verifier thread limit exceeded"
            );
        }
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
fn exit_after_monitor_error(child: &mut Child, error: io::Error) -> Result<Option<ExitStatus>> {
    use std::time::{Duration, Instant};

    // During Darwin's exit teardown, proc_pidinfo can report ESRCH before
    // waitpid exposes the exit status. Recheck for a bounded interval rather
    // than accepting an unmonitored live child or blocking indefinitely.
    let grace = if error.raw_os_error() == Some(libc::ESRCH) {
        Duration::from_millis(100)
    } else {
        Duration::ZERO
    };
    let deadline = Instant::now() + grace;
    loop {
        if let Some(status) = child.try_wait().context("reap proof verifier")? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Err(error).context("cannot monitor verifier resources");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(target_os = "macos")]
fn task_info(pid: u32) -> io::Result<libc::proc_taskinfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_taskinfo>();
    // SAFETY: the buffer has the size expected by PROC_PIDTASKINFO and is only
    // assumed initialized after the kernel reports writing the complete value.
    let written = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size as i32,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    if written != size as i32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete verifier resource information",
        ));
    }
    Ok(unsafe { info.assume_init() })
}
impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: restrict() established a private process group with this PID.
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.wait();
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "verifier_process_linux_tests.rs"]
mod linux_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, File},
        os::{fd::AsRawFd, unix::fs::MetadataExt},
    };

    #[test]
    fn subprocess_limits_remove_credentials_and_unrelated_descriptors() -> Result<()> {
        if std::env::var("SC_VERIFIER_RESOURCE_TEST").as_deref() == Ok("1") {
            assert!(std::env::var_os("SC_PARENT_CREDENTIAL_CANARY").is_none());
            for (resource, ceiling) in [
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_CPU, CPU_SECONDS),
                (libc::RLIMIT_FSIZE, FILE_BYTES),
                (libc::RLIMIT_NOFILE, FILE_DESCRIPTORS),
                (libc::RLIMIT_NPROC, USER_PROCESSES),
            ] {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                assert_eq!(unsafe { libc::getrlimit(resource, &mut limit) }, 0);
                assert!(limit.rlim_cur <= ceiling as libc::rlim_t);
                assert!(limit.rlim_max <= ceiling as libc::rlim_t);
            }
            let fd: i32 = std::env::var("SC_PRIVATE_FD")?.parse()?;
            let expected_inode: libc::ino_t = std::env::var("SC_PRIVATE_INODE")?.parse()?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == 0 {
                assert_ne!(unsafe { stat.assume_init() }.st_ino, expected_inode);
            }
            let lock_fd: i32 = std::env::var("SC_LOCK_FD")?.parse()?;
            assert!(unsafe { libc::fcntl(lock_fd, libc::F_GETFD) } >= 0);
            return Ok(());
        }
        let dir = std::env::temp_dir().join(format!(
            "verifier-limits-{}",
            hex::encode(crate::random32())
        ));
        fs::create_dir(&dir)?;
        let result = (|| {
            let private_path = dir.join("credential-canary");
            fs::write(&private_path, b"synthetic test credential")?;
            let private = File::open(&private_path)?;
            // Intentionally simulate a parent library that omitted CLOEXEC.
            ensure!(
                unsafe { libc::fcntl(private.as_raw_fd(), libc::F_SETFD, 0) } == 0,
                "configure test descriptor"
            );
            let _lock = crate::local::ProcessLock::acquire(&dir.join("operation.lock"))?;
            let mut command = Command::new(std::env::current_exe()?);
            command.args(["--exact", "verifier_process::tests::subprocess_limits_remove_credentials_and_unrelated_descriptors", "--nocapture"]);
            command.env("SC_PARENT_CREDENTIAL_CANARY", "must-not-reach-verifier");
            restrict(&mut command)?;
            command
                .env("SC_VERIFIER_RESOURCE_TEST", "1")
                .env("SC_PRIVATE_FD", private.as_raw_fd().to_string())
                .env("SC_PRIVATE_INODE", private.metadata()?.ino().to_string())
                .env(
                    "SC_LOCK_FD",
                    crate::local::operation_lock_fd().unwrap().to_string(),
                );
            let mut child = Process::spawn(&mut command)?;
            let _ = child.enforce_runtime_limits()?;
            ensure!(
                child.0.wait()?.success(),
                "verifier subprocess resource test failed"
            );
            Ok(())
        })();
        fs::remove_dir_all(dir)?;
        result
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resident_monitor_reads_actual_process_memory_and_threads() -> Result<()> {
        let info = task_info(std::process::id())?;
        assert!(info.pti_resident_size > 0);
        assert!(info.pti_threadnum > 0);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn child_waiting_for_stdin(exit_code: &str) -> Result<Process> {
        use std::process::Stdio;

        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "read ignored; exit \"$1\"",
                "verifier-exit-test",
                exit_code,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        restrict(&mut command)?;
        Process::spawn(&mut command)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn monitor_exit_race_preserves_child_status() -> Result<()> {
        use std::time::{Duration, Instant};

        for code in ["0", "7"] {
            let mut child = child_waiting_for_stdin(code)?;
            assert!(child.0.try_wait()?.is_none());
            drop(child.0.stdin.take().unwrap());
            // Observe Darwin's actual exit transition before entering the
            // grace period. Injecting ESRCH into a still-live shell made its
            // startup and CI scheduling part of the 100ms teardown deadline.
            // Do not reap here: the monitor-error path must retain the status.
            let deadline = Instant::now() + Duration::from_secs(10);
            let error = loop {
                match task_info(child.0.id()) {
                    Err(error) => break error,
                    Ok(_) => {
                        ensure!(Instant::now() < deadline, "test child did not exit");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            };
            assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
            let status =
                exit_after_monitor_error(&mut child.0, error)?.expect("exited child status");
            assert_eq!(status.code(), Some(code.parse()?));
            assert_eq!(child.0.try_wait()?, Some(status));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn monitor_error_for_live_child_fails_closed() -> Result<()> {
        let mut child = child_waiting_for_stdin("0")?;
        for errno in [libc::ESRCH, libc::EPERM] {
            let error = exit_after_monitor_error(&mut child.0, io::Error::from_raw_os_error(errno))
                .expect_err("live child must not bypass resource monitoring");
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(errno)
            );
            assert!(child.0.try_wait()?.is_none());
        }
        Ok(())
    }
}
