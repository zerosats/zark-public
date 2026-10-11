//! Explicit Linux enforcement probes. Run as a dedicated non-root UID with
//! capabilities dropped; ordinary macOS/root tests are not this evidence.
use super::*;
use std::{
    fs::{self, File},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::MetadataExt, process::ExitStatusExt},
    },
    process::Stdio,
    time::{Duration, Instant},
};

fn require_unprivileged() -> Result<()> {
    ensure!(
        unsafe { libc::getuid() } != 0 && unsafe { libc::geteuid() } != 0,
        "Linux enforcement probes require a non-root service UID"
    );
    let status = fs::read_to_string("/proc/self/status")?;
    let capabilities = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .context("missing effective capability mask")?;
    ensure!(
        u64::from_str_radix(capabilities.trim(), 16)? == 0,
        "Linux enforcement probes require all effective capabilities dropped"
    );
    Ok(())
}

fn probe_command(name: &str) -> Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command.args([
        "--exact",
        &format!("verifier_process::linux_tests::{name}"),
        "--ignored",
        "--nocapture",
    ]);
    restrict(&mut command)?;
    command.env("SC_LINUX_ENFORCEMENT_PROBE", "1");
    Ok(command)
}

fn wait_bounded(child: &mut Process) -> Result<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok(status);
        }
        ensure!(
            Instant::now() < deadline,
            "Linux verifier probe did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "requires an unprivileged Linux service UID without capabilities"]
fn linux_unprivileged_resource_enforcement() -> Result<()> {
    require_unprivileged()?;
    if std::env::var("SC_LINUX_ENFORCEMENT_PROBE").as_deref() != Ok("1") {
        let mut command = probe_command("linux_unprivileged_resource_enforcement")?;
        // PDEATHSIG belongs to the calling kernel task. Linux copy_process()
        // clears it for new tasks, including libtest's worker thread. Query
        // the actual exec thread immediately after restrict's pre-exec hook.
        // The separate spawning-thread-exit test checks the real kill effect.
        unsafe {
            command.pre_exec(|| {
                let mut death_signal: libc::c_int = 0;
                if libc::prctl(libc::PR_GET_PDEATHSIG, std::ptr::addr_of_mut!(death_signal)) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if death_signal != libc::SIGKILL {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }
                Ok(())
            });
        }
        let mut child = Process::spawn(&mut command)?;
        ensure!(
            wait_bounded(&mut child)?.success(),
            "Linux resource probe failed"
        );
        return Ok(());
    }

    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
        1
    );
    assert_eq!(unsafe { libc::getpgrp() }, unsafe { libc::getpid() });
    for (resource, ceiling) in [
        (libc::RLIMIT_AS, ADDRESS_SPACE_BYTES),
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

    // Reserve address space without touching physical pages. The production AS
    // limit must reject this even if the container has ample virtual memory.
    let length = usize::try_from(ADDRESS_SPACE_BYTES + 4096)?;
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let mapping_error = io::Error::last_os_error();
    if mapping != libc::MAP_FAILED {
        unsafe {
            libc::munmap(mapping, length);
        }
        anyhow::bail!("verifier address-space ceiling was not enforced");
    }
    assert_eq!(mapping_error.raw_os_error(), Some(libc::ENOMEM));

    let mut descriptors = Vec::new();
    let fd_error = loop {
        match File::open("/dev/null") {
            Ok(file) => {
                descriptors.push(file);
                ensure!(
                    descriptors.len() <= FILE_DESCRIPTORS as usize,
                    "verifier descriptor ceiling was not enforced"
                );
            }
            Err(error) => break error,
        }
    };
    assert_eq!(fd_error.raw_os_error(), Some(libc::EMFILE));
    drop(descriptors);

    // Ignore SIGXFSZ only in this isolated probe so the failing syscall can be
    // inspected. A memfd avoids touching the service filesystem or secrets.
    let fd = unsafe { libc::memfd_create(c"verifier-fsize-probe".as_ptr(), libc::MFD_CLOEXEC) };
    ensure!(
        fd >= 0,
        "create file-size probe: {}",
        io::Error::last_os_error()
    );
    let file = unsafe { File::from_raw_fd(fd) };
    let previous = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
    ensure!(
        previous != libc::SIG_ERR,
        "configure file-size probe signal"
    );
    let truncated = unsafe { libc::ftruncate(file.as_raw_fd(), (FILE_BYTES + 1) as libc::off_t) };
    let file_error = io::Error::last_os_error();
    unsafe {
        libc::signal(libc::SIGXFSZ, previous);
    }
    assert_eq!(truncated, -1);
    assert_eq!(file_error.raw_os_error(), Some(libc::EFBIG));

    // Reduce NPROC only in this probe. Checking a single refused fork proves
    // actual per-UID enforcement without creating hundreds of processes.
    unsafe {
        lower_limit(libc::RLIMIT_NPROC, 0)?;
    }
    let pid = unsafe { libc::fork() };
    let fork_error = io::Error::last_os_error();
    if pid == 0 {
        unsafe {
            libc::_exit(99);
        }
    }
    if pid > 0 {
        unsafe {
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        anyhow::bail!("unprivileged verifier process ceiling was not enforced");
    }
    assert_eq!(fork_error.raw_os_error(), Some(libc::EAGAIN));
    Ok(())
}

#[test]
#[ignore = "requires an unprivileged Linux service UID without capabilities"]
fn linux_cpu_limit_terminates_child() -> Result<()> {
    require_unprivileged()?;
    if std::env::var("SC_LINUX_ENFORCEMENT_PROBE").as_deref() == Ok("1") {
        loop {
            std::hint::spin_loop();
        }
    }
    let mut command = probe_command("linux_cpu_limit_terminates_child")?;
    // Exercise the same setter with a one-second test ceiling, avoiding a
    // thirty-second busy loop in every explicit enforcement run.
    unsafe {
        command.pre_exec(|| lower_limit(libc::RLIMIT_CPU, 1));
    }
    let mut child = Process::spawn(&mut command)?;
    assert_eq!(wait_bounded(&mut child)?.signal(), Some(libc::SIGKILL));
    Ok(())
}

#[test]
#[ignore = "requires an unprivileged Linux service UID without capabilities"]
fn linux_spawning_thread_exit_kills_verifier() -> Result<()> {
    require_unprivileged()?;
    // Linux PDEATHSIG follows the creating thread, not merely the parent PID.
    // Transfer the live guard to this thread so its death can be reaped here.
    let mut child = std::thread::spawn(|| -> Result<Process> {
        let mut command = Command::new("/bin/sleep");
        command.arg("60");
        restrict(&mut command)?;
        Process::spawn(&mut command)
    })
    .join()
    .expect("verifier spawning thread panicked")?;
    assert_eq!(wait_bounded(&mut child)?.signal(), Some(libc::SIGKILL));
    Ok(())
}

#[test]
#[ignore = "requires an unprivileged Linux service UID without capabilities"]
fn linux_descriptor_scan_fallback_is_fail_closed() -> Result<()> {
    require_unprivileged()?;
    if std::env::var("SC_LINUX_ENFORCEMENT_PROBE").as_deref() == Ok("1") {
        let fd: libc::c_int = std::env::var("SC_FALLBACK_PRIVATE_FD")?.parse()?;
        let inode: libc::ino_t = std::env::var("SC_FALLBACK_PRIVATE_INODE")?.parse()?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == 0 {
            assert_ne!(unsafe { stat.assume_init() }.st_ino, inode);
        }
        return Ok(());
    }
    unsafe fn absent_syscall() -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }
    unsafe fn absent_flag() -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EINVAL))
    }
    unsafe fn seccomp_denial() -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }
    unsafe fn unexpected_error() -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EIO))
    }

    let error = unsafe { linux_descriptors_cloexec(0, unexpected_error) }.unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    let path = std::env::temp_dir().join(format!(
        "verifier-fallback-{}",
        hex::encode(crate::random32())
    ));
    fs::write(&path, b"synthetic descriptor canary")?;
    let result = (|| {
        let private = File::open(&path)?;
        let fd = private.as_raw_fd();
        let errors: [unsafe fn() -> io::Result<()>; 3] =
            [absent_syscall, absent_flag, seccomp_denial];
        for close_range in errors {
            let mut command = probe_command("linux_descriptor_scan_fallback_is_fail_closed")?;
            command.env("SC_FALLBACK_PRIVATE_FD", fd.to_string()).env(
                "SC_FALLBACK_PRIVATE_INODE",
                private.metadata()?.ino().to_string(),
            );
            // Undo the production first pass for this one canary, then force
            // the old-kernel/seccomp fallback in the isolated child only.
            unsafe {
                command.pre_exec(move || {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    linux_descriptors_cloexec(fd + 1, close_range)
                });
            }
            let mut child = Process::spawn(&mut command)?;
            ensure!(
                wait_bounded(&mut child)?.success(),
                "descriptor scan fallback leaked a file"
            );
        }
        // The exec-error pipe must survive the pre-exec close-on-exec setup.
        let mut command = Command::new(path.join("not-an-executable"));
        restrict(&mut command)?;
        let error = command
            .spawn()
            .expect_err("invalid executable unexpectedly started");
        assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR));
        Ok(())
    })();
    fs::remove_file(path)?;
    result
}

#[test]
#[ignore = "requires an unprivileged Linux service UID without capabilities"]
fn linux_drop_kills_group_and_reaps_direct_child() -> Result<()> {
    require_unprivileged()?;
    let directory =
        std::env::temp_dir().join(format!("verifier-group-{}", hex::encode(crate::random32())));
    fs::create_dir(&directory)?;
    let pid_file = directory.join("descendant.pid");
    let result = (|| {
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "sleep 60 & printf '%s' \"$!\" > \"$1\"; read ignored",
                "verifier-group-probe",
            ])
            .arg(&pid_file)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        restrict(&mut command)?;
        let child = Process::spawn(&mut command)?;
        let pid = child.0.id() as libc::pid_t;
        let deadline = Instant::now() + Duration::from_secs(5);
        let descendant: libc::pid_t = loop {
            if let Ok(text) = fs::read_to_string(&pid_file)
                && let Ok(pid) = text.parse()
            {
                break pid;
            }
            ensure!(Instant::now() < deadline, "descendant did not start");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(unsafe { libc::getpgid(descendant) }, pid);
        drop(child);
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match fs::read_to_string(format!("/proc/{descendant}/status")) {
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        || error.raw_os_error() == Some(libc::ESRCH) =>
                {
                    break;
                }
                Ok(status)
                    if status.lines().any(|line| {
                        line.starts_with("State:\tZ") || line.starts_with("State:\tX")
                    }) =>
                {
                    break;
                }
                Err(error) => return Err(error.into()),
                _ => (),
            }
            ensure!(
                Instant::now() < deadline,
                "verifier descendant still executing after Drop"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // Only the direct child is ours to reap. PID 1/subreaper reaps the
        // terminated descendant; run container probes with an init process.
        Ok(())
    })();
    fs::remove_dir_all(directory)?;
    result
}
