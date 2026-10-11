//! Exercise post-startup high descriptors in isolated subprocesses, not by
//! changing resource limits in the multi-threaded test runner.
use super::*;
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const TEST: &str =
    "prover::process::tests::lower_limit_still_closes_high_descriptors_and_retains_operation_lock";
const MARKER: &str = "ZARK_TEST_PROVER_DESCRIPTORS";

#[test]
fn lower_limit_still_closes_high_descriptors_and_retains_operation_lock() -> Result<()> {
    match std::env::var(MARKER).as_deref() {
        Ok("verify") => {
            let private: i32 = std::env::var("ZARK_TEST_PRIVATE_FD")?.parse()?;
            let lock: i32 = std::env::var("ZARK_TEST_LOCK_FD")?.parse()?;
            ensure!(
                unsafe { libc::fcntl(private, libc::F_GETFD) } == -1,
                "high descriptor leaked"
            );
            ensure!(
                unsafe { libc::fcntl(lock, libc::F_GETFD) } >= 0,
                "operation lock lost"
            );
            ensure!(
                std::env::var_os("ZARK_TEST_CREDENTIAL").is_none(),
                "credential leaked"
            );
            return Ok(());
        }
        Ok("prepare") => {}
        _ => {
            ensure!(
                Command::new(std::env::current_exe()?)
                    .args(["--exact", TEST])
                    .env(MARKER, "prepare")
                    .status()?
                    .success(),
                "descriptor fixture failed"
            );
            return Ok(());
        }
    }
    let mut original = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) } == 0,
        "get limit"
    );
    let high_limit = libc::rlimit {
        rlim_cur: 16384,
        rlim_max: original.rlim_max,
    };
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &high_limit) } == 0,
        "test limit"
    );
    let file = File::open("/dev/null")?;
    // F_DUPFD intentionally omits CLOEXEC, modelling a library-created handle.
    let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 9000) };
    ensure!(high >= 9000, "duplicate test descriptor");
    let high = unsafe { OwnedFd::from_raw_fd(high) };
    crate::cli::macos::bound_descriptor_limit();
    ensure!(
        unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } == 8192,
        "wallet startup limit"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("work")
        .join(format!("descriptor-test-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let result = (|| {
        let lock = root.join("operation.lock");
        let _guard = zark_protocol::local::ProcessLock::acquire(&lock)?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", TEST])
            .env("ZARK_TEST_CREDENTIAL", "synthetic");
        prepare(&mut command, &root, 4, false)?;
        // Locate the guard without exposing its handle in the public API.
        use std::os::unix::fs::MetadataExt;
        let inode = std::fs::metadata(&lock)?.ino();
        let lock_fd = std::fs::read_dir("/dev/fd")?
            .filter_map(|entry| entry.ok())
            .find(|entry| std::fs::metadata(entry.path()).is_ok_and(|m| m.ino() == inode))
            .context("find test lock")?
            .file_name();
        command
            .env(MARKER, "verify")
            .env("ZARK_TEST_PRIVATE_FD", high.as_raw_fd().to_string())
            .env("ZARK_TEST_LOCK_FD", lock_fd)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = Running(command.spawn()?);
        ensure!(
            child.0.wait()?.success(),
            "restricted child descriptor check"
        );
        Ok(())
    })();
    std::fs::remove_dir_all(root)?;
    result
}
