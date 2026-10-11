use super::*;
use std::{
    process::{Child, Stdio},
    time::{Duration, Instant},
};

#[test]
fn frozen_jobs_name_a_runtime_only_difference() {
    let job = |input: &str, runtime: Option<&str>| Job {
        version: 1,
        role: "sender_from_origin".into(),
        suite: "suite".into(),
        input_sha256: input.into(),
        statement: "statement".into(),
        nargo_sha256: "nargo".into(),
        bb_sha256: "bb".into(),
        runtime_identity: runtime.map(Into::into),
    };
    let expected = job("input", Some("rust helper"));
    for saved in [job("input", Some("python helper")), job("input", None)] {
        assert!(
            saved
                .mismatch(&expected)
                .contains("different prover runtime")
        );
    }
    for saved in [
        job("changed", Some("rust helper")),
        job("changed", Some("python helper")),
    ] {
        assert_eq!(
            saved.mismatch(&expected),
            "proof job is frozen for different inputs"
        );
    }
}

#[test]
fn worker_profile_clears_legacy_flags_credentials_and_qos() -> Result<()> {
    let directory = std::env::temp_dir().join(format!("zark-workers-{}", hex::encode(random32())));
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let _cleanup = Cleanup {
        directory: directory.clone(),
        parent: None,
        prover: None,
    };
    for (threads, fast) in [(8, false), (16, true)] {
        let mut command = Command::new("/bin/sh");
        command
            .env("BB_MSM_LEGACY", "0")
            .env("BB_BENCH", "0")
            .env("BB_MACOS_USER_INITIATED", "1")
            .env("PRIVATE_SENTINEL", "private");
        process::prepare(&mut command, &directory, threads, fast)?;
        let environment: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        for name in [
            "HARDWARE_CONCURRENCY",
            "BB_HARDWARE_CONCURRENCY",
            "RAYON_NUM_THREADS",
            "OMP_NUM_THREADS",
        ] {
            assert_eq!(
                environment[std::ffi::OsStr::new(name)].unwrap(),
                threads.to_string().as_str()
            );
        }
        for name in [
            "BB_MSM_LEGACY",
            "BB_BENCH",
            "BB_MACOS_USER_INITIATED",
            "PRIVATE_SENTINEL",
        ] {
            assert!(!environment.contains_key(std::ffi::OsStr::new(name)));
        }
        assert_eq!(
            environment
                .get(std::ffi::OsStr::new("BB_MSM_NEW"))
                .copied()
                .flatten(),
            fast.then_some(std::ffi::OsStr::new("1"))
        );
    }
    Ok(())
}

// Runs only in a child test process. The shell writes its PID before exec so the
// parent regression can kill the wallet while the simulated prover survives.
#[test]
#[ignore = "subprocess helper for killed-wallet lock regression"]
fn orphan_lock_helper() -> Result<()> {
    let directory =
        PathBuf::from(std::env::var_os("ZARK_LOCK_TEST_DIRECTORY").context("test directory")?);
    let _outer = ProcessLock::acquire(&directory.join("outer.lock"))?;
    let _job = ProcessLock::acquire(&directory.join("job.lock"))?;
    let mut command = Command::new("/bin/sh");
    command
        .current_dir(&directory)
        .args(["-c", "echo $$ > child.pid; exec /bin/sleep 15"]);
    run(
        &mut command,
        &directory,
        "simulated prover failed",
        4,
        false,
    )
}

struct Cleanup {
    directory: PathBuf,
    parent: Option<Child>,
    prover: Option<i32>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(parent) = &mut self.parent {
            let _ = parent.kill();
            let _ = parent.wait();
        }
        if let Some(pid) = self.prover {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn surviving_prover_keeps_job_locked_after_wallet_is_killed() -> Result<()> {
    let directory =
        std::env::temp_dir().join(format!("zark-orphan-lock-{}", hex::encode(random32())));
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let parent = Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "prover::tests::orphan_lock_helper"])
        .env("ZARK_LOCK_TEST_DIRECTORY", &directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut cleanup = Cleanup {
        directory: directory.clone(),
        parent: Some(parent),
        prover: None,
    };
    let deadline = Instant::now() + Duration::from_secs(8);
    let pid = loop {
        if let Ok(text) = fs::read_to_string(directory.join("child.pid"))
            && let Ok(pid) = text.trim().parse::<i32>()
        {
            break pid;
        }
        ensure!(
            Instant::now() < deadline && cleanup.parent.as_mut().unwrap().try_wait()?.is_none(),
            "simulated prover did not start"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    ensure!(pid > 1, "invalid simulated prover pid");
    cleanup.prover = Some(pid);
    cleanup.parent.as_mut().unwrap().kill()?;
    cleanup.parent.as_mut().unwrap().wait()?;
    // The unrelated outer lock is not leaked, but the exact proof job remains
    // protected while its child still owns the witness output directory.
    let _outer = ProcessLock::acquire(&directory.join("outer.lock"))?;
    ensure!(
        ProcessLock::acquire(&directory.join("job.lock")).is_err(),
        "killed wallet released its live prover lock"
    );
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(lock) = ProcessLock::acquire(&directory.join("job.lock")) {
            drop(lock);
            break;
        }
        ensure!(Instant::now() < deadline, "terminated prover kept job lock");
        std::thread::sleep(Duration::from_millis(20));
    }
    cleanup.prover = None;
    Ok(())
}
