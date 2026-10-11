use super::*;
use std::{
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    path::PathBuf,
    process::Command,
    sync::mpsc,
    thread,
};

struct Paths(PathBuf);
impl Paths {
    fn new() -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../work")
            .join(format!(
                "checkpoint-wait-{}",
                hex::encode(zark_protocol::random32())
            ));
        fs::create_dir_all(root.join("db"))?;
        fs::create_dir(root.join("checkpoint"))?;
        Ok(Self(root))
    }
    fn db(&self) -> PathBuf {
        self.0.join("db/signer.sqlite")
    }
    fn floor(&self) -> PathBuf {
        self.0.join("checkpoint/floor.json")
    }
    fn lock(&self) -> PathBuf {
        self.0.join("checkpoint/floor.lock")
    }
}
impl Drop for Paths {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn checkpoint_waits_for_pre_exec_child_without_unlocking_it() -> Result<()> {
    let paths = Paths::new()?;
    let lock = ProcessLock::acquire(&paths.lock())?;
    let (mut parent, child_pipe) = UnixStream::pair()?;
    parent.set_read_timeout(Some(Duration::from_secs(5)))?;
    let fd = child_pipe.as_raw_fd();
    let child = thread::spawn(move || -> Result<()> {
        let mut command = Command::new("/usr/bin/true");
        // Force the actual fork-before-exec window while another thread owns
        // the checkpoint. CLOEXEC cannot release its inherited flock yet.
        // SAFETY: only async-signal-safe syscalls on an owned descriptor.
        unsafe {
            command.pre_exec(move || {
                libc::alarm(5);
                let mut byte = 1u8;
                if libc::write(fd, (&byte as *const u8).cast(), 1) != 1
                    || libc::read(fd, (&mut byte as *mut u8).cast(), 1) != 1
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let status = command.status()?;
        drop(child_pipe);
        ensure!(status.success(), "fork probe failed");
        Ok(())
    });
    parent.read_exact(&mut [0])?;
    drop(lock);

    let before = Instant::now();
    let blocked = CheckpointLock::acquire_until(
        &paths.db(),
        &paths.floor(),
        before + Duration::from_millis(40),
        &|| Ok(()),
    );
    assert_eq!(
        blocked.err().unwrap().to_string(),
        "checkpoint busy: lock deadline"
    );
    assert!(before.elapsed() < Duration::from_secs(2));
    assert!(
        ProcessLock::acquire(&paths.lock()).is_err(),
        "child's lock was forcibly released"
    );

    // A request deadline shorter than the checkpoint budget cancels the wait.
    let deadline = Instant::now() + Duration::from_millis(20);
    let cancelled = CheckpointLock::acquire(&paths.db(), &paths.floor(), &|| {
        ensure!(
            Instant::now() < deadline,
            "private request deadline exceeded"
        );
        Ok(())
    });
    assert_eq!(
        cancelled.err().unwrap().to_string(),
        "private request deadline exceeded"
    );

    let (done, result) = mpsc::channel();
    let db = paths.db();
    let floor = paths.floor();
    let waiter = thread::spawn(move || {
        let acquired = CheckpointLock::acquire(&db, &floor, &|| Ok(())).map(drop);
        done.send(acquired).unwrap();
    });
    assert!(matches!(
        result.recv_timeout(Duration::from_millis(40)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    parent.write_all(&[1])?;
    child.join().unwrap()?;
    result.recv_timeout(Duration::from_secs(2))??;
    waiter.join().unwrap();
    drop(ProcessLock::acquire(&paths.lock())?);
    Ok(())
}

#[test]
fn queued_request_deadline_cancels_its_ticket() -> Result<()> {
    let paths = Paths::new()?;
    let held = CheckpointLock::acquire(&paths.db(), &paths.floor(), &|| Ok(()))?;
    let db = paths.db();
    let floor = paths.floor();
    let waiter = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(30);
        CheckpointLock::acquire(&db, &floor, &|| {
            ensure!(
                Instant::now() < deadline,
                "private request deadline exceeded"
            );
            Ok(())
        })
        .err()
        .unwrap()
        .to_string()
    });
    assert_eq!(waiter.join().unwrap(), "private request deadline exceeded");
    drop(held);
    // The cancelled ticket cannot strand the next request behind it.
    drop(CheckpointLock::acquire(
        &paths.db(),
        &paths.floor(),
        &|| Ok(()),
    )?);
    Ok(())
}

#[test]
fn queue_and_file_lock_share_one_budget() -> Result<()> {
    let paths = Paths::new()?;
    let lock = ProcessLock::acquire(&paths.lock())?;
    let deadline = Instant::now() + Duration::from_millis(150);
    let permit =
        crate::admission::Permit::acquire(&fs::canonicalize(paths.lock())?, deadline, &|| Ok(()))?;
    let db = paths.db();
    let floor = paths.floor();
    let before = Instant::now();
    let waiter = thread::spawn(move || {
        CheckpointLock::acquire_until(&db, &floor, deadline, &|| Ok(()))
            .err()
            .unwrap()
            .to_string()
    });
    thread::sleep(Duration::from_millis(60));
    drop(permit);
    let error = waiter.join().unwrap();
    assert!(matches!(
        error.as_str(),
        "checkpoint busy: lock deadline" | "checkpoint busy: admission deadline"
    ));
    assert!(before.elapsed() < Duration::from_secs(2));
    drop(lock);
    Ok(())
}

#[test]
fn filesystem_errors_are_not_retried_as_contention() -> Result<()> {
    let paths = Paths::new()?;
    fs::create_dir(paths.lock())?;
    let error = CheckpointLock::acquire(&paths.db(), &paths.floor(), &|| {
        anyhow::bail!("unexpected contention retry")
    })
    .err()
    .unwrap();
    assert!(error.downcast_ref::<io::Error>().is_some());
    assert_ne!(error.to_string(), "unexpected contention retry");
    Ok(())
}
