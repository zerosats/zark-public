//! Unix process adapters shared by the owner and signer executables.
use anyhow::Result;
use std::{
    cell::Cell,
    fs::{File, OpenOptions},
    io,
    marker::PhantomData,
    os::{
        fd::{AsRawFd, BorrowedFd, RawFd},
        unix::{fs::OpenOptionsExt, process::CommandExt},
    },
    path::Path,
    process::Command,
    rc::Rc,
};

thread_local! { static OPERATION_LOCK: Cell<Option<RawFd>> = const { Cell::new(None) }; }

pub(crate) fn operation_lock_fd() -> Option<RawFd> {
    OPERATION_LOCK.with(Cell::get)
}

/// An advisory process lock. The guard stays
/// on its acquiring thread; only explicitly configured child tools inherit it.
pub struct ProcessLock {
    file: File,
    previous: Option<RawFd>,
    _thread: PhantomData<Rc<()>>,
}
impl ProcessLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        // SAFETY: file owns a valid descriptor throughout this call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            let message = format!(
                "Another command or service is running: {} ({error})",
                path.display()
            );
            // Retain the OS cause so bounded checkpoint waits can distinguish
            // contention from permissions, filesystem errors and other failures.
            return Err(anyhow::Error::new(error).context(message));
        }
        let previous = OPERATION_LOCK.with(|slot| slot.replace(Some(file.as_raw_fd())));
        Ok(Self {
            file,
            previous,
            _thread: PhantomData,
        })
    }
}
impl Drop for ProcessLock {
    fn drop(&mut self) {
        OPERATION_LOCK.with(|slot| slot.set(self.previous));
        // Close, never LOCK_UN: a surviving child must keep the shared lock.
        let _ = self.file.as_raw_fd();
    }
}

/// Runs `helper` on a scoped thread while `main` runs on this one. Child tools
/// the helper starts with [`inherit_operation_lock`] keep this thread's
/// innermost operation locked exactly as if started here: the helper holds a
/// close-on-exec duplicate of that descriptor, which is the same flock, so a
/// guard released here first cannot unlock a surviving child.
///
/// macOS sets close-on-exec on new pipes and sockets non-atomically, so ones
/// this thread creates meanwhile can briefly reach a helper's child. Only
/// short-lived read-only tools may be started from the helper.
pub fn join_with_helper<A, B: Send>(
    main: impl FnOnce() -> A,
    helper: impl FnOnce() -> B + Send,
) -> Result<(A, B)> {
    let inherited = match OPERATION_LOCK.with(Cell::get) {
        // SAFETY: the slot names a descriptor only while its guard is alive on
        // this thread, and the duplicate is taken before this call returns.
        Some(fd) => Some(unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?),
        None => None,
    };
    std::thread::scope(|scope| {
        let helper = std::thread::Builder::new().spawn_scoped(scope, move || {
            OPERATION_LOCK.with(|slot| slot.set(inherited.as_ref().map(AsRawFd::as_raw_fd)));
            let result = helper();
            OPERATION_LOCK.with(|slot| slot.set(None));
            drop(inherited);
            result
        })?;
        let main = main();
        match helper.join() {
            Ok(helper) => Ok((main, helper)),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

/// A prover/verifier can outlive a killed wallet. Keep its operation locked
/// until that child exits, without leaking the lock into background services.
pub fn inherit_operation_lock(command: &mut Command) {
    if let Some(fd) = OPERATION_LOCK.with(Cell::get) {
        // SAFETY: pre_exec only invokes async-signal-safe fcntl on a live fd.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use anyhow::ensure;
    use std::{fs, os::unix::fs::DirBuilderExt, process::Stdio};

    #[cfg(target_os = "linux")]
    #[test]
    fn temporary_draft_must_be_retained_across_a_forking_join() -> Result<()> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../work")
            .join(format!("fork-draft-{}", hex::encode(crate::random32())));
        fs::create_dir_all(&directory)?;
        let outer_path = directory.join("operation.lock");
        let draft_path = directory.join("recovery-draft.lock");
        let result = (|| {
            let _outer = ProcessLock::acquire(&outer_path)?;
            // Force the old lifetime: acquire/drop a temporary draft while a
            // helper's fork is paused before exec. CLOEXEC cannot prevent this.
            let (start, started) = std::sync::mpsc::channel();
            let (mut parent, child_pipe) = UnixStream::pair()?;
            parent.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            let fd = child_pipe.as_raw_fd();
            let (main, child) = join_with_helper(
                || -> Result<()> {
                    let draft = ProcessLock::acquire(&draft_path)?;
                    start.send(())?;
                    let mut byte = [0];
                    parent.read_exact(&mut byte)?;
                    drop(draft);
                    let blocked = ProcessLock::acquire(&draft_path).is_err();
                    parent.write_all(&[1])?;
                    ensure!(blocked, "pre-exec child did not retain temporary draft");
                    Ok(())
                },
                move || -> Result<()> {
                    started.recv()?;
                    let mut command = Command::new("/bin/true");
                    inherit_operation_lock(&mut command);
                    // Only async-signal-safe syscalls in the forked child.
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
                    ensure!(command.status()?.success(), "fork probe child failed");
                    Ok(())
                },
            )?;
            main?;
            child?;
            drop(child_pipe);
            // Fixed lifetime: one draft before the concurrent phase, used
            // without reopening, released only after the helper is reaped.
            let draft = ProcessLock::acquire(&draft_path)?;
            let (main, child) = join_with_helper(
                || -> Result<()> {
                    ensure!(draft.file.metadata()?.is_file(), "draft guard lost");
                    ensure!(ProcessLock::acquire(&draft_path).is_err(), "draft unlocked");
                    Ok(())
                },
                || -> Result<()> {
                    let mut command = Command::new("/bin/true");
                    inherit_operation_lock(&mut command);
                    ensure!(command.status()?.success(), "retained draft child failed");
                    Ok(())
                },
            )?;
            main?;
            child?;
            drop(draft);
            let _reopened = ProcessLock::acquire(&draft_path)?;
            ensure!(
                ProcessLock::acquire(&outer_path).is_err(),
                "outer lock lost"
            );
            Ok(())
        })();
        fs::remove_dir_all(directory)?;
        result
    }

    #[test]
    fn helper_children_keep_the_callers_operation_locked() -> Result<()> {
        let directory = std::env::temp_dir().canonicalize()?.join(format!(
            "zark-local-test-{}",
            hex::encode(crate::random32())
        ));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let path = directory.join("operation.lock");
        let result = (|| {
            let guard = ProcessLock::acquire(&path)?;
            let ((), child) = join_with_helper(
                || (),
                || {
                    let mut command = Command::new("/bin/sleep");
                    command.arg("0.5").stdin(Stdio::null());
                    inherit_operation_lock(&mut command);
                    command.spawn()
                },
            )?;
            let mut child = child?;
            assert_eq!(operation_lock_fd(), Some(guard.file.as_raw_fd()));
            drop(guard);
            assert!(
                ProcessLock::acquire(&path).is_err(),
                "a helper's surviving child must keep the operation locked"
            );
            child.wait()?;
            drop(ProcessLock::acquire(&path)?);
            let ((), unlocked) = join_with_helper(|| (), operation_lock_fd)?;
            assert_eq!(unlocked, None);
            Ok(())
        })();
        fs::remove_dir_all(&directory)?;
        result
    }
}
