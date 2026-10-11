//! Fair, bounded admission and process-lock waits for checkpointing and verification.
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};
use zark_protocol::local::ProcessLock;

pub(crate) fn acquire_process_lock(
    path: &Path,
    deadline: Instant,
    guard: &dyn Fn() -> Result<()>,
    busy: &'static str,
) -> Result<ProcessLock> {
    let mut waited = false;
    loop {
        if waited {
            guard()?;
        }
        ensure!(Instant::now() < deadline, busy);
        match ProcessLock::acquire(path) {
            Ok(lock) => return Ok(lock),
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::WouldBlock) =>
            {
                // A child forked by another thread can retain this flock until
                // exec. Wait for its real close; never force-unlock it. Reuse
                // the FIFO deadline so queueing cannot extend the total budget.
                guard()?;
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(10)),
                );
                waited = true;
            }
            Err(error) => return Err(error),
        }
    }
}

#[derive(Default)]
struct Queue {
    next: u64,
    serving: u64,
    cancelled: BTreeSet<u64>,
}
#[derive(Default)]
struct Admission {
    queue: Mutex<Queue>,
    changed: Condvar,
}
pub(crate) struct Permit {
    admission: Arc<Admission>,
}
static QUEUES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Admission>>>> = OnceLock::new();

impl Queue {
    fn advance(&mut self) {
        self.serving += 1;
        while self.cancelled.remove(&self.serving) {
            self.serving += 1;
        }
    }

    fn cancel(&mut self, ticket: u64) {
        if ticket == self.serving {
            self.advance();
        } else {
            self.cancelled.insert(ticket);
        }
    }
}
impl Permit {
    pub fn acquire(path: &Path, deadline: Instant, guard: &dyn Fn() -> Result<()>) -> Result<Self> {
        let admission = {
            let mut registry = QUEUES
                .get_or_init(Default::default)
                .lock()
                .map_err(|_| anyhow::anyhow!("checkpoint admission unavailable"))?;
            registry.retain(|_, value| value.strong_count() > 0);
            if let Some(existing) = registry.get(path).and_then(Weak::upgrade) {
                existing
            } else {
                let new = Arc::new(Admission::default());
                registry.insert(path.to_path_buf(), Arc::downgrade(&new));
                new
            }
        };
        let mut queue = admission
            .queue
            .lock()
            .map_err(|_| anyhow::anyhow!("checkpoint admission unavailable"))?;
        ensure!(
            queue.next - queue.serving < 128,
            "checkpoint busy: admission capacity"
        );
        ensure!(
            queue.next < u64::MAX - 128,
            "checkpoint admission sequence exhausted"
        );
        let ticket = queue.next;
        queue.next += 1;
        let mut waited = false;
        loop {
            // Recheck after waking, even if this ticket is now at the front.
            // Cancellation must advance that ticket or every later waiter stalls.
            if waited || queue.serving != ticket {
                let check = guard().and_then(|()| {
                    ensure!(
                        Instant::now() < deadline,
                        "checkpoint busy: admission deadline"
                    );
                    Ok(())
                });
                if let Err(error) = check {
                    queue.cancel(ticket);
                    admission.changed.notify_all();
                    return Err(error);
                }
            }
            if queue.serving == ticket {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (next, _) = admission
                .changed
                .wait_timeout(queue, remaining.min(Duration::from_millis(10)))
                .map_err(|_| anyhow::anyhow!("checkpoint admission unavailable"))?;
            queue = next;
            waited = true;
        }
        drop(queue);
        Ok(Self { admission })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut queue) = self.admission.queue.lock() {
            queue.advance();
            self.admission.changed.notify_all();
        }
    }
}
