//! Bounded admission and dedicated continuation/recovery lanes preserve already-admitted recovery.
use super::{
    Arc, BTreeMap, Command, Duration, HostedConfig, Instant, Mutex, Path, Request, Result, ensure,
    mpsc, unexpired,
};

pub(super) fn recovery(command: &Command) -> bool {
    matches!(
        command,
        Command::RetrieveIssued { .. }
            | Command::RetrieveExit { .. }
            | Command::RetrieveBootstrap { .. }
            | Command::BatchAbort { .. }
            | Command::CancelTransfer {}
            | Command::AcknowledgeTransfer { .. }
            // Cancellation releases the local owner guard only after a fresh
            // head check. Both reads still require an engine-known session.
            | Command::Head { .. }
            | Command::CompleteSender {}
    )
}
pub(super) fn continuation(command: &Command) -> bool {
    recovery(command)
        || matches!(
            command,
            Command::Handover { .. }
                | Command::ProposeRecipient { .. }
                | Command::Prepare { .. }
                | Command::Issue { .. }
                | Command::IssueDeposit { .. }
                | Command::BatchReady { .. }
                | Command::AcceptOrigin { .. }
                | Command::BootstrapPrepare { .. }
                | Command::BootstrapFreeze { .. }
                | Command::ExitIssue { .. }
        )
}

pub(super) fn queue_for<'a, T>(
    command: &Command,
    ordinary: &'a mpsc::SyncSender<T>,
    continuation_queue: &'a mpsc::SyncSender<T>,
    recovery_queue: &'a mpsc::SyncSender<T>,
) -> &'a mpsc::SyncSender<T> {
    if recovery(command) {
        recovery_queue
    } else if continuation(command) || matches!(command, Command::ExitPrepare { .. }) {
        continuation_queue
    } else {
        ordinary
    }
}

#[derive(Default)]
pub(super) struct Usage {
    inflight: usize,
    count: usize,
    window: Option<Instant>,
}
pub(super) type UsageMap = Arc<Mutex<BTreeMap<String, Usage>>>;
pub(super) struct Permit {
    key: String,
    usage: UsageMap,
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut all) = self.usage.lock()
            && let Some(u) = all.get_mut(&self.key)
        {
            u.inflight = u.inflight.saturating_sub(1);
        }
    }
}
pub(super) fn admit(usage: &UsageMap, key: String, inflight: usize, rate: usize) -> Result<Permit> {
    let mut all = usage
        .lock()
        .map_err(|_| anyhow::anyhow!("private admission unavailable"))?;
    all.retain(|_, u| {
        u.inflight > 0
            || u.window
                .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
    });
    ensure!(
        all.contains_key(&key) || all.len() < 1024,
        "private admission capacity"
    );
    let u = all.entry(key.clone()).or_default();
    if u.window
        .is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
    {
        u.window = Some(Instant::now());
        u.count = 0;
    }
    ensure!(
        u.inflight < inflight && u.count < rate,
        "private admission capacity"
    );
    u.inflight += 1;
    u.count += 1;
    Ok(Permit {
        key,
        usage: usage.clone(),
    })
}
pub(super) fn guard(
    path: &Path,
    request: &Request,
    digest: Option<&str>,
    deadline: Instant,
) -> Result<()> {
    unexpired(deadline)?;
    if !continuation(&request.command) {
        HostedConfig::load(path)?.authorize(digest, &hex::encode(request.context.coin))?;
    }
    unexpired(deadline)
}

pub(super) fn admit_start(
    config: &HostedConfig,
    usage: &UsageMap,
    request: &Request,
    digest: Option<&str>,
    peer: std::net::IpAddr,
) -> Result<Vec<Permit>> {
    let mut permits = Vec::new();
    if let Some(public) = &config.public_access {
        permits.push(admit(
            usage,
            "public:global".into(),
            public.max_inflight,
            public.requests_per_minute,
        )?);
        permits.push(admit(
            usage,
            format!("public:peer:{}", peer.to_canonical()),
            public.peer_max_inflight,
            public.peer_requests_per_minute,
        )?);
        permits.push(admit(
            usage,
            format!("session:{}", hex::encode(request.context.session_auth)),
            2,
            60,
        )?);
        if matches!(request.command, Command::BootstrapAllocate {}) {
            permits.push(admit(
                usage,
                "public:allocations".into(),
                public.max_inflight,
                public.allocations_per_minute,
            )?);
        }
    } else {
        let credential = config.credential(digest, &hex::encode(request.context.coin))?;
        permits.push(admit(
            usage,
            format!("credential:{}", credential.sha256),
            credential.max_inflight,
            credential.requests_per_minute,
        )?);
    }
    Ok(permits)
}
