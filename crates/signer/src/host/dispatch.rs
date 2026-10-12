//! Both transports share admission counters and the same bounded service queues.
use super::{
    MailWork, NETWORK_LIFETIME, REQUEST_LIFETIME, Reply, Work,
    admission::{self, Permit, UsageMap},
    config::HostedConfig,
    transport::{classify, decode, failure},
};
use anyhow::Result;
use std::{net::IpAddr, path::PathBuf, sync::mpsc, time::Instant};
use zark_protocol::wire::{Command, Request};

pub(super) fn execute(
    engine: &super::Engine,
    path: &std::path::Path,
    job: &Work,
) -> serde_json::Value {
    let check = || admission::guard(path, &job.request, job.digest.as_deref(), job.deadline);
    match check().and_then(|_| engine.handle_guarded(&job.request, check)) {
        Ok(response) => serde_json::json!({"ok":true,"result":{"version":10,"response":response}}),
        Err(error) => classify(&error),
    }
}

#[derive(Clone)]
pub(super) struct Dispatch {
    pub(super) path: PathBuf,
    pub(super) ordinary: mpsc::SyncSender<Work>,
    pub(super) continued: mpsc::SyncSender<Work>,
    pub(super) recovered: mpsc::SyncSender<Work>,
    pub(super) mail: mpsc::SyncSender<MailWork>,
    pub(super) usage: UsageMap,
    pub(super) continuation_usage: UsageMap,
    pub(super) recovery_usage: UsageMap,
    pub(super) mail_usage: UsageMap,
}
impl Dispatch {
    pub(super) fn signing_permits(
        &self,
        request: &Request,
        digest: Option<&str>,
        peer: IpAddr,
    ) -> Result<Vec<Permit>> {
        if admission::continuation(&request.command) {
            // Hosting credentials cannot strand an already admitted operation.
            // The Engine still authenticates its frozen session and proof.
            Ok(vec![admission::admit(
                if admission::recovery(&request.command) {
                    &self.recovery_usage
                } else {
                    &self.continuation_usage
                },
                format!("session:{}", hex::encode(request.context.session_auth)),
                2,
                60,
            )?])
        } else {
            admission::admit_start(
                &HostedConfig::load(&self.path)?,
                if matches!(request.command, Command::ExitPrepare { .. }) {
                    &self.continuation_usage
                } else {
                    &self.usage
                },
                request,
                digest,
                peer,
            )
        }
    }
    pub(super) fn mail_permits(&self, peer: IpAddr) -> Result<Vec<Permit>> {
        let limits = HostedConfig::load(&self.path)?
            .messaging
            .ok_or_else(|| anyhow::anyhow!("messaging disabled"))?;
        Ok(vec![
            admission::admit(
                &self.mail_usage,
                "mail:global".into(),
                limits.max_inflight,
                limits.requests_per_minute,
            )?,
            admission::admit(
                &self.mail_usage,
                format!("mail:peer:{}", peer.to_canonical()),
                limits.peer_max_inflight,
                limits.peer_requests_per_minute,
            )?,
        ])
    }
    pub(super) fn signing(
        &self,
        reply: Reply,
        request: Request,
        digest: Option<String>,
        permits: Vec<Permit>,
        accepted: Instant,
    ) {
        let job = Work {
            reply,
            request,
            digest,
            _permits: permits,
            deadline: accepted + REQUEST_LIFETIME,
            queued: Instant::now(),
        };
        if let Err(error) = admission::queue_for(
            &job.request.command,
            &self.ordinary,
            &self.continued,
            &self.recovered,
        )
        .try_send(job)
        {
            let job = match error {
                mpsc::TrySendError::Full(j) | mpsc::TrySendError::Disconnected(j) => j,
            };
            job.reply.reject(failure("overloaded", true));
        }
    }
    pub(super) fn messaging(
        &self,
        reply: Reply,
        request: zark_protocol::mail::Request,
        permits: Vec<Permit>,
        accepted: Instant,
    ) {
        let job = MailWork {
            reply,
            request,
            _permits: permits,
            deadline: accepted + NETWORK_LIFETIME,
        };
        if let Err(error) = self.mail.try_send(job) {
            let job = match error {
                mpsc::TrySendError::Full(j) | mpsc::TrySendError::Disconnected(j) => j,
            };
            job.reply.reject(failure("overloaded", true));
        }
    }
    pub(super) fn browser_signing(
        &self,
        bytes: &[u8],
        reply: Reply,
        accepted: Instant,
        peer: IpAddr,
    ) {
        match decode(bytes).and_then(|(request, digest)| {
            let permits = self.signing_permits(&request, digest.as_deref(), peer)?;
            Ok((request, digest, permits))
        }) {
            Ok((request, digest, permits)) => {
                self.signing(reply, request, digest, permits, accepted)
            }
            Err(error) => reply.reject(classify(&error)),
        }
    }
}
