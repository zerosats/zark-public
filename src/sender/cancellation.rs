//! Cancel or abort a transfer before releasing the local owner guard.
use super::{SenderDraft, cached_cancellation};
use crate::freshness::SignerClient;
use anyhow::{Context, Result, ensure};
use k256::schnorr::SigningKey;
use serde::Deserialize;
use zark_protocol::handoff::Digest;
use zark_protocol::wire::{Command, Request};
use zeroize::Zeroize;

impl SenderDraft {
    pub(crate) fn cancel_transfer(&mut self, client: &dyn SignerClient) -> Result<()> {
        ensure!(
            self.record.batch.is_none(),
            "batch members require batch-abort"
        );
        ensure!(!self.record.retired, "sender already completed");
        let request = match &self.record.cancellation {
            Some(saved) => cached_cancellation(&self.record.context, saved)?,
            None => {
                let request = Request::sign(
                    self.record.context.clone(),
                    Command::CancelTransfer {},
                    &SigningKey::from_bytes(&self.record.session)?,
                )?;
                self.record.cancellation = Some(hex::encode(&*request.encode()?));
                self.persist()?;
                request
            }
        };
        let response = client.request(&request).context(
            "transfer cancellation did not complete; retry cancel after a lost response. If the reservation was never admitted, resume the same saved operation with valid credentials before cancelling it",
        )?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Cancellation {
            cancelled: bool,
            operation: Digest,
        }
        let response: Cancellation = serde_json::from_value(response)
            .map_err(|_| anyhow::anyhow!("invalid cancellation receipt"))?;
        ensure!(
            response.cancelled && response.operation == self.record.context.operation,
            "signer did not cancel this transfer"
        );
        // This receipt is only about this operation. The caller separately
        // verifies a fresh Accepted head before releasing the local owner guard.
        self.finish_aborted()
    }
    pub(crate) fn abort_batch(&mut self, client: &dyn SignerClient) -> Result<()> {
        let manifest = self.record.batch.as_ref().context("sender has no batch")?;
        let request = Request::sign(
            self.record.context.clone(),
            Command::BatchAbort {
                manifest: manifest.clone(),
            },
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        let response = client.request(&request)?;
        ensure!(response["aborted"] == true, "signer did not abort batch");
        self.finish_aborted()
    }
    /// Caller must first verify a fresh signed Accepted head for the unchanged owner.
    pub(crate) fn cancel_after_accepted_head(&mut self) -> Result<()> {
        ensure!(
            self.record.batch.is_some() || self.record.reservation.is_none(),
            "ordinary reserved transfer cannot be cancelled as a batch"
        );
        self.finish_aborted()
    }
    pub(super) fn finish_aborted(&mut self) -> Result<()> {
        ensure!(!self.record.retired, "sender already completed");
        self.record.aborted = true;
        if let Some(mask) = &mut self.record.mask {
            mask.zeroize();
        }
        if let Some(value) = &mut self.record.reservation {
            value.zeroize();
        }
        if let Some(value) = &mut self.record.handover {
            value.zeroize();
        }
        if let Some(value) = &mut self.record.offer {
            value.zeroize();
        }
        if let Some(value) = &mut self.record.completion {
            value.zeroize();
        }
        self.record.mask = None;
        self.record.token.zeroize();
        self.record.reservation = None;
        self.record.handover = None;
        self.record.offer = None;
        self.record.offer_digest = None;
        self.record.completion = None;
        self.persist()?;
        Ok(())
    }
}
