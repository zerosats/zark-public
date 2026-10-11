//! Complete Bitcoin signatures and export durable recovery material.
use super::{RecoveryDraft, RecoveryMode, Stage};
use crate::bitcoin::attach_signature;
use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use bitcoin::consensus::{deserialize, serialize};
use std::path::Path;
use zark_protocol::handoff::{Digest, SigningBinding, TransferContext};

impl RecoveryDraft {
    /// Pins exactly one server nonce. The same nonce is an idempotent retry;
    /// a changed context or nonce never reuses the saved blinding values.
    pub fn bind_server_nonce(
        &mut self,
        context: &TransferContext,
        server_nonce: [u8; 64],
    ) -> Result<SigningBinding> {
        ensure!(
            self.record.context == *context,
            "recovery draft context mismatch"
        );
        let native = self.record.validate()?;
        let nonce = hex::encode(server_nonce);
        let binding = self.record.binding(&native, &nonce)?;
        match &self.record.state {
            Stage::Prepared {} => {
                self.record.state = Stage::NonceBound {
                    server_nonce: nonce,
                    binding: hex::encode(binding.encode()?),
                }
            }
            Stage::NonceBound {
                server_nonce: saved,
                ..
            }
            | Stage::Complete {
                server_nonce: saved,
                ..
            } => {
                ensure!(
                    *saved == nonce,
                    "recovery draft already bound to a different server nonce"
                );
            }
        }
        self.persist()?;
        Ok(binding)
    }

    /// Completes and natively verifies the actual BIP340 recovery signature.
    /// No server secret is accepted by this API. A partial alone is insufficient:
    /// context and the previously pinned nonce must match, even on exact retry.
    pub fn finish(
        &mut self,
        context: &TransferContext,
        server_nonce: [u8; 64],
        partial: Digest,
    ) -> Result<Transaction> {
        ensure!(
            self.record.context == *context,
            "recovery draft context mismatch"
        );
        let nonce = hex::encode(server_nonce);
        match &self.record.state {
            Stage::Prepared {} => anyhow::bail!("bind a server nonce before completing recovery"),
            Stage::NonceBound {
                server_nonce: saved,
                ..
            } => ensure!(*saved == nonce, "recovery server nonce mismatch"),
            Stage::Complete {
                server_nonce: saved,
                partial: saved_partial,
                ..
            } => {
                ensure!(
                    *saved == nonce && *saved_partial == partial,
                    "completed recovery only permits its exact response"
                );
            }
        }
        let native = self.record.validate()?;
        let transaction = self.record.complete_native(&native, &nonce, &partial)?;
        self.record.state = Stage::Complete {
            server_nonce: nonce,
            binding: hex::encode(
                self.record
                    .binding(&native, &hex::encode(server_nonce))?
                    .encode()?,
            ),
            partial,
            transaction: hex::encode(serialize(&transaction)),
        };
        self.persist()?;
        Ok(transaction)
    }

    /// Revalidates saved completion without a signer, prover, or old-owner data.
    /// This is the raw current recovery, not an old-version RecoveryExport.
    pub fn completed_transaction(&self) -> Result<Transaction> {
        self.native()?;
        match &self.record.state {
            Stage::Complete { transaction, .. } => Ok(deserialize(&hex::decode(transaction)?)?),
            _ => anyhow::bail!("recovery transaction is not complete"),
        }
    }

    /// Writes a standalone recovery file containing only public transaction
    /// context, the signed activation and own recovery, and its payout secret.
    /// The target must not exist and its parent must be private (0700). A failed
    /// write may leave a partial file; never treat that as a completed export.
    pub fn export_portable(&self, path: &Path) -> Result<()> {
        self.completed_activation()?;
        let recovery = self.completed_transaction()?;
        let activation = deserialize(&hex::decode(&self.record.activation)?)?;
        crate::recovery_export::write_completed(
            path,
            crate::recovery_export::CompletedRecovery {
                deployment: &self.record.context.deployment,
                coin: &self.record.context.coin,
                activation_parent: &self.record.activation_input,
                activation: &activation,
                backing: &self.record.backing,
                recovery: &recovery,
                fee_sat: self.record.fee,
                relative_blocks: self.record.next_delay,
                payout_secret: &self.record.payout_secret,
            },
        )
    }

    /// Attach only after this receiver's exact initial recovery has been fully
    /// signed and saved. Parent txid/output/sequence remain unchanged; only its
    /// single validated signature is added. Exact retry is permitted.
    pub fn attach_completed_activation(&mut self, activation: &Transaction) -> Result<()> {
        self.completed_transaction()?;
        match &self.record.mode {
            RecoveryMode::BootstrapOriginPending {} => (),
            RecoveryMode::BootstrapOriginAttached {} => {
                ensure!(
                    self.record.activation == hex::encode(serialize(activation)),
                    "bootstrap activation is already attached"
                );
                self.record.validate()?;
                return Ok(());
            }
            _ => anyhow::bail!("only a pending bootstrap origin accepts activation attachment"),
        }
        let mut expected: Transaction = deserialize(&hex::decode(&self.record.activation)?)?;
        ensure!(
            activation.input.len() == 1 && activation.input[0].witness.len() == 1,
            "bootstrap activation witness shape"
        );
        let signature: [u8; 64] = activation.input[0]
            .witness
            .iter()
            .next()
            .context("bootstrap activation signature")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bootstrap activation signature length"))?;
        attach_signature(
            &mut expected,
            self.record.activation_input.amount,
            self.record.activation_input.key()?,
            &signature,
        )?;
        ensure!(
            *activation == expected
                && activation.compute_txid().to_string() == self.record.backing.txid,
            "bootstrap activation differs from frozen parent transaction"
        );
        self.record.activation = hex::encode(serialize(activation));
        self.record.mode = RecoveryMode::BootstrapOriginAttached {};
        self.record.validate()?;
        self.persist()
    }

    pub fn completed_activation(&self) -> Result<Transaction> {
        self.native()?;
        ensure!(
            !matches!(&self.record.mode, RecoveryMode::BootstrapOriginPending {}),
            "bootstrap parent activation is not complete"
        );
        Ok(deserialize(&hex::decode(&self.record.activation)?)?)
    }
}
