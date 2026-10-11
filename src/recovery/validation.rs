//! Native transaction, key and recovery-record validation.
use super::{
    NativeDraft, RECORD_VERSION, Record, RecoveryCommitments, RecoveryMode, SCHEMA, Stage,
    funding_opening,
};
use crate::bitcoin::{attach_signature, backup, sighash};
use crate::signing::{Blinding, FundingKey};
use anyhow::{Context, Result, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{OutPoint, Transaction, Txid};
use k256::Scalar;
use k256::schnorr::SigningKey;
use std::str::FromStr;
use zark_protocol::handoff::{
    Digest, RecoveryDelay, RecoveryOpening, RecoverySchedule, SigningBinding, blinding_commitment,
    origin_previous_capability, origin_previous_state, origin_refresh_commitment,
};
use zark_protocol::{point, point_bytes, scalar};

impl Record {
    pub(super) fn validate(&self) -> Result<NativeDraft> {
        let _timing =
            zark_protocol::timing::Span::new(zark_protocol::timing::Phase::RecoveryValidation);
        ensure!(
            self.schema == SCHEMA && self.version == RECORD_VERSION,
            "unsupported recovery draft record"
        );
        self.context.encode()?;
        ensure!(
            !matches!(&self.mode, RecoveryMode::BootstrapOriginAttached {})
                || matches!(&self.state, Stage::Complete { .. }),
            "bootstrap activation attached before own recovery completion"
        );
        ensure!(
            self.backing.deployment == hex::encode(self.context.deployment)
                && self.activation_input.deployment == self.backing.deployment
                && self.backing.id == hex::encode(self.context.coin),
            "recovery backing context mismatch"
        );
        for commitment in [
            self.refresh_commitment,
            self.previous_capability,
            self.next_capability,
        ] {
            ensure!(
                commitment != [0; 32],
                "zero recovery authorization commitment"
            );
        }
        ensure!(
            self.previous_capability != self.next_capability,
            "capability must rotate"
        );
        let schedule = RecoverySchedule {
            initial: self.initial,
            gap: self.gap,
            margin: self.margin,
        };
        let next = RecoveryDelay::from_sequence(self.next_delay)?;
        let predecessor_sentinel =
            origin_previous_state(&self.context.deployment, &self.context.coin)?;
        let capability_sentinel =
            origin_previous_capability(&self.context.deployment, &self.context.coin)?;
        ensure!(
            self.next_capability != capability_sentinel,
            "origin sentinel is not an owner capability"
        );
        match &self.mode {
            RecoveryMode::Transfer { previous_delay } => {
                ensure!(
                    self.context.previous_state != predecessor_sentinel
                        && self.previous_capability != capability_sentinel,
                    "origin context is not a transfer"
                );
                schedule.check_transition(RecoveryDelay::from_sequence(*previous_delay)?, next)?;
            }
            RecoveryMode::Origin {}
            | RecoveryMode::BootstrapOriginPending {}
            | RecoveryMode::BootstrapOriginAttached {} => {
                schedule.validate()?;
                ensure!(
                    self.context.previous_state == predecessor_sentinel
                        && self.previous_capability == capability_sentinel,
                    "invalid origin predecessor context"
                );
                ensure!(
                    next == schedule.delay_after(0)?,
                    "origin recovery must use initial delay"
                );
            }
        }
        let funding = funding_opening(&self.context, &self.backing)?;
        let funding_commitment = funding.commitment()?;
        let server = point(&hex::decode(&self.draft_server)?)?;
        if !matches!(&self.mode, RecoveryMode::Transfer { .. }) {
            ensure!(
                self.refresh_commitment
                    == origin_refresh_commitment(
                        &self.context,
                        &funding_commitment,
                        &point_bytes(server)?
                    )?,
                "origin refresh commitment mismatch"
            );
        }
        let user = scalar(&self.user_secret)?;
        ensure!(user != Scalar::ZERO, "zero recovery user share");
        let key = FundingKey::new(server, user)?;
        ensure!(
            point_bytes(key.internal)? == funding.internal_point
                && key.xonly()? == funding.output_key()?
                && key.xonly()? == self.backing.key()?,
            "refreshed shares changed the backing key"
        );
        let activation: Transaction = deserialize(&hex::decode(&self.activation)?)?;
        ensure!(
            self.backing.vout == 0
                && activation.compute_txid() == Txid::from_str(&self.backing.txid)?,
            "activation does not create this backing"
        );
        let activation_outpoint = OutPoint::new(
            Txid::from_str(&self.activation_input.txid)?,
            self.activation_input.vout,
        );
        let mut expected_activation = crate::bitcoin::activation(
            activation_outpoint,
            self.activation_input.amount,
            &[(self.backing.amount, key.xonly()?)],
            0,
        )?;
        if matches!(&self.mode, RecoveryMode::BootstrapOriginPending {}) {
            ensure!(
                activation == expected_activation,
                "pending bootstrap activation must be canonical and unsigned"
            );
        } else {
            ensure!(
                activation.input.len() == 1 && activation.input[0].witness.len() == 1,
                "invalid activation witness shape"
            );
            let signature: [u8; 64] = activation.input[0]
                .witness
                .iter()
                .next()
                .context("missing activation signature")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid activation signature length"))?;
            attach_signature(
                &mut expected_activation,
                self.activation_input.amount,
                self.activation_input.key()?,
                &signature,
            )?;
        }
        ensure!(
            activation == expected_activation,
            "activation transaction mismatch"
        );
        let payout = SigningKey::from_bytes(&self.payout_secret)
            .map_err(|_| anyhow::anyhow!("invalid recovery payout secret"))?;
        let payout_key: Digest = payout.verifying_key().to_bytes().into();
        let transaction = backup(
            OutPoint::new(Txid::from_str(&self.backing.txid)?, self.backing.vout),
            self.backing.amount,
            self.fee,
            payout_key,
            next.blocks(),
        )?;
        ensure!(
            hex::encode(serialize(&transaction)) == self.unsigned_transaction,
            "saved unsigned recovery differs from its parameters"
        );
        let recovery = RecoveryOpening {
            deployment: self.context.deployment,
            coin: self.context.coin,
            funding: funding_commitment,
            salt: self.backup_salt,
            payout: payout_key,
            fee: self.fee,
            delay: next,
        }
        .commitment()?;
        let blinding = blinding_commitment(
            &self.context,
            &funding_commitment,
            &recovery,
            &self.alpha,
            &self.beta,
            &self.nonce_salt,
        )?;
        let blind = Blinding {
            alpha: scalar(&self.alpha)?,
            beta: scalar(&self.beta)?,
        };
        let message = sighash(&transaction, self.backing.amount, key.xonly()?)?;
        let native = NativeDraft {
            key,
            server,
            blind,
            transaction,
            message,
            commitments: RecoveryCommitments {
                funding: funding_commitment,
                recovery,
                blinding,
            },
        };
        match &self.state {
            Stage::Prepared {} => (),
            Stage::NonceBound {
                server_nonce,
                binding,
            } => {
                ensure!(
                    *binding == hex::encode(self.binding(&native, server_nonce)?.encode()?),
                    "saved recovery signing binding changed"
                );
            }
            Stage::Complete {
                server_nonce,
                binding,
                partial,
                transaction,
            } => {
                ensure!(
                    *binding == hex::encode(self.binding(&native, server_nonce)?.encode()?),
                    "completed recovery signing binding changed"
                );
                let completed = self.complete_native(&native, server_nonce, partial)?;
                ensure!(
                    hex::encode(serialize(&completed)) == *transaction,
                    "saved completed recovery mismatch"
                );
            }
        }
        Ok(native)
    }

    pub(super) fn binding(&self, native: &NativeDraft, nonce: &str) -> Result<SigningBinding> {
        let server_nonce = point(&hex::decode(nonce)?)?;
        let session =
            native
                .blind
                .bind(&native.key, native.server, server_nonce, native.message)?;
        let binding = SigningBinding {
            context: self.context.clone(),
            funding: native.commitments.funding,
            refresh_commitment: self.refresh_commitment,
            previous_capability: self.previous_capability,
            next_capability: self.next_capability,
            recovery: native.commitments.recovery,
            nonce_commitment: native.commitments.blinding,
            draft_server: point_bytes(native.server)?,
            server_nonce: point_bytes(server_nonce)?,
            blinded_challenge: session.challenge.to_bytes().into(),
        };
        binding.encode()?;
        Ok(binding)
    }

    pub(super) fn complete_native(
        &self,
        native: &NativeDraft,
        nonce: &str,
        partial: &Digest,
    ) -> Result<Transaction> {
        let rs = point(&hex::decode(nonce)?)?;
        let session = native
            .blind
            .bind(&native.key, native.server, rs, native.message)?;
        let signature =
            native
                .blind
                .finish(&native.key, &session, native.server, rs, scalar(partial)?)?;
        let mut transaction = native.transaction.clone();
        attach_signature(
            &mut transaction,
            self.backing.amount,
            native.key.xonly()?,
            &signature,
        )?;
        Ok(transaction)
    }
}
