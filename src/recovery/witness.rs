//! Checked recovery bindings and private witness construction.
use super::{
    OriginRecoveryParameters, RecoveryCommitments, RecoveryDraft, RecoveryMode, RecoveryParameters,
    Stage, funding_opening, recovery_field,
};
use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use bitcoin::consensus::{deserialize, serialize};
use k256::Scalar;
use k256::schnorr::SigningKey;
use zark_protocol::handoff::{
    Digest, ServerShareOpening, SigningBinding, StateOpening, issuance_commitment,
};
use zark_protocol::{point_bytes, scalar};

impl RecoveryDraft {
    /// F, B and N were committed durably at creation, before any server nonce.
    pub fn commitments(&self) -> Result<RecoveryCommitments> {
        Ok(self.native()?.commitments)
    }

    /// Public signing statement, derived again from this exact saved draft.
    /// Its existence does not authorize issuance or prove current ownership.
    pub fn signing_binding(&self) -> Result<SigningBinding> {
        let native = self.native()?;
        match &self.record.state {
            Stage::Prepared {} => anyhow::bail!("recovery nonce is not bound"),
            Stage::NonceBound { server_nonce, .. } | Stage::Complete { server_nonce, .. } => {
                self.record.binding(&native, server_nonce)
            }
        }
    }

    /// Enforces the journal/draft relationship after a crash or separate reopen.
    /// No private opening escapes this module through the comparison.
    pub(crate) fn require_receiver_parameters(
        &self,
        expected: &RecoveryParameters,
        user: &Digest,
        payout: &Digest,
    ) -> Result<()> {
        self.native()?;
        ensure!(
            matches!(&self.record.mode, RecoveryMode::Transfer { previous_delay }
            if *previous_delay == expected.previous_delay.blocks()),
            "receiver recovery mode mismatch"
        );
        ensure!(
            self.record.context == expected.context
                && serde_json::to_vec(&self.record.backing)?
                    == serde_json::to_vec(&expected.backing)?
                && serde_json::to_vec(&self.record.activation_input)?
                    == serde_json::to_vec(&expected.activation_input)?
                && self.record.activation == hex::encode(serialize(&expected.activation))
                && self.record.draft_server == hex::encode(expected.draft_server)
                && self.record.refresh_commitment == expected.refresh_commitment
                && self.record.previous_capability == expected.previous_capability
                && self.record.next_capability == expected.next_capability
                && self.record.initial == expected.schedule.initial
                && self.record.gap == expected.schedule.gap
                && self.record.margin == expected.schedule.margin
                && self.record.next_delay == expected.next_delay.blocks()
                && self.record.fee == expected.fee
                && self.record.user_secret == *user
                && self.record.payout_secret == *payout,
            "recipient journal and recovery draft differ"
        );
        Ok(())
    }

    /// The origin journal pins its unsigned common parent and own active keys
    /// before any recovery nonce request. Attached mode differs only by the
    /// validated parent signature, never by the transaction body or recovery.
    pub(crate) fn require_bootstrap_origin_parameters(
        &self,
        expected: &OriginRecoveryParameters,
        user: &Digest,
        payout: &Digest,
    ) -> Result<()> {
        self.native()?;
        ensure!(
            matches!(
                &self.record.mode,
                RecoveryMode::BootstrapOriginPending {} | RecoveryMode::BootstrapOriginAttached {}
            ),
            "recovery is not a bootstrap origin"
        );
        ensure!(
            expected.activation.input.len() == 1 && expected.activation.input[0].witness.is_empty(),
            "origin journal expected activation must be unsigned"
        );
        let mut unsigned: Transaction = deserialize(&hex::decode(&self.record.activation)?)?;
        unsigned.input[0].witness.clear();
        ensure!(
            self.record.context == expected.context
                && serde_json::to_vec(&self.record.backing)?
                    == serde_json::to_vec(&expected.backing)?
                && serde_json::to_vec(&self.record.activation_input)?
                    == serde_json::to_vec(&expected.activation_input)?
                && unsigned == expected.activation
                && self.record.draft_server == hex::encode(expected.draft_server)
                && self.record.next_capability == expected.initial_capability
                && self.record.initial == expected.schedule.initial
                && self.record.gap == expected.schedule.gap
                && self.record.margin == expected.schedule.margin
                && self.record.next_delay == expected.schedule.initial
                && self.record.fee == expected.fee
                && self.record.user_secret == *user
                && self.record.payout_secret == *payout,
            "origin journal and recovery draft differ"
        );
        Ok(())
    }

    /// Only the recipient journal may request this private witness. Every field
    /// comes from the saved native transaction, never a caller-supplied opening.
    pub(crate) fn append_recovery_witness(&self, out: &mut String, completed: bool) -> Result<()> {
        let binding = self.signing_binding()?;
        recovery_field(out, "statement", &binding.encode()?)?;
        recovery_field(out, "binding_digest", &binding.digest()?)?;
        if completed {
            let (_, partial) = self.completion_binding()?;
            recovery_field(out, "partial", &partial)?;
            let transaction = self.completed_transaction()?;
            let signature = transaction.input[0]
                .witness
                .iter()
                .next()
                .context("recovery signature")?;
            recovery_field(out, "signature", signature)?;
        }
        recovery_field(out, "user", &self.record.user_secret)?;
        recovery_field(out, "alpha", &self.record.alpha)?;
        recovery_field(out, "beta", &self.record.beta)?;
        recovery_field(out, "nonce_salt", &self.record.nonce_salt)?;
        self.append_funding_witness(out)?;
        self.append_recovery_opening(out, "destination")?;
        let session = k256::schnorr::VerifyingKey::from_bytes(&self.record.context.session_auth)?;
        let point = point_bytes((*session.as_affine()).into())?;
        recovery_field(out, "session_auth_point", &point)
    }

    pub(crate) fn append_funding_witness(&self, out: &mut String) -> Result<()> {
        self.native()?;
        let funding = funding_opening(&self.record.context, &self.record.backing)?;
        recovery_field(out, "funding_salt", &funding.salt)?;
        recovery_field(out, "txid", &funding.txid)?;
        out.push_str(&format!(
            "vout = {}\namount = {}\n",
            funding.vout, funding.amount
        ));
        Ok(())
    }

    pub(crate) fn append_recovery_opening(
        &self,
        out: &mut String,
        payout_name: &str,
    ) -> Result<()> {
        self.native()?;
        let key = SigningKey::from_bytes(&self.record.payout_secret)?;
        let destination = point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&key.to_bytes())?)?;
        recovery_field(out, payout_name, &destination)?;
        recovery_field(out, "backup_salt", &self.record.backup_salt)?;
        out.push_str(&format!(
            "fee = {}\ndelay = {}\n",
            self.record.fee, self.record.next_delay
        ));
        Ok(())
    }

    pub(crate) fn completion_binding(&self) -> Result<(SigningBinding, Digest)> {
        let binding = self.signing_binding()?;
        match &self.record.state {
            Stage::Complete { partial, .. } => Ok((binding, *partial)),
            _ => anyhow::bail!("recovery is not complete"),
        }
    }

    pub(crate) fn append_receiver_recovery_witness(&self, out: &mut String) -> Result<()> {
        self.signing_binding()?;
        recovery_field(out, "user", &self.record.user_secret)?;
        recovery_field(out, "alpha", &self.record.alpha)?;
        recovery_field(out, "beta", &self.record.beta)?;
        recovery_field(out, "nonce_salt", &self.record.nonce_salt)?;
        self.append_funding_witness(out)?;
        self.append_recovery_opening(out, "payout")?;
        let session = k256::schnorr::VerifyingKey::from_bytes(&self.record.context.session_auth)?;
        recovery_field(
            out,
            "session_auth_point",
            &point_bytes((*session.as_affine()).into())?,
        )
    }

    pub(crate) fn own_state(&self, server_salt: &Digest, policy: Digest) -> Result<StateOpening> {
        let (binding, partial) = self.completion_binding()?;
        let state = StateOpening {
            deployment: binding.context.deployment,
            coin: binding.context.coin,
            funding: binding.funding,
            capability: binding.next_capability,
            recovery: binding.recovery,
            server_share: ServerShareOpening {
                deployment: binding.context.deployment,
                coin: binding.context.coin,
                server: binding.draft_server,
                salt: *server_salt,
            }
            .commitment()?,
            policy,
            issuance: issuance_commitment(&binding.digest()?, &partial)?,
        };
        state.commitment()?;
        Ok(state)
    }

    /// Narrow sender-local algebra. The server's mask is never available to the
    /// recipient; only the resulting masked share belongs in its offer.
    pub(crate) fn masked_user(&self, mask: &Digest) -> Result<Digest> {
        self.completed_activation()?;
        self.completed_transaction()?;
        ensure!(scalar(mask)? != Scalar::ZERO, "zero sender mask");
        let z = scalar(&self.record.user_secret)? + scalar(mask)?;
        ensure!(z != Scalar::ZERO, "zero masked owner share");
        Ok(z.to_bytes().into())
    }

    /// Private witness fields for this owner's sender primitive. Does not export
    /// its recovery signature or old proof; those remain independent artifacts.
    pub(crate) fn append_sender_opening(&self, out: &mut String) -> Result<()> {
        self.completed_activation()?;
        self.completed_transaction()?;
        recovery_field(out, "server", &hex::decode(&self.record.draft_server)?)?;
        recovery_field(out, "user", &self.record.user_secret)?;
        self.append_funding_witness(out)?;
        // The recursive predecessor authenticates this exact funding opening;
        // the v10 sender circuit reuses its Taproot output key.
        recovery_field(out, "funding_output_key", &self.record.backing.key()?)?;
        self.append_recovery_opening(out, "destination")
    }
}
