//! One private receiver job combines invitation, share-refresh and recovery relations.
use super::ReceiverJournal;
use super::persistence::write_private_new;
use anyhow::{Result, ensure};
use k256::schnorr::SigningKey;
use std::path::Path;
use zark_protocol::address::ReceivingAddress;
use zark_protocol::certificate::PredecessorKind;
use zark_protocol::handoff::Digest;
use zark_protocol::proof::{PinnedVerifier, Relation};
use zark_protocol::{point_bytes, scalar};
use zeroize::Zeroizing;

impl ReceiverJournal {
    /// The invitation lends its claim secret only for this private witness write.
    /// No intermediate claim/recovery proof or public secret getter is created.
    pub(crate) fn write_receiver_witness(
        &self,
        invitation_id: &Digest,
        address: &ReceivingAddress,
        claim_secret: &Digest,
        verifier: &PinnedVerifier,
        scratch: &Path,
        path: &Path,
    ) -> Result<()> {
        self.recovery_preparation_request()?;
        ensure!(
            *invitation_id == self.record.invitation_id && address.encode() == self.record.address,
            "receiver witness invitation mismatch"
        );
        let key = SigningKey::from_bytes(claim_secret)?;
        ensure!(
            key.to_bytes()[..] == *claim_secret
                && key.verifying_key().to_bytes()[..] == address.claim_key()[1..],
            "receiver claim key mismatch"
        );
        let native = self.native_offer()?;
        verifier.sender_handover(
            native.predecessor(),
            native.handover(),
            native.outer_proof(),
            scratch,
        )?;
        let material = native.recipient_material();
        let draft = self.open_recovery()?;
        let signing = draft.signing_binding()?;
        let mut out = Zeroizing::new(String::new());
        witness_field(
            &mut out,
            "statement",
            &self.issuance_binding(&signing)?.encode()?,
        )?;
        witness_field(&mut out, "handover", &native.handover().encode()?)?;
        crate::prover::packed_witness(&mut out, &self.issuance_binding(&signing)?.encode()?)?;
        let role = match native.predecessor() {
            PredecessorKind::Origin => Relation::SenderFromOrigin,
            PredecessorKind::Transfer => Relation::SenderFromTransfer,
        };
        recursive_field(
            &mut out,
            "handover_vk",
            &verifier.recursive_key_bytes(role)?,
            115,
        )?;
        recursive_field(&mut out, "handover_proof", native.outer_proof(), 458)?;
        witness_field(&mut out, "claim", &self.claim_binding()?.encode()?)?;
        witness_field(&mut out, "claim_secret", claim_secret)?;
        witness_field(
            &mut out,
            "claim_point",
            &point_bytes(k256::ProjectivePoint::GENERATOR * scalar(claim_secret)?)?,
        )?;
        witness_field(&mut out, "claim_salt", &material.claim_salt)?;
        witness_field(&mut out, "next_capability", &self.record.capability)?;
        witness_field(&mut out, "masked_share", &material.masked_share)?;
        witness_field(&mut out, "masked_share_salt", &material.masked_share_salt)?;
        witness_field(&mut out, "delta", &self.record.delta)?;
        witness_field(&mut out, "delta_salt", &self.record.delta_salt)?;
        draft.append_receiver_recovery_witness(&mut out)?;
        witness_field(&mut out, "bridge_salt", &material.bridge_salt)?;
        out.push_str(&format!("old_delay = {}\n", material.old_delay));
        let policy = self.policy.schedule;
        out.push_str(&format!(
            "initial = {}\ngap = {}\nmargin = {}\n",
            policy.initial, policy.gap, policy.margin
        ));
        write_private_new(path, out.as_bytes())
    }
}

pub(super) fn witness_field(output: &mut String, name: &str, bytes: &[u8]) -> Result<()> {
    let encoded = Zeroizing::new(serde_json::to_string(bytes)?);
    output.push_str(name);
    output.push_str(" = ");
    output.push_str(&encoded);
    output.push('\n');
    Ok(())
}

pub(super) fn recursive_field(
    output: &mut String,
    name: &str,
    bytes: &[u8],
    fields: usize,
) -> Result<()> {
    ensure!(bytes.len() == fields * 32, "recursive witness field length");
    output.push_str(name);
    output.push_str(" = [");
    for (index, field) in bytes.chunks_exact(32).enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\"0x");
        output.push_str(&hex::encode(field));
        output.push('"');
    }
    output.push_str("]\n");
    Ok(())
}
