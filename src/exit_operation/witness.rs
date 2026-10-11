//! Encode predecessor evidence into the pinned exit authorization ABI.
use super::ExitOperation;
use crate::prover::Prover;
use anyhow::{Result, ensure};
use serde_json::Value;
use std::path::Path;
use zark_protocol::{
    certificate::{OwnerCertificate, PredecessorKind},
    proof::PinnedVerifier,
};

impl ExitOperation {
    pub fn write_authorization_witness(
        &self,
        path: &Path,
        prover: &Prover,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<()> {
        self.verify(verifier, scratch)?;
        let mut values = self.draft()?.authorization_values(&self.policy)?;
        values["current"] = serde_json::json!(self.current()?.encode()?);
        values["current_vk"] = fields(&verifier.recursive_key_bytes(self.role())?)?;
        match &self.certificate()? {
            OwnerCertificate::OriginIssued {
                authorization,
                proof,
                partial,
                activation_partial,
                server_salt,
                origin_signature,
            } => {
                values["current_proof"] = fields(proof)?;
                values["current_authorization"] = serde_json::json!(authorization);
                values["current_partial"] = serde_json::json!(partial);
                values["current_activation_partial"] = serde_json::json!(activation_partial);
                values["current_server_salt"] = serde_json::json!(server_salt);
                values["current_origin_signature"] = serde_json::json!(origin_signature);
                for (name, x) in [
                    ("current_origin_key_point", self.policy.origin_key),
                    (
                        "current_origin_nonce_point",
                        origin_signature[..32].try_into()?,
                    ),
                ] {
                    let point = k256::schnorr::VerifyingKey::from_bytes(&x)?;
                    values[name] = serde_json::json!(
                        zark_protocol::point_bytes((*point.as_affine()).into())?.to_vec()
                    );
                }
            }
            OwnerCertificate::TransferIssued {
                authorization,
                proof,
                partial,
                server_salt,
            } => {
                values["current_proof"] = fields(proof)?;
                values["previous_authorization"] = serde_json::json!(authorization);
                values["previous_partial"] = serde_json::json!(partial);
                ensure!(
                    values["server_salt"] == serde_json::json!(server_salt),
                    "exit predecessor server salt mismatch"
                );
            }
        }
        prover.write_json_witness(
            match self.record.predecessor {
                PredecessorKind::Origin => "exit_from_origin",
                PredecessorKind::Transfer => "exit_from_transfer",
            },
            &values,
            path,
        )
    }
}

fn fields(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len().is_multiple_of(32), "recursive field size");
    Ok(serde_json::json!(
        bytes
            .chunks_exact(32)
            .map(|b| format!("0x{}", hex::encode(b)))
            .collect::<Vec<_>>()
    ))
}
