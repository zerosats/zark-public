//! Reserve, prove and authorize the exact sender handover.
use super::{Mask, SenderDraft, canonical_any, field, recursive, saved_offer_digest, write_new};
use crate::chain::ChainConfig;
use crate::envelope::{OfferContext, encrypt_offer};
use crate::freshness::SignerClient;
use crate::offer::{OfferParameters, UnverifiedOffer};
use crate::recovery::RecoveryDraft;
use anyhow::{Context, Result, ensure};
use bitcoin::consensus::deserialize;
use k256::schnorr::SigningKey;
use serde::Deserialize;
use std::path::Path;
use zark_protocol::certificate::OwnerCertificate;
use zark_protocol::handoff::{
    Digest, HandoverBinding, RecoveryDelay, bridge_commitment, draft_access_commitment,
    mask_commitment, masked_share_commitment,
};
use zark_protocol::lineage::LineageHandoverBinding;
use zark_protocol::owner_auth::OwnerAuthorization;
use zark_protocol::proof::{PinnedVerifier, Relation};
use zark_protocol::wire::{Command, Request};
use zeroize::Zeroizing;

impl SenderDraft {
    pub fn reserve(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
    ) -> Result<()> {
        self.verify_current(verifier, scratch)?;
        ensure!(
            !self.record.retired && !self.record.aborted,
            "sender coin unavailable"
        );
        let request = if let Some(saved) = &self.record.reservation {
            Request::decode(&canonical_any(saved)?)?
        } else {
            let owner_authorization = OwnerAuthorization::sign_reservation(
                &self.record.context,
                &self.record.capability,
            )?;
            let command = if let Some(manifest) = &self.record.batch {
                Command::BatchReserve {
                    manifest: manifest.clone(),
                    owner_authorization,
                }
            } else {
                Command::Reserve {
                    owner_authorization,
                }
            };
            self.freeze_request(command, true)?
        };
        self.check_chain(chain)?;
        let response = client.request(&request)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            mask: Digest,
            mask_salt: Digest,
            mask_commitment: Digest,
        }
        let response: Reply = serde_json::from_value(response)
            .map_err(|_| anyhow::anyhow!("invalid sender reservation response"))?;
        ensure!(
            mask_commitment(
                &self.record.context.intent(),
                &response.mask,
                &response.mask_salt
            )? == response.mask_commitment,
            "sender mask commitment mismatch"
        );
        let masked = self.recovery()?.masked_user(&response.mask)?;
        if let Some(saved) = &self.record.mask {
            ensure!(
                saved.mask == response.mask
                    && saved.salt == response.mask_salt
                    && saved.masked == masked,
                "sender mask already frozen"
            );
        } else {
            self.record.mask = Some(Mask {
                mask: response.mask,
                salt: response.mask_salt,
                masked,
            });
            self.persist()?;
        }
        Ok(())
    }
    pub(super) fn freeze_request(
        &mut self,
        command: Command,
        reservation: bool,
    ) -> Result<Request> {
        let slot = if reservation {
            &self.record.reservation
        } else {
            &self.record.handover
        };
        if let Some(saved) = slot {
            let saved = Request::decode(&canonical_any(saved)?)?;
            ensure!(
                *saved.command.body()? == *command.body()?,
                "sender request already frozen"
            );
            return Ok(saved);
        }
        let key = SigningKey::from_bytes(&self.record.session)?;
        let request = Request::sign(self.record.context.clone(), command, &key)?;
        let encoded = hex::encode(&*request.encode()?);
        if reservation {
            self.record.reservation = Some(encoded);
        } else {
            self.record.handover = Some(encoded);
        }
        self.persist()?;
        Ok(request)
    }
    pub(super) fn handover_binding_unchecked(
        &self,
        recovery: &RecoveryDraft,
    ) -> Result<LineageHandoverBinding> {
        let cert = self.current()?;
        let mask = self
            .record
            .mask
            .as_ref()
            .context("sender mask not frozen")?;
        let intent = self.record.context.intent();
        let delay = RecoveryDelay::from_sequence(
            recovery.completed_transaction()?.input[0]
                .sequence
                .to_consensus_u32(),
        )?;
        let state = recovery.own_state(&self.record.server_salt, cert.policy)?;
        Ok(LineageHandoverBinding {
            handover: HandoverBinding {
                intent: intent.clone(),
                funding: cert.funding,
                mask: mask_commitment(&intent, &mask.mask, &mask.salt)?,
                masked_share: masked_share_commitment(
                    &intent,
                    &mask.masked,
                    &self.record.masked_salt,
                )?,
                bridge: bridge_commitment(
                    &intent,
                    &cert.funding,
                    delay,
                    &cert.policy,
                    &self.record.bridge_salt,
                )?,
                previous_capability: state.capability,
                server_share: state.server_share,
                policy: cert.policy,
                draft_access: draft_access_commitment(&intent, &self.record.token)?,
            },
            origin_key: cert.origin_key,
            role_hashes: cert.role_hashes,
        })
    }
    pub fn write_sender_witness(
        &self,
        path: &Path,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<()> {
        self.verify_current(verifier, scratch)?;
        let recovery = self.recovery()?;
        let composed = self.handover_binding_unchecked(&recovery)?;
        let h = &composed.handover;
        let mask = self.record.mask.as_ref().context("sender mask")?;
        let own = recovery.own_state(&self.record.server_salt, h.policy)?;
        let mut out = Zeroizing::new(String::new());
        field(&mut out, "statement", &composed.encode()?)?;
        crate::prover::packed_witness(&mut out, &composed.encode()?)?;
        recovery.append_sender_opening(&mut out)?;
        for (name, value) in [
            ("server_salt", self.record.server_salt),
            ("capability", self.record.capability),
            ("mask", mask.mask),
            ("mask_salt", mask.salt),
            ("masked_share", mask.masked),
            ("masked_share_salt", self.record.masked_salt),
            ("issuance_digest", own.issuance),
            ("bridge_salt", self.record.bridge_salt),
            ("token", self.record.token),
        ] {
            field(&mut out, name, &value)?;
        }
        let p = self.policy.schedule;
        out.push_str(&format!(
            "initial = {}\ngap = {}\nmargin = {}\n",
            p.initial, p.gap, p.margin
        ));
        field(&mut out, "previous_statement", &self.current()?.encode()?)?;
        let certificate = self.certificate()?;
        let (previous_role, previous_proof) = match &certificate {
            OwnerCertificate::OriginIssued {
                authorization,
                proof,
                partial,
                activation_partial,
                server_salt,
                origin_signature,
            } => {
                field(&mut out, "previous_authorization", authorization)?;
                field(&mut out, "previous_partial", partial)?;
                field(&mut out, "previous_activation_partial", activation_partial)?;
                field(&mut out, "previous_server_salt", server_salt)?;
                field(&mut out, "previous_origin_signature", origin_signature)?;
                for (name, x) in [
                    ("previous_origin_key_point", self.policy.origin_key),
                    (
                        "previous_origin_nonce_point",
                        origin_signature[..32].try_into()?,
                    ),
                ] {
                    let point = k256::schnorr::VerifyingKey::from_bytes(&x)?;
                    field(
                        &mut out,
                        name,
                        &zark_protocol::point_bytes((*point.as_affine()).into())?,
                    )?;
                }
                (Relation::DepositAuthorization, proof)
            }
            OwnerCertificate::TransferIssued {
                authorization,
                proof,
                partial,
                ..
            } => {
                field(&mut out, "previous_authorization", authorization)?;
                field(&mut out, "previous_partial", partial)?;
                (Relation::ReceiverAuthorization, proof)
            }
        };
        recursive(
            &mut out,
            "previous_vk",
            &verifier.recursive_key_bytes(previous_role)?,
            115,
        )?;
        recursive(&mut out, "previous_proof", previous_proof, 458)?;
        write_new(path, out.as_bytes())
    }
    pub fn authorize_handover(
        &mut self,
        proof: &[u8],
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
    ) -> Result<()> {
        self.verify_current(verifier, scratch)?;
        ensure!(!self.record.retired, "sender coin retired");
        let h = self.handover_binding_unchecked(&self.recovery()?)?;
        let predecessor = self.certificate()?.kind();
        // Live backing is read while the proof is verified and the request is
        // frozen; the handover is sent only after both succeed.
        let live = self.live_backing(chain)?;
        let (request, observed) = zark_protocol::local::join_with_helper(
            || {
                verifier.sender_handover(predecessor, &h, proof, scratch)?;
                self.freeze_request(
                    Command::Handover {
                        predecessor,
                        statement: h.encode()?,
                        proof: proof.to_vec(),
                    },
                    false,
                )
            },
            || live.observe(chain),
        )?;
        let request = request?;
        chain.check_transfer_window(&observed?, live.previous, live.next)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            authorized: bool,
        }
        let reply: Reply = serde_json::from_value(client.request(&request)?)
            .map_err(|_| anyhow::anyhow!("invalid handover acknowledgement"))?;
        ensure!(reply.authorized, "handover not authorized");
        if self.record.offer.is_none() {
            let context = OfferContext {
                deployment: self.record.context.deployment,
                coin: self.record.context.coin,
                operation: self.record.context.operation,
            };
            let mask = self.record.mask.as_ref().context("sender mask")?;
            let delay = RecoveryDelay::from_sequence(
                self.recovery()?.completed_transaction()?.input[0]
                    .sequence
                    .to_consensus_u32(),
            )?;
            let offer = UnverifiedOffer::from_parts(
                OfferParameters {
                    predecessor,
                    handover: h,
                    proof: proof.to_vec(),
                    backing: self.record.backing.clone(),
                    activation_input: self.record.activation_input.clone(),
                    activation: deserialize(&canonical_any(&self.record.activation)?)?,
                    masked_share: mask.masked,
                    masked_share_salt: self.record.masked_salt,
                    bridge_salt: self.record.bridge_salt,
                    old_delay: delay,
                    claim_salt: self.record.claim_salt,
                    token: self.record.token,
                },
                &self.recipient()?,
                &context,
                &self.policy,
            )?;
            let encoded = offer.encode()?;
            let encrypted = encrypt_offer(&self.recipient()?, &context, &encoded)?;
            self.record.offer_digest = Some(saved_offer_digest(
                &self.record.context,
                encrypted.as_bytes(),
            )?);
            self.record.offer = Some(hex::encode(encrypted.as_bytes()));
            self.persist()?;
        }
        Ok(())
    }
}
