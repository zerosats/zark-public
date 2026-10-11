//! Prepare recovery and freeze its exact authorization before issuance.
use super::persistence::decode_hex;
use super::response::{checked_recovery_request, exact_response_fields, response_bytes};
use super::{ReceiverJournal, RecoveryRecord, RecoveryRequest, RequestRecord, Stage, fresh_scalar};
use crate::chain::ChainConfig;
use crate::recovery::{RecoveryCommitments, RecoveryDraft, RecoveryParameters};
use anyhow::{Context, Result, ensure};
use k256::schnorr::SigningKey;
use std::fs;
use std::path::Path;
use zark_protocol::handoff::{Digest, SigningBinding, policy_commitment};
use zark_protocol::lineage::{IssuanceBinding, LineageBinding};
use zark_protocol::proof::PinnedVerifier;
use zark_protocol::session::Purpose;
use zark_protocol::wire::{Command, MAX_BODY};
use zeroize::Zeroizing;

impl ReceiverJournal {
    /// Saves a fresh payout key and fee before creating the separate native
    /// recovery draft. Exact retry reopens the same draft and commitments.
    /// This commitment-only request must precede disclosure of a server nonce.
    pub fn prepare_recovery(&mut self, fee: u64) -> Result<RecoveryRequest> {
        self.require_authorized()?;
        ensure!(
            (1..=10_000).contains(&fee) && self.native_offer()?.common_backing().amount > fee + 330,
            "recipient recovery fee bounds"
        );
        match &mut self.record.stage {
            Stage::DraftFrozen {
                recovery: Some(r), ..
            } => ensure!(r.fee == fee, "recovery fee is already frozen"),
            Stage::DraftFrozen { recovery, .. } => {
                let payout = SigningKey::from_bytes(&fresh_scalar())?;
                *recovery = Some(RecoveryRecord {
                    payout: payout.to_bytes().into(),
                    fee,
                    preparation: None,
                    issuance: None,
                    certificate: None,
                    acceptance: None,
                    accepted: false,
                    outgoing: None,
                });
                self.persist()?;
            }
            _ => anyhow::bail!("freeze actual draft before preparing recovery"),
        }
        let parameters = self.recovery_parameters()?;
        let payout = Zeroizing::new(self.recovery_record()?.payout);
        let directory = self.directory.join("own-recovery");
        let draft = match fs::symlink_metadata(&directory) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                RecoveryDraft::create(&directory, parameters, &self.record.user, &payout)?
            }
            Ok(_) => self.open_recovery()?,
            Err(e) => return Err(e.into()),
        };
        let body = self.preparation_body(draft.commitments()?)?;
        if let Some(request) = &self.recovery_record()?.preparation {
            return checked_recovery_request(
                &self.record.context,
                Purpose::RecoveryPreparation,
                request,
                &body,
            );
        }
        let request = self.sign_body(Purpose::RecoveryPreparation, &body)?;
        self.recovery_record_mut()?.preparation = Some(request);
        self.persist()?;
        drop(draft);
        self.recovery_preparation_request()
    }

    pub fn recovery_preparation_request(&self) -> Result<RecoveryRequest> {
        self.require_authorized()?;
        let draft = self.open_recovery()?;
        self.recovery_preparation_with_draft(&draft)
    }

    fn recovery_preparation_with_draft(&self, draft: &RecoveryDraft) -> Result<RecoveryRequest> {
        self.require_authorized()?;
        let body = self.preparation_body(draft.commitments()?)?;
        checked_recovery_request(
            &self.record.context,
            Purpose::RecoveryPreparation,
            self.recovery_record()?
                .preparation
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("recovery preparation request is not saved"))?,
            &body,
        )
    }

    /// Authentication of this response belongs to the orchestration layer.
    /// Native code freezes exactly one nonce after the durable commitments.
    pub fn bind_recovery_nonce(&mut self, response: &serde_json::Value) -> Result<SigningBinding> {
        self.recovery_preparation_request()?;
        exact_response_fields(response, &["server_nonce", "server_salt", "draft_server"])?;
        let server_nonce = response_bytes::<64>(response, "server_nonce")?;
        let server_salt = response_bytes::<32>(response, "server_salt")?;
        let server = response_bytes::<64>(response, "draft_server")?;
        ensure!(
            self.record.server_salt == Some(server_salt)
                && self.recovery_parameters()?.draft_server == server,
            "preparation response differs from frozen draft"
        );
        let mut draft = self.open_recovery()?;
        draft.bind_server_nonce(&self.record.context, server_nonce)
    }

    /// Only a successfully verified full TransferIssuance proof can freeze this
    /// request. A primitive recovery proof, even valid, is never sufficient.
    pub fn freeze_issuance_request(
        &mut self,
        proof: &[u8],
        verifier: &PinnedVerifier,
        scratch: &Path,
        chain: Option<&ChainConfig>,
    ) -> Result<RecoveryRequest> {
        let draft = self.open_recovery()?;
        self.freeze_issuance_with_draft(&draft, proof, verifier, scratch, chain)
    }

    pub(super) fn freeze_issuance_with_draft(
        &mut self,
        draft: &RecoveryDraft,
        proof: &[u8],
        verifier: &PinnedVerifier,
        scratch: &Path,
        chain: Option<&ChainConfig>,
    ) -> Result<RecoveryRequest> {
        self.recovery_preparation_with_draft(draft)?;
        let signing = draft.signing_binding()?;
        let binding = self.issuance_binding(&signing)?;
        verifier.receiver_authorization(&binding, proof, scratch)?;
        let command = if let Some(manifest) = &self.record.batch {
            let observed_tip = if let Some(saved) = &self.recovery_record()?.issuance {
                Self::saved_batch_tip(saved)?
            } else {
                self.checked_live_tip(chain.context("batch readiness requires Bitcoin chain")?)?
            };
            Command::BatchReady {
                manifest: manifest.clone(),
                observed_tip,
                statement: binding.encode()?,
                proof: proof.to_vec(),
            }
        } else {
            Command::Issue {
                statement: binding.encode()?,
                proof: proof.to_vec(),
            }
        };
        let purpose = command.purpose();
        let body = command.body()?;
        if let Some(saved) = &self.recovery_record()?.issuance {
            return checked_recovery_request(&self.record.context, purpose, saved, &body);
        }
        let request = self.sign_body(purpose, &body)?;
        self.recovery_record_mut()?.issuance = Some(request);
        self.persist()?;
        self.issuance_with_draft(draft, verifier, scratch)
    }

    /// Re-verifies the complete saved proof after every reopen before returning
    /// an exact signed retry or using an issued server response.
    pub fn issuance_request(
        &self,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<RecoveryRequest> {
        let draft = self.open_recovery()?;
        self.issuance_with_draft(&draft, verifier, scratch)
    }

    fn issuance_with_draft(
        &self,
        draft: &RecoveryDraft,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<RecoveryRequest> {
        self.require_authorized()?;
        let signing = draft.signing_binding()?;
        let saved = self
            .recovery_record()?
            .issuance
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("composed issuance request is not frozen"))?;
        let proof = self.decode_issuance(saved, &signing)?;
        verifier.receiver_authorization(&self.issuance_binding(&signing)?, &proof, scratch)?;
        let command = if let Some(manifest) = &self.record.batch {
            Command::BatchReady {
                manifest: manifest.clone(),
                observed_tip: Self::saved_batch_tip(saved)?,
                statement: self.issuance_binding(&signing)?.encode()?,
                proof,
            }
        } else {
            Command::Issue {
                statement: self.issuance_binding(&signing)?.encode()?,
                proof,
            }
        };
        checked_recovery_request(
            &self.record.context,
            command.purpose(),
            saved,
            &command.body()?,
        )
    }

    /// Saves and verifies the receiver's own actual recovery, not accepted
    /// ownership. The previously frozen composed proof is reverified first.
    pub fn complete_recovery(
        &mut self,
        partial: Digest,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<bitcoin::Transaction> {
        self.issuance_request(verifier, scratch)?;
        let mut draft = self.open_recovery()?;
        let binding = draft.signing_binding()?;
        draft.finish(&self.record.context, binding.server_nonce, partial)
    }

    pub(super) fn recovery_record(&self) -> Result<&RecoveryRecord> {
        match &self.record.stage {
            Stage::DraftFrozen {
                recovery: Some(recovery),
                ..
            } => Ok(recovery),
            _ => anyhow::bail!("recipient recovery is not prepared"),
        }
    }
    pub(super) fn recovery_record_mut(&mut self) -> Result<&mut RecoveryRecord> {
        match &mut self.record.stage {
            Stage::DraftFrozen {
                recovery: Some(recovery),
                ..
            } => Ok(recovery),
            _ => anyhow::bail!("recipient recovery is not prepared"),
        }
    }
    pub(super) fn recovery_parameters(&self) -> Result<RecoveryParameters> {
        let native = self.native_offer()?;
        let (previous_delay, next_delay) = self.recovery_delays()?;
        let (server, refresh) = match &self.record.stage {
            Stage::DraftFrozen {
                server, refresh, ..
            } => (server, *refresh),
            _ => anyhow::bail!("recipient draft is not frozen"),
        };
        Ok(RecoveryParameters {
            context: self.record.context.clone(),
            backing: native.common_backing().clone(),
            activation_input: native.common_activation_input().clone(),
            activation: native.common_activation().clone(),
            draft_server: decode_hex(server, 64)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("draft point size"))?,
            refresh_commitment: refresh,
            previous_capability: native.handover().handover.previous_capability,
            next_capability: self.claim_binding()?.next_capability,
            schedule: self.policy.schedule,
            previous_delay,
            next_delay,
            fee: self.recovery_record()?.fee,
        })
    }
    pub(super) fn open_recovery(&self) -> Result<RecoveryDraft> {
        let record = self.recovery_record()?;
        let draft =
            RecoveryDraft::open(&self.directory.join("own-recovery"), &self.record.context)?;
        draft.require_receiver_parameters(
            &self.recovery_parameters()?,
            &self.record.user,
            &record.payout,
        )?;
        Ok(draft)
    }
    pub(super) fn preparation_body(&self, commitments: RecoveryCommitments) -> Result<Vec<u8>> {
        Ok(Command::Prepare {
            recovery: commitments.recovery,
            blinding: commitments.blinding,
        }
        .body()?
        .to_vec())
    }
    pub(super) fn issuance_binding(&self, signing: &SigningBinding) -> Result<IssuanceBinding> {
        Ok(IssuanceBinding {
            signing: SigningBinding::decode(&signing.encode()?)?,
            policy: policy_commitment(self.policy.schedule)?,
            origin_key: self.policy.origin_key,
            role_hashes: self.policy.role_hashes,
        })
    }
    pub(super) fn lineage_binding(&self, draft: &RecoveryDraft) -> Result<LineageBinding> {
        let state = draft.own_state(
            &self.record.server_salt.context("server salt missing")?,
            policy_commitment(self.policy.schedule)?,
        )?;
        Ok(LineageBinding {
            deployment: state.deployment,
            coin: state.coin,
            funding: state.funding,
            state: state.commitment()?,
            policy: state.policy,
            origin_key: self.policy.origin_key,
            role_hashes: self.policy.role_hashes,
        })
    }
    pub(super) fn decode_issuance(
        &self,
        saved: &RequestRecord,
        signing: &SigningBinding,
    ) -> Result<Vec<u8>> {
        let bytes = decode_hex(&saved.body, MAX_BODY)?;
        let command = Command::decode(&bytes)?;
        let (statement, proof) = match (&self.record.batch, command) {
            (None, Command::Issue { statement, proof }) => (statement, proof),
            (
                Some(expected),
                Command::BatchReady {
                    manifest,
                    statement,
                    proof,
                    ..
                },
            ) if &manifest == expected => (statement, proof),
            _ => anyhow::bail!("saved command is not the frozen issuance kind"),
        };
        ensure!(
            statement == self.issuance_binding(signing)?.encode()?,
            "invalid composed issuance statement"
        );
        checked_recovery_request(
            &self.record.context,
            if self.record.batch.is_some() {
                Purpose::BatchReadiness
            } else {
                Purpose::RecoveryIssuance
            },
            saved,
            &bytes,
        )?;
        Ok(proof)
    }

    fn saved_batch_tip(saved: &RequestRecord) -> Result<Digest> {
        let bytes = decode_hex(&saved.body, MAX_BODY)?;
        match Command::decode(&bytes)? {
            Command::BatchReady { observed_tip, .. } if observed_tip != [0; 32] => Ok(observed_tip),
            _ => anyhow::bail!("saved batch readiness has no Bitcoin tip"),
        }
    }
}
