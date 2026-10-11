//! Verify the incoming offer and freeze the exact recipient claim.
use super::persistence::{decode_hex, validate_record, validated_request};
use super::response::{exact_response_fields, response_bytes};
use super::{MAX_WIRE_BYTES, PrivateClaimRequest, ReceiverJournal, Record, RequestRecord, Stage};
use crate::invitation::{LocalInvitation, ReservationResult};
use crate::offer::UnverifiedOffer;
use crate::signing::FundingKey;
use anyhow::{Result, ensure};
use k256::schnorr::SigningKey;
use std::path::Path;
use zark_protocol::handoff::{
    ClaimBinding, Digest, ServerShareOpening, capability_commitment, delta_commitment,
    refresh_commitment,
};
use zark_protocol::proof::PinnedVerifier;
use zark_protocol::wire::{Command, Request};
use zark_protocol::{point, point_bytes, scalar};
use zeroize::Zeroizing;

impl ReceiverJournal {
    /// Reverification is mandatory after every reopen. Persist the journal phase
    /// first, then reserve the exact original invitation wire. On a crash, retry
    /// both operations; no newly generated key, offer or request replaces them.
    pub fn authorize_and_reserve(
        &mut self,
        invitation: &mut LocalInvitation,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<ReservationResult> {
        let context = self.offer_context();
        let native = validate_record(&self.record, invitation, &context, &self.policy)?;
        let verified = native.verify(verifier, scratch)?;
        if matches!(self.record.stage, Stage::PendingOffer {}) {
            self.record.stage = Stage::Authorized {};
            self.persist()?;
        }
        let encrypted = Zeroizing::new(decode_hex(&self.record.envelope, MAX_WIRE_BYTES)?);
        let result = invitation.reserve(context.coin, context.operation, &encrypted)?;
        self.verified = Some(verified);
        Ok(result)
    }

    /// Public statement only. Its existence does not authorize a claim.
    pub fn claim_binding(&self) -> Result<ClaimBinding> {
        claim_binding(&self.record, &self.native_offer()?)
    }

    pub fn freeze_claim_request(&mut self) -> Result<PrivateClaimRequest> {
        self.require_authorized()?;
        let binding = self.claim_binding()?;
        match (&self.record.context.scope, &self.record.batch) {
            (zark_protocol::handoff::OperationScope::Single, None) => (),
            (zark_protocol::handoff::OperationScope::Batch { manifest_digest }, Some(manifest)) => {
                ensure!(
                    *manifest_digest == manifest.digest()?,
                    "recipient batch intent changed"
                );
                manifest.index(&self.record.context, false)?;
            }
            _ => anyhow::bail!("recipient must bind the exact batch before proposing a draft"),
        }
        let command = Command::ProposeRecipient {
            statement: binding.encode()?,
            token: self.record.token,
            delta: self.record.delta,
            delta_salt: self.record.delta_salt,
        };
        let body = command.body()?;
        match &self.record.stage {
            Stage::Authorized {} => {
                let key = SigningKey::from_bytes(&self.record.session)
                    .map_err(|_| anyhow::anyhow!("invalid recipient session"))?;
                let request = Request::sign(self.record.context.clone(), command, &key)?;
                self.record.stage = Stage::ProposalFrozen {
                    request: RequestRecord {
                        body: hex::encode(&*body),
                        digest: request.digest()?,
                        signature: hex::encode(request.signature),
                    },
                };
            }
            Stage::ProposalFrozen { request } | Stage::DraftFrozen { request, .. } => ensure!(
                request.body == hex::encode(&*body),
                "recipient claim request is already frozen"
            ),
            Stage::PendingOffer {} => anyhow::bail!("recipient offer is pending"),
        }
        self.persist()?;
        self.recipient_claim_request()
    }

    pub fn recipient_claim_request(&self) -> Result<PrivateClaimRequest> {
        self.require_authorized()?;
        let request = match &self.record.stage {
            Stage::ProposalFrozen { request } | Stage::DraftFrozen { request, .. } => request,
            _ => anyhow::bail!("recipient claim request is not frozen"),
        };
        validated_request(&self.record, &self.claim_binding()?, request)
    }

    /// Validates and freezes an actual refreshed server point, not a caller's
    /// opaque refresh digest. Authenticating the server response is separate.
    pub fn freeze_draft(&mut self, response: &serde_json::Value) -> Result<Digest> {
        self.require_authorized()?;
        exact_response_fields(response, &["draft_server", "server_salt"])?;
        let server = response_bytes::<64>(response, "draft_server")?;
        let server_salt = response_bytes::<32>(response, "server_salt")?;
        ensure!(server_salt != [0; 32], "empty server share salt");
        let claim = self.claim_binding()?;
        let refresh = refresh_commitment(
            &self.record.context,
            &claim.mask,
            &claim.masked_share,
            &claim.bridge,
            &claim.delta,
            &server,
        )?;
        self.validate_draft(&server, &refresh)?;
        let encoded = hex::encode(server);
        match &self.record.stage {
            Stage::ProposalFrozen { request } => {
                ensure!(
                    self.record.server_salt.is_none(),
                    "server share salt before draft"
                );
                self.record.stage = Stage::DraftFrozen {
                    request: request.clone(),
                    server: encoded,
                    refresh,
                    recovery: None,
                };
                self.record.server_salt = Some(server_salt);
            }
            Stage::DraftFrozen {
                server: saved,
                refresh: saved_refresh,
                ..
            } => ensure!(
                *saved == encoded
                    && *saved_refresh == refresh
                    && self.record.server_salt == Some(server_salt),
                "recipient draft is already frozen"
            ),
            _ => anyhow::bail!("recipient claim must be frozen before draft"),
        }
        self.persist()?;
        ServerShareOpening {
            deployment: self.record.context.deployment,
            coin: self.record.context.coin,
            server,
            salt: server_salt,
        }
        .commitment()
    }
}

pub(super) fn claim_binding(record: &Record, native: &UnverifiedOffer) -> Result<ClaimBinding> {
    let handover = &native.handover().handover;
    let binding = ClaimBinding {
        context: record.context.clone(),
        mask: handover.mask,
        masked_share: handover.masked_share,
        bridge: handover.bridge,
        delta: delta_commitment(&record.context, &record.delta, &record.delta_salt)?,
        next_capability: capability_commitment(
            &record.context.deployment,
            &record.context.coin,
            &record.capability,
        )?,
    };
    binding.encode()?;
    Ok(binding)
}

pub(super) fn validate_draft(
    record: &Record,
    native: &UnverifiedOffer,
    server: &[u8; 64],
    refresh: &Digest,
) -> Result<()> {
    let claim = claim_binding(record, native)?;
    ensure!(
        *refresh
            == refresh_commitment(
                &record.context,
                &claim.mask,
                &claim.masked_share,
                &claim.bridge,
                &claim.delta,
                server
            )?,
        "recipient refresh commitment mismatch"
    );
    let key = FundingKey::new(point(server)?, scalar(&record.user)?)?;
    let backing = native.common_backing();
    ensure!(
        point_bytes(key.internal)? == hex::decode(&backing.internal_point)?.as_slice()
            && key.xonly()? == backing.key()?,
        "recipient refreshed shares changed backing"
    );
    Ok(())
}
