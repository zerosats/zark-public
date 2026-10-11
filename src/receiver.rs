//! Durable recipient-owned operation for the two-proof flow.
//! Pending offers confer no authority. Every reopened journal must reverify its
//! actual outer proof before witness generation, claim requests or draft use.
mod acceptance;
mod claim;
mod freshness;
mod issuance;
mod outgoing;
mod persistence;
mod response;
mod settlement;
mod witness;
use claim::validate_draft;
use persistence::{acquire_lock, check_directory, decode_hex, validate_record};

use crate::{
    envelope::OfferContext,
    freshness::{HeadProbe, SignerClient},
    invitation::LocalInvitation,
    offer::{MAX_OFFER_PLAINTEXT_BYTES, UnverifiedOffer, VerifiedOffer},
};
use anyhow::{Result, ensure};
use k256::{Scalar, schnorr::SigningKey};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    batch::Manifest as BatchManifest,
    handoff::{Digest, RecoveryDelay, TransferContext},
    hash,
    head::Phase as HeadPhase,
    lineage::LineagePolicy,
    local::ProcessLock,
    proof::PinnedVerifier,
    random32, scalar,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SCHEMA: &str = "zark-recipient-operation";
const RECORD: &str = "recipient-operation.json";
const LOCK: &str = "recipient-operation.lock";
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_WIRE_BYTES: usize = 2 * MAX_OFFER_PLAINTEXT_BYTES + 512;

#[derive(Clone, Copy)]
enum CurrentUse {
    IncomingTransfer,
    CooperativeExit,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RequestRecord {
    body: String,
    digest: Digest,
    signature: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
// One journal stage is retained at a time and its encoded record is capped at
// MAX_RECORD_BYTES. Keep the existing stored format and zeroizing ownership.
#[allow(clippy::large_enum_variant)]
enum Stage {
    PendingOffer {},
    Authorized {},
    ProposalFrozen {
        request: RequestRecord,
    },
    DraftFrozen {
        request: RequestRecord,
        server: String,
        refresh: Digest,
        recovery: Option<RecoveryRecord>,
    },
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RecoveryRecord {
    payout: Digest,
    fee: u64,
    preparation: Option<RequestRecord>,
    issuance: Option<RequestRecord>,
    certificate: Option<CertificateRecord>,
    acceptance: Option<RequestRecord>,
    accepted: bool,
    outgoing: Option<OutgoingOperation>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum OutgoingOperation {
    Transfer {
        directory: String,
        staging: String,
        recipient: String,
    },
    Exit {
        directory: String,
        staging: String,
        destination: Digest,
        fee: u64,
    },
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct CertificateRecord {
    encoded: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    invitation_id: Digest,
    address: String,
    #[zeroize(skip)]
    context: TransferContext,
    #[serde(default)]
    #[zeroize(skip)]
    batch: Option<BatchManifest>,
    offer: String,
    envelope: String,
    user: Digest,
    capability: Digest,
    token: Digest,
    session: Digest,
    delta: Digest,
    delta_salt: Digest,
    server_salt: Option<Digest>,
    stage: Stage,
}

/// Explicit recipient-to-signer payload. Contains a delta opening and must use
/// confidential authenticated transport; never return it to the previous owner.
pub struct PrivateClaimRequest {
    body: Zeroizing<Vec<u8>>,
    signature: [u8; 64],
}

/// Session-authenticated request containing only opaque recovery commitments or
/// the complete composed issuance proof. Does not contain Bitcoin openings.
pub struct RecoveryRequest {
    body: Vec<u8>,
    signature: [u8; 64],
}
impl RecoveryRequest {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}
impl PrivateClaimRequest {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Public progress only. None of these phases mean ownership is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverPhase {
    PendingOffer,
    Authorized,
    ProposalFrozen,
    DraftFrozen,
    RecoveryPrepared,
    IssuanceFrozen,
    CertificateFrozen,
    Accepted,
}

/// Private secrets have no public getters, Debug or serialization implementation.
/// The advisory process lock serializes cooperating local processes only.
pub struct ReceiverJournal {
    directory: PathBuf,
    record: Record,
    policy: LineagePolicy,
    verified: Option<VerifiedOffer>,
    _lock: ProcessLock,
}

impl ReceiverJournal {
    /// Saves the exact native-checked offer and fresh independent recipient keys
    /// before any invitation reservation or claim. Does not verify proof authority.
    pub fn prepare(
        directory: &Path,
        invitation: &LocalInvitation,
        context: &OfferContext,
        encrypted: &[u8],
        policy: &LineagePolicy,
    ) -> Result<Self> {
        ensure!(
            !encrypted.is_empty() && encrypted.len() <= MAX_WIRE_BYTES,
            "recipient offer wire size"
        );
        let decrypted = invitation.decrypt_offer(context, encrypted)?;
        let address = invitation.public_address()?;
        let offer = UnverifiedOffer::decode(decrypted.plaintext(), &address, context, policy)?;
        let material = offer.recipient_material();
        let user = fresh_scalar();
        let session = SigningKey::from_bytes(&fresh_scalar())
            .map_err(|_| anyhow::anyhow!("recipient session generation"))?;
        let recipient_context = offer
            .handover()
            .handover
            .intent
            .with_session(session.verifying_key().to_bytes().into())?;
        let record = Record {
            schema: SCHEMA.into(),
            version: 3,
            invitation_id: invitation.invitation_id(),
            address: address.encode(),
            context: recipient_context,
            batch: None,
            offer: hex::encode(&*offer.encode()?),
            envelope: hex::encode(encrypted),
            user,
            capability: SigningKey::from_bytes(&fresh_scalar())?.to_bytes().into(),
            token: material.token,
            session: session.to_bytes().into(),
            delta: (scalar(&material.masked_share)? - scalar(&user)?)
                .to_bytes()
                .into(),
            delta_salt: nonzero_random(),
            server_salt: None,
            stage: Stage::PendingOffer {},
        };
        validate_record(&record, invitation, context, policy)?;
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        check_directory(directory)?;
        fs::File::open(
            directory
                .parent()
                .ok_or_else(|| anyhow::anyhow!("recipient directory parent"))?,
        )?
        .sync_all()?;
        let lock = acquire_lock(directory)?;
        let journal = Self {
            directory: directory.into(),
            record,
            policy: policy.clone(),
            verified: None,
            _lock: lock,
        };
        journal.persist()?;
        Ok(journal)
    }

    pub fn phase(&self) -> ReceiverPhase {
        match &self.record.stage {
            Stage::PendingOffer {} => ReceiverPhase::PendingOffer,
            Stage::Authorized {} => ReceiverPhase::Authorized,
            Stage::ProposalFrozen { .. } => ReceiverPhase::ProposalFrozen,
            Stage::DraftFrozen {
                recovery: Some(r), ..
            } if r.accepted => ReceiverPhase::Accepted,
            Stage::DraftFrozen {
                recovery: Some(r), ..
            } if r.certificate.is_some() => ReceiverPhase::CertificateFrozen,
            Stage::DraftFrozen {
                recovery: Some(r), ..
            } if r.issuance.is_some() => ReceiverPhase::IssuanceFrozen,
            Stage::DraftFrozen {
                recovery: Some(r), ..
            } if r.preparation.is_some() => ReceiverPhase::RecoveryPrepared,
            Stage::DraftFrozen { .. } => ReceiverPhase::DraftFrozen,
        }
    }

    pub fn context(&self) -> &TransferContext {
        &self.record.context
    }

    /// Check a local gross/direct-exit amount expectation against the
    /// native-validated decrypted activation input. This does not verify proof
    /// authority or authorize ownership.
    /// Call before reserving the invitation or making any signer request.
    pub fn require_expected_amount(&self, expected_amount: u64) -> Result<()> {
        ensure!(
            expected_amount > 0
                && self.native_offer()?.common_activation_input().amount == expected_amount,
            "received coin amount differs from expected amount"
        );
        Ok(())
    }

    pub(crate) fn deposit_amount(&self) -> Result<u64> {
        Ok(self.native_offer()?.common_activation_input().amount)
    }

    pub(crate) fn verified_deposit_amount(
        &self,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<u64> {
        self.verified_certificate(verifier, scratch)?;
        self.deposit_amount()
    }

    pub(crate) fn bind_batch(&mut self, manifest: &BatchManifest) -> Result<()> {
        manifest.index(&self.record.context, false)?;
        if let Some(saved) = &self.record.batch {
            ensure!(saved == manifest, "receiver batch manifest changed");
        } else {
            ensure!(
                !self.has_issuance_request(),
                "receiver issuance already frozen"
            );
            self.record.batch = Some(manifest.clone());
            self.persist()?;
        }
        Ok(())
    }
    pub(crate) fn batch(&self) -> Option<&BatchManifest> {
        self.record.batch.as_ref()
    }
    pub(crate) fn batch_revision(
        &self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        control: &Digest,
    ) -> Result<u64> {
        let (certificate, _) = self.verified_certificate(verifier, scratch)?;
        let probe = HeadProbe::new(
            &self.record.context,
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        let response = client.request(probe.request())?;
        Ok(probe
            .verify(
                response,
                control,
                &certificate.state,
                &self.claim_binding()?.next_capability,
                HeadPhase::Accepted,
            )?
            .revision())
    }

    pub(crate) fn require_cli_parameters(&self, offer_hash: &Digest, fee: u64) -> Result<()> {
        ensure!(
            hash(&[&decode_hex(&self.record.envelope, MAX_WIRE_BYTES)?]) == *offer_hash,
            "receiver metadata differs from saved encrypted offer"
        );
        if let Stage::DraftFrozen {
            recovery: Some(recovery),
            ..
        } = &self.record.stage
        {
            ensure!(
                recovery.fee == fee,
                "receiver metadata differs from frozen recovery fee"
            );
        }
        Ok(())
    }

    /// Native planned delays only; this does not establish current entitlement.
    pub fn recovery_delays(&self) -> Result<(RecoveryDelay, RecoveryDelay)> {
        let native = self.native_offer()?;
        let previous = RecoveryDelay::from_sequence(native.recipient_material().old_delay)?;
        let next = RecoveryDelay::from_sequence(
            previous
                .blocks()
                .checked_sub(self.policy.schedule.gap)
                .ok_or_else(|| anyhow::anyhow!("recipient recovery delay underflow"))?,
        )?;
        self.policy.schedule.check_transition(previous, next)?;
        Ok((previous, next))
    }

    fn server_salt(&self) -> Result<Digest> {
        self.record
            .server_salt
            .filter(|salt| *salt != [0; 32])
            .ok_or_else(|| anyhow::anyhow!("server-returned share salt is not frozen"))
    }

    fn offer_context(&self) -> OfferContext {
        OfferContext {
            deployment: self.record.context.deployment,
            coin: self.record.context.coin,
            operation: self.record.context.operation,
        }
    }
    fn native_offer(&self) -> Result<UnverifiedOffer> {
        let address = ReceivingAddress::decode(
            &self.record.address,
            AddressNetwork::Test,
            &self.record.context.deployment,
        )?;
        UnverifiedOffer::decode(
            &Zeroizing::new(decode_hex(&self.record.offer, MAX_OFFER_PLAINTEXT_BYTES)?),
            &address,
            &self.offer_context(),
            &self.policy,
        )
    }
    fn require_authorized(&self) -> Result<()> {
        ensure!(
            self.verified.is_some(),
            "recipient offer must be reverified after opening"
        );
        Ok(())
    }
    fn validate_draft(&self, server: &[u8; 64], refresh: &Digest) -> Result<()> {
        validate_draft(&self.record, &self.native_offer()?, server, refresh)
    }
}

fn nonzero_random() -> Digest {
    loop {
        let value = random32();
        if value != [0; 32] {
            return value;
        }
    }
}
fn fresh_scalar() -> Digest {
    loop {
        let value = random32();
        if scalar(&value).is_ok_and(|s| s != Scalar::ZERO) {
            return value;
        }
    }
}
#[cfg(test)]
#[path = "receiver/tests.rs"]
mod wire_tests;
