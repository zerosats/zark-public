//! Durable records, restart validation and exact-request persistence.
use super::claim::{claim_binding, validate_draft};
use super::response::checked_recovery_request;
use super::{
    LOCK, MAX_RECORD_BYTES, MAX_WIRE_BYTES, PrivateClaimRequest, RECORD, ReceiverJournal, Record,
    RequestRecord, SCHEMA, Stage,
};
use crate::envelope::OfferContext;
use crate::invitation::LocalInvitation;
use crate::offer::{MAX_OFFER_PLAINTEXT_BYTES, UnverifiedOffer};
use anyhow::{Result, ensure};
use k256::Scalar;
use k256::schnorr::SigningKey;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zark_protocol::handoff::ClaimBinding;
use zark_protocol::lineage::LineagePolicy;
use zark_protocol::local::ProcessLock;
use zark_protocol::scalar;
use zark_protocol::session::Purpose;
use zark_protocol::storage::atomic_write;
use zark_protocol::wire::{Command, MAX_BODY, Request};
use zeroize::Zeroizing;

impl ReceiverJournal {
    pub fn open(
        directory: &Path,
        invitation: &LocalInvitation,
        context: &OfferContext,
        policy: &LineagePolicy,
    ) -> Result<Self> {
        check_directory(directory)?;
        let lock = acquire_lock(directory)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(RECORD))?;
        check_file(&file.metadata()?)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "recipient record size"
        );
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private recipient record"))?;
        validate_record(&record, invitation, context, policy)?;
        zark_protocol::storage::sync_observed(&file, directory)?;
        let journal = Self {
            directory: directory.into(),
            record,
            policy: policy.clone(),
            verified: None,
            _lock: lock,
        };
        journal.validate_saved_recovery()?;
        Ok(journal)
    }

    pub(super) fn sign_body(&self, purpose: Purpose, body: &[u8]) -> Result<RequestRecord> {
        let key = SigningKey::from_bytes(&self.record.session)?;
        let command = Command::decode(body)?;
        ensure!(command.purpose() == purpose, "wrong recipient command role");
        let request = Request::sign(self.record.context.clone(), command, &key)?;
        Ok(RequestRecord {
            body: hex::encode(body),
            digest: request.digest()?,
            signature: hex::encode(request.signature),
        })
    }

    pub(super) fn validate_saved_recovery(&self) -> Result<()> {
        let path = self.directory.join("own-recovery");
        let metadata = fs::symlink_metadata(&path);
        let recovery = match self.recovery_record() {
            Ok(record) => record,
            Err(_) => {
                ensure!(
                    metadata.is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "orphan recipient recovery directory"
                );
                return Ok(());
            }
        };
        let payout = SigningKey::from_bytes(&recovery.payout)?;
        ensure!(
            payout.to_bytes()[..] == recovery.payout
                && (1..=10_000).contains(&recovery.fee)
                && self.native_offer()?.common_backing().amount > recovery.fee + 330,
            "invalid saved recipient recovery settings"
        );
        match metadata {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    recovery.preparation.is_none()
                        && recovery.issuance.is_none()
                        && recovery.certificate.is_none()
                        && recovery.acceptance.is_none()
                        && !recovery.accepted
                        && recovery.outgoing.is_none(),
                    "committed recipient recovery is missing"
                );
                return Ok(());
            }
            Err(e) => return Err(e.into()),
            Ok(_) => (),
        }
        let draft = self.open_recovery()?;
        if let Some(preparation) = &recovery.preparation {
            checked_recovery_request(
                &self.record.context,
                Purpose::RecoveryPreparation,
                preparation,
                &self.preparation_body(draft.commitments()?)?,
            )?;
        }
        if let Some(issuance) = &recovery.issuance {
            ensure!(
                recovery.preparation.is_some(),
                "issuance before preparation"
            );
            self.decode_issuance(issuance, &draft.signing_binding()?)?;
        }
        // Certificate and acknowledgement validation each reopen the recovery
        // draft. Release this exclusive guard before those independent checks.
        drop(draft);
        if let Some(certificate) = &recovery.certificate {
            ensure!(recovery.issuance.is_some(), "certificate before issuance");
            ensure!(
                certificate.encoded == hex::encode(&*self.build_certificate()?.encode_private()?),
                "saved recipient certificate mismatch"
            );
        }
        if let Some(acceptance) = &recovery.acceptance {
            recovery
                .certificate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("acceptance before current certificate"))?;
            let body = self.acknowledgement_command()?.body()?;
            checked_recovery_request(
                &self.record.context,
                Purpose::TransferAcknowledgement,
                acceptance,
                &body,
            )?;
        }
        ensure!(
            !recovery.accepted || recovery.acceptance.is_some(),
            "local receipt without acceptance request"
        );
        ensure!(
            recovery.outgoing.is_none() || recovery.accepted,
            "outgoing operation before accepted receipt"
        );
        // Proof validity is re-established by the corresponding public methods;
        // syntactically valid private records never restore runtime authority.
        Ok(())
    }

    pub(super) fn persist(&self) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "recipient record size"
        );
        atomic_write(&self.directory.join(RECORD), &bytes)?;
        check_file(&fs::symlink_metadata(self.directory.join(RECORD))?)
    }
}

pub(super) fn validate_record(
    record: &Record,
    invitation: &LocalInvitation,
    context: &OfferContext,
    policy: &LineagePolicy,
) -> Result<UnverifiedOffer> {
    ensure!(
        record.schema == SCHEMA && record.version == 3,
        "unsupported recipient record"
    );
    ensure!(
        record.invitation_id == invitation.invitation_id()
            && record.address == invitation.public_address()?.encode(),
        "recipient invitation mismatch"
    );
    ensure!(
        record.context.deployment == context.deployment
            && record.context.coin == context.coin
            && record.context.operation == context.operation,
        "recipient operation mismatch"
    );
    if let Some(manifest) = &record.batch {
        manifest.index(&record.context, false)?;
    }
    let address = invitation.public_address()?;
    let bytes = Zeroizing::new(decode_hex(&record.offer, MAX_OFFER_PLAINTEXT_BYTES)?);
    let native = UnverifiedOffer::decode(&bytes, &address, context, policy)?;
    let encrypted = Zeroizing::new(decode_hex(&record.envelope, MAX_WIRE_BYTES)?);
    let decrypted = invitation.decrypt_offer(context, &encrypted)?;
    let decoded = UnverifiedOffer::decode(decrypted.plaintext(), &address, context, policy)?;
    ensure!(
        *decoded.encode()? == *native.encode()?,
        "recipient saved offer differs from exact encrypted offer"
    );
    let session = SigningKey::from_bytes(&record.session)
        .map_err(|_| anyhow::anyhow!("invalid saved session"))?;
    ensure!(
        session.to_bytes()[..] == record.session
            && session.verifying_key().to_bytes()[..] == record.context.session_auth,
        "noncanonical recipient session"
    );
    ensure!(
        record.context
            == native
                .handover()
                .handover
                .intent
                .with_session(record.context.session_auth)?,
        "recipient intent mismatch"
    );
    ensure!(
        scalar(&record.user)? != Scalar::ZERO && record.capability != [0; 32],
        "invalid recipient secret"
    );
    let material = native.recipient_material();
    ensure!(
        record.token == material.token,
        "recipient draft token changed"
    );
    ensure!(
        scalar(&material.masked_share)? == scalar(&record.user)? + scalar(&record.delta)?,
        "recipient delta relation"
    );
    let binding = claim_binding(record, &native)?;
    ensure!(
        match &record.stage {
            Stage::DraftFrozen { .. } => record.server_salt.is_some_and(|salt| salt != [0; 32]),
            _ => record.server_salt.is_none(),
        },
        "invalid recipient server salt phase"
    );
    ensure!(
        binding.next_capability != native.handover().handover.previous_capability,
        "recipient capability must rotate"
    );
    match &record.stage {
        Stage::PendingOffer {} | Stage::Authorized {} => (),
        Stage::ProposalFrozen { request } => {
            validated_request(record, &binding, request)?;
        }
        Stage::DraftFrozen {
            request,
            server,
            refresh,
            ..
        } => {
            validated_request(record, &binding, request)?;
            validate_draft(
                record,
                &native,
                &decode_hex(server, 64)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("draft point length"))?,
                refresh,
            )?;
        }
    }
    Ok(native)
}

pub(super) fn validated_request(
    record: &Record,
    binding: &ClaimBinding,
    request: &RequestRecord,
) -> Result<PrivateClaimRequest> {
    let body = Zeroizing::new(decode_hex(&request.body, MAX_BODY)?);
    let command = Command::decode(&body)?;
    let Command::ProposeRecipient {
        statement,
        token,
        delta,
        delta_salt,
        ..
    } = &command
    else {
        anyhow::bail!("saved command is not claim")
    };
    ensure!(
        *statement == binding.encode()?
            && *token == record.token
            && *delta == record.delta
            && *delta_salt == record.delta_salt,
        "frozen recipient claim mismatch"
    );
    ensure!(
        request.digest == command.digest(&record.context)?,
        "recipient request digest mismatch"
    );
    let signature: [u8; 64] = decode_hex(&request.signature, 64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("request signature length"))?;
    Request::from_body(record.context.clone(), &body, signature)?;
    Ok(PrivateClaimRequest { body, signature })
}

pub(super) fn decode_hex(value: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        !value.is_empty()
            && value.len() <= 2 * max
            && value.len().is_multiple_of(2)
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "recipient field encoding"
    );
    Ok(hex::decode(value)?)
}

pub(super) fn check_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir()
            && m.permissions().mode() & 0o777 == 0o700
            && m.uid() == unsafe { libc::geteuid() },
        "recipient directory must be private and owned"
    );
    Ok(())
}

pub(super) fn check_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.permissions().mode() & 0o777 == 0o600
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() },
        "recipient file must be private, owned and singly linked"
    );
    Ok(())
}

pub(super) fn acquire_lock(directory: &Path) -> Result<ProcessLock> {
    let path = directory.join(LOCK);
    match fs::symlink_metadata(&path) {
        Ok(m) => check_file(&m)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    };
    let lock = ProcessLock::acquire(&path)?;
    check_file(&fs::symlink_metadata(&path)?)?;
    Ok(lock)
}

pub(super) fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("witness parent"))?;
    check_directory(parent)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    check_file(&file.metadata()?)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) fn canonical_new_operation_path(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "outgoing operation path must be absolute"
    );
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("outgoing operation parent"))?
        .canonicalize()?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("outgoing operation name"))?;
    Ok(parent.join(name))
}
