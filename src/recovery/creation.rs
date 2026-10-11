//! Create or reopen a private recovery draft and preserve its process lock.
use super::{
    DraftParameters, MAX_RECORD_BYTES, OriginRecoveryParameters, RECORD_FILE, RECORD_VERSION,
    Record, RecoveryDraft, RecoveryMode, RecoveryParameters, SCHEMA, Stage, acquire_lock,
    check_directory, check_file, funding_opening, nonzero_random,
};
use crate::bitcoin::backup;
use crate::outgoing::{initialize_outgoing, new_staging_path};
use crate::signing::Blinding;
use anyhow::{Context, Result, ensure};
use bitcoin::consensus::serialize;
use bitcoin::{OutPoint, Txid};
use k256::schnorr::SigningKey;
use std::cell::RefCell;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::str::FromStr;
use zark_protocol::handoff::{
    Digest, TransferContext, origin_previous_capability, origin_refresh_commitment,
};
use zark_protocol::storage::atomic_write;
use zeroize::Zeroizing;

impl RecoveryDraft {
    /// Creates a new draft directory. On uncertain creation, reopen the committed
    /// draft explicitly. Existing or partial directories are never overwritten.
    pub fn create(
        directory: &Path,
        parameters: RecoveryParameters,
        user_secret: &Digest,
        payout_secret: &Digest,
    ) -> Result<Self> {
        Self::create_prepared(
            directory,
            DraftParameters {
                context: parameters.context,
                backing: parameters.backing,
                activation_input: parameters.activation_input,
                activation: parameters.activation,
                draft_server: parameters.draft_server,
                refresh_commitment: parameters.refresh_commitment,
                previous_capability: parameters.previous_capability,
                next_capability: parameters.next_capability,
                schedule: parameters.schedule,
                next_delay: parameters.next_delay,
                fee: parameters.fee,
                mode: RecoveryMode::Transfer {
                    previous_delay: parameters.previous_delay.blocks(),
                },
            },
            user_secret,
            payout_secret,
        )
    }

    /// Constructs only an initial recovery, with exact bootstrap sentinels and
    /// policy initial delay. Origin refresh is derived from the actual common
    /// funding and server point. This verifies no ownership or allocation proof.
    /// A committed origin record reopens through `open` with its persisted mode.
    pub fn create_origin(
        directory: &Path,
        parameters: OriginRecoveryParameters,
        user_secret: &Digest,
        payout_secret: &Digest,
    ) -> Result<Self> {
        Self::create_origin_with_mode(
            directory,
            parameters,
            user_secret,
            payout_secret,
            RecoveryMode::Origin {},
        )
    }

    /// Safe bootstrap only: the exact parent activation is still unsigned while
    /// this initial recovery is prepared and completed. Ordinary origins and
    /// transfers continue to require a fully signed activation at construction.
    pub fn create_bootstrap_origin(
        directory: &Path,
        parameters: OriginRecoveryParameters,
        user_secret: &Digest,
        payout_secret: &Digest,
    ) -> Result<Self> {
        Self::create_origin_with_mode(
            directory,
            parameters,
            user_secret,
            payout_secret,
            RecoveryMode::BootstrapOriginPending {},
        )
    }

    pub(super) fn create_origin_with_mode(
        directory: &Path,
        parameters: OriginRecoveryParameters,
        user_secret: &Digest,
        payout_secret: &Digest,
        mode: RecoveryMode,
    ) -> Result<Self> {
        let funding = funding_opening(&parameters.context, &parameters.backing)?.commitment()?;
        let refresh_commitment =
            origin_refresh_commitment(&parameters.context, &funding, &parameters.draft_server)?;
        let previous_capability =
            origin_previous_capability(&parameters.context.deployment, &parameters.context.coin)?;
        let next_delay = parameters.schedule.delay_after(0)?;
        Self::create_prepared(
            directory,
            DraftParameters {
                context: parameters.context,
                backing: parameters.backing,
                activation_input: parameters.activation_input,
                activation: parameters.activation,
                draft_server: parameters.draft_server,
                refresh_commitment,
                previous_capability,
                next_capability: parameters.initial_capability,
                schedule: parameters.schedule,
                next_delay,
                fee: parameters.fee,
                mode,
            },
            user_secret,
            payout_secret,
        )
    }

    pub(super) fn create_prepared(
        directory: &Path,
        parameters: DraftParameters,
        user_secret: &Digest,
        payout_secret: &Digest,
    ) -> Result<Self> {
        let payout = SigningKey::from_bytes(payout_secret)
            .map_err(|_| anyhow::anyhow!("invalid recovery payout secret"))?;
        let unsigned = backup(
            OutPoint::new(
                Txid::from_str(&parameters.backing.txid)?,
                parameters.backing.vout,
            ),
            parameters.backing.amount,
            parameters.fee,
            payout.verifying_key().to_bytes().into(),
            parameters.next_delay.blocks(),
        )?;
        let blind = Blinding::default();
        let record = Record {
            schema: SCHEMA.into(),
            version: RECORD_VERSION,
            mode: parameters.mode,
            context: parameters.context,
            backing: parameters.backing,
            activation_input: parameters.activation_input,
            activation: hex::encode(serialize(&parameters.activation)),
            draft_server: hex::encode(parameters.draft_server),
            refresh_commitment: parameters.refresh_commitment,
            previous_capability: parameters.previous_capability,
            next_capability: parameters.next_capability,
            initial: parameters.schedule.initial,
            gap: parameters.schedule.gap,
            margin: parameters.schedule.margin,
            next_delay: parameters.next_delay.blocks(),
            fee: parameters.fee,
            user_secret: *user_secret,
            payout_secret: *payout_secret,
            alpha: blind.alpha.to_bytes().into(),
            beta: blind.beta.to_bytes().into(),
            backup_salt: nonzero_random(),
            nonce_salt: nonzero_random(),
            unsigned_transaction: hex::encode(serialize(&unsigned)),
            state: Stage::Prepared {},
        };
        record.validate()?;
        let parent = directory.parent().context("recovery draft parent")?;
        check_directory(parent)?;
        let destination = parent
            .canonicalize()?
            .join(directory.file_name().context("recovery draft name")?);
        ensure!(
            fs::symlink_metadata(&destination)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "recovery draft already exists; reopen its exact saved state"
        );
        let context = record.context.clone();
        let staging = new_staging_path(&destination)?;
        // The constructor cannot expose commitments or send requests before it
        // returns. An interrupted unpublished attempt may therefore be retained
        // privately and replaced by a fresh attempt. Once the final directory
        // appears it contains the complete durable record; never replace it.
        initialize_outgoing(
            &destination,
            &staging,
            |attempt| {
                fs::DirBuilder::new().mode(0o700).create(attempt)?;
                check_directory(attempt)?;
                let lock = acquire_lock(attempt)?;
                let draft = Self {
                    directory: attempt.into(),
                    record,
                    validated: Default::default(),
                    _lock: lock,
                };
                draft.persist()?;
                Ok(draft)
            },
            |published| Self::open(published, &context),
        )
    }

    pub fn open(directory: &Path, context: &TransferContext) -> Result<Self> {
        let _timing = zark_protocol::timing::Span::new(zark_protocol::timing::Phase::RecoveryOpen);
        check_directory(directory)?;
        let lock = acquire_lock(directory)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(RECORD_FILE))?;
        check_file(&file.metadata()?)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "recovery draft record too large"
        );
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private recovery draft"))?;
        ensure!(
            record.context == *context,
            "recovery draft context mismatch"
        );
        let native = record.validate()?;
        zark_protocol::storage::sync_observed(&file, directory)?;
        Ok(Self {
            directory: directory.into(),
            validated: RefCell::new(Some((record.digest()?, native))),
            record,
            _lock: lock,
        })
    }

    pub(super) fn persist(&self) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "recovery draft record too large"
        );
        atomic_write(&self.directory.join(RECORD_FILE), &bytes)?;
        check_file(&fs::symlink_metadata(self.directory.join(RECORD_FILE))?)
    }
}
