//! Private local receiving invitations, isolated from wallet and signer flows.
//!
//! One `invitation.json` is the authoritative record: the public address is
//! always rederived from it, never committed in a second file. An existing
//! directory without a valid committed record fails closed, including after a
//! crash between mkdir and the first rename. Reopening a committed record is
//! idempotent. Orphan atomic-write temporary files are never read or cleaned.
//!
//! A reservation only records a local, one-use offer selection. It proves no
//! authorization, signature, coin ownership, or successful receipt. No encryption
//! or claim-signature implementation is provided here. Mainnet remains disabled.
//!
//! Storage is trusted to this OS user. Permissions and advisory locking do not
//! authenticate a valid rewrite or restoration of an older record by that user.
//! Final live receipt must separately verify current signer authority and Bitcoin
//! backing. There is no local-file rollback-defense claim.
use anyhow::{Context, Result, ensure};
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint, schnorr::SigningKey};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    hash,
    local::ProcessLock,
    random32,
    storage::atomic_write,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SCHEMA: &str = "zark-local-invitation";
const RECORD_VERSION: u32 = 1;
const RECORD_FILE: &str = "invitation.json";
const LOCK_FILE: &str = "invitation.lock";
const MAX_RECORD_BYTES: u64 = 8192;
pub const MAX_OFFER_BYTES: usize = 2_000_000;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum StoredState {
    // An empty struct variant makes deny_unknown_fields reject extra contents;
    // serde's internally tagged unit variant would silently ignore those fields.
    Fresh {},
    Reserved {
        coin: [u8; 32],
        operation: [u8; 32],
        offer_digest: [u8; 32],
    },
}

// Private storage serialization only: neither this type nor its secrets are
// returned. Serialization buffers and retained secret bytes are zeroized on drop.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct PrivateRecord {
    schema: String,
    version: u32,
    network: String,
    deployment: [u8; 32],
    invitation_id: [u8; 32],
    envelope_secret: [u8; 32],
    claim_secret: [u8; 32],
    state: StoredState,
}

impl PrivateRecord {
    fn address(&self) -> Result<ReceivingAddress> {
        ensure!(
            self.schema == SCHEMA && self.version == RECORD_VERSION && self.network == "test",
            "unsupported private invitation schema, version, or network"
        );
        ensure!(
            self.invitation_id != [0; 32],
            "invalid invitation identifier"
        );
        let envelope = SecretKey::from_slice(&self.envelope_secret)
            .map_err(|_| anyhow::anyhow!("invalid private envelope key"))?;
        let claim = SigningKey::from_bytes(&self.claim_secret)
            .map_err(|_| anyhow::anyhow!("invalid private claim key"))?;
        let normalized = Zeroizing::new(claim.to_bytes());
        ensure!(
            normalized[..] == self.claim_secret,
            "noncanonical private claim key"
        );
        let envelope_public = envelope.public_key().to_encoded_point(true);
        let mut claim_public = [0; 33];
        claim_public[0] = 2;
        claim_public[1..].copy_from_slice(&claim.verifying_key().to_bytes());
        if let StoredState::Reserved {
            coin,
            operation,
            offer_digest,
        } = &self.state
        {
            ensure!(
                *coin != [0; 32] && *operation != [0; 32] && *offer_digest != [0; 32],
                "invalid stored invitation reservation"
            );
        }
        ReceivingAddress::new(
            AddressNetwork::Test,
            self.deployment,
            envelope_public.as_bytes().try_into()?,
            claim_public,
        )
    }
}

/// Public local state only. `Reserved` does not mean a receipt was accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationStatus {
    Fresh,
    Reserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationResult {
    Reserved,
    AlreadyReserved,
}

/// Decrypted peer bytes, never proof of sender identity, receipt, or ownership.
/// Decryption does not reserve the invitation. The caller must validate the
/// transfer authorization before explicitly reserving the exact wire bytes.
/// Payload memory is zeroized when this value is dropped.
pub struct DecryptedOffer {
    plaintext: Zeroizing<Vec<u8>>,
}

impl DecryptedOffer {
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

/// Holds the existing advisory process lock for its lifetime; not Send or Sync.
/// No private secret accessors, Debug, Display, or public serialization exist.
pub struct LocalInvitation {
    directory: PathBuf,
    record: PrivateRecord,
    _lock: ProcessLock,
}

impl LocalInvitation {
    /// Creates a new private directory, or reopens the same committed invitation.
    /// The parent must already exist. Existing directories without a committed
    /// record are not silently regenerated. Creation never enables mainnet.
    pub fn create(directory: &Path, network: AddressNetwork, deployment: [u8; 32]) -> Result<Self> {
        check_context(network, &deployment)?;
        let created = match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error.into()),
        };
        check_directory(directory)?;
        let lock = lock_directory(directory)?;
        if !created {
            return Self::load_locked(directory, deployment, lock);
        }
        // Make the directory entry durable before the first record can be
        // acknowledged. A crash here leaves an explicit incomplete directory.
        fs::File::open(directory.parent().context("invitation parent directory")?)?.sync_all()?;
        let envelope = random_secret();
        let mut claim_seed = random_secret();
        let mut claim = SigningKey::from_bytes(claim_seed.as_ref())?;
        let mut normalized_claim = Zeroizing::new(claim.to_bytes());
        // Independent draws can theoretically yield equal/negated public keys.
        while envelope[0..] == normalized_claim[..]
            || SecretKey::from_slice(envelope.as_ref())?
                .public_key()
                .to_encoded_point(true)
                .as_bytes()[1..]
                == claim.verifying_key().to_bytes()[..]
        {
            claim_seed = random_secret();
            claim = SigningKey::from_bytes(claim_seed.as_ref())?;
            normalized_claim = Zeroizing::new(claim.to_bytes());
        }
        let mut invitation_id = random32();
        while invitation_id == [0; 32] {
            invitation_id = random32();
        }
        let invitation = Self {
            directory: directory.into(),
            record: PrivateRecord {
                schema: SCHEMA.into(),
                version: RECORD_VERSION,
                network: "test".into(),
                deployment,
                invitation_id,
                envelope_secret: *envelope,
                claim_secret: normalized_claim[..].try_into()?,
                state: StoredState::Fresh {},
            },
            _lock: lock,
        };
        invitation.record.address()?;
        invitation.persist()?;
        Ok(invitation)
    }

    /// Opens only a committed invitation; never generates replacement keys.
    pub fn open(directory: &Path, network: AddressNetwork, deployment: [u8; 32]) -> Result<Self> {
        check_context(network, &deployment)?;
        check_directory(directory)?;
        let lock = lock_directory(directory)?;
        Self::load_locked(directory, deployment, lock)
    }

    fn load_locked(directory: &Path, deployment: [u8; 32], lock: ProcessLock) -> Result<Self> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            // O_NONBLOCK has no effect on regular files; a substituted FIFO
            // must reach the regular-file check instead of blocking at open.
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(RECORD_FILE))
            .context("committed private invitation is missing or unreadable")?;
        check_private_file(&file.metadata()?)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "private invitation record too large"
        );
        let record: PrivateRecord = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private invitation record"))?;
        ensure!(
            record.deployment == deployment,
            "invitation deployment mismatch"
        );
        record.address()?;
        // Retrying after an uncertain rename/fsync outcome acknowledges only a
        // validated committed record and first makes its durability explicit.
        zark_protocol::storage::sync_observed(&file, directory)?;
        Ok(Self {
            directory: directory.into(),
            record,
            _lock: lock,
        })
    }

    fn persist(&self) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "private invitation record too large"
        );
        atomic_write(&self.directory.join(RECORD_FILE), &bytes)?;
        check_private_file(&fs::symlink_metadata(self.directory.join(RECORD_FILE))?)
    }

    /// Public only; explicitly rendered by the caller for peer delivery.
    pub fn public_address(&self) -> Result<ReceivingAddress> {
        self.record.address()
    }

    pub fn invitation_id(&self) -> [u8; 32] {
        self.record.invitation_id
    }

    /// Registration proves receiving-key possession without disclosing its secret.
    pub fn mail_registration(&self, token_hash: &str, ttl: u64) -> Result<String> {
        let digest =
            zark_protocol::mail::registration_digest(&self.public_address()?, token_hash, ttl)?;
        let key = SigningKey::from_bytes(&self.record.claim_secret)?;
        Ok(hex::encode(key.sign_raw(&digest, &random32())?.to_bytes()))
    }

    pub fn sign_peer_message(
        &self,
        recipient: &str,
        message: &serde_json::Value,
    ) -> Result<String> {
        let digest =
            zark_protocol::mail::peer_message_digest(&self.public_address()?, recipient, message)?;
        let key = SigningKey::from_bytes(&self.record.claim_secret)?;
        Ok(hex::encode(key.sign_raw(&digest, &random32())?.to_bytes()))
    }

    /// Delivery decryption never reserves an invitation or establishes ownership.
    pub fn decrypt_message(&self, id: &str, ciphertext: &str) -> Result<Zeroizing<Vec<u8>>> {
        crate::envelope::decrypt_message(
            &self.public_address()?,
            id,
            &self.record.envelope_secret,
            ciphertext,
        )
    }

    pub fn status(&self) -> InvitationStatus {
        match &self.record.state {
            StoredState::Fresh {} => InvitationStatus::Fresh,
            StoredState::Reserved { .. } => InvitationStatus::Reserved,
        }
    }

    /// Authenticates ciphertext integrity and decrypts without changing storage.
    /// This does not authenticate sender identity/ownership: anyone holding the
    /// address may encrypt an offer. Validate the transfer authorization before
    /// separately calling reserve with this exact encrypted wire byte sequence.
    pub fn decrypt_offer(
        &self,
        context: &crate::envelope::OfferContext,
        envelope: &[u8],
    ) -> Result<DecryptedOffer> {
        let address = self.public_address()?;
        let plaintext = crate::envelope::decrypt_offer(
            &address,
            context,
            &self.record.envelope_secret,
            envelope,
        )?;
        Ok(DecryptedOffer { plaintext })
    }

    /// Decrypts, checks this invitation's recipient claim and native Bitcoin
    /// context, verifies the actual pinned outer handover, then reserves the
    /// exact encrypted bytes. Reservation is not receipt acceptance. The wallet
    /// must separately require fresh signer-head and live-chain safety checks
    /// before acting on current ownership or completing a received transfer.
    pub fn verify_and_reserve_offer(
        &mut self,
        context: &crate::envelope::OfferContext,
        envelope: &[u8],
        policy: &zark_protocol::lineage::LineagePolicy,
        verifier: &zark_protocol::proof::PinnedVerifier,
        scratch: &Path,
    ) -> Result<(crate::offer::VerifiedOffer, ReservationResult)> {
        let decrypted = self.decrypt_offer(context, envelope)?;
        let offer = crate::offer::UnverifiedOffer::decode(
            decrypted.plaintext(),
            &self.public_address()?,
            context,
            policy,
        )?;
        let verified = offer.verify(verifier, scratch)?;
        let reserved = self.reserve(context.coin, context.operation, envelope)?;
        Ok((verified, reserved))
    }

    /// Writes the authorized journal's actor-local claim witness. The claim key
    /// remains invitation-owned and is never returned as a raw public value.
    pub fn write_receiver_authorization_witness(
        &self,
        journal: &crate::receiver::ReceiverJournal,
        verifier: &zark_protocol::proof::PinnedVerifier,
        scratch: &Path,
        path: &Path,
    ) -> Result<()> {
        journal.write_receiver_witness(
            &self.record.invitation_id,
            &self.public_address()?,
            &self.record.claim_secret,
            verifier,
            scratch,
            path,
        )
    }

    /// Locally reserves exactly this coin/operation/offer byte sequence. This is
    /// not receipt acceptance. Bound bytes before hashing; do not JSON-normalize
    /// an altered retry into an accepted one. No reservation is ever released.
    pub fn reserve(
        &mut self,
        coin: [u8; 32],
        operation: [u8; 32],
        offer: &[u8],
    ) -> Result<ReservationResult> {
        ensure!(
            coin != [0; 32] && operation != [0; 32],
            "zero coin or operation identifier"
        );
        ensure!(
            !offer.is_empty() && offer.len() <= MAX_OFFER_BYTES,
            "invalid offer size"
        );
        let address = self.public_address()?.encode();
        let digest = hash(&[
            b"ZARK_LOCAL_INVITATION_OFFER_V1",
            &self.record.deployment,
            &self.record.invitation_id,
            &(address.len() as u32).to_le_bytes(),
            address.as_bytes(),
            &coin,
            &operation,
            &(offer.len() as u64).to_le_bytes(),
            offer,
        ]);
        let outcome = match &self.record.state {
            StoredState::Fresh {} => ReservationResult::Reserved,
            StoredState::Reserved {
                coin: saved_coin,
                operation: saved_operation,
                offer_digest,
            } => {
                ensure!(
                    *saved_coin == coin && *saved_operation == operation && *offer_digest == digest,
                    "invitation is already reserved for a different offer"
                );
                ReservationResult::AlreadyReserved
            }
        };
        self.record.state = StoredState::Reserved {
            coin,
            operation,
            offer_digest: digest,
        };
        // Keep the in-memory reservation on any uncertain write failure. An
        // identical retry persists it again; a competing offer cannot replace it.
        self.persist()?;
        Ok(outcome)
    }
}

fn check_context(network: AddressNetwork, deployment: &[u8; 32]) -> Result<()> {
    ensure!(
        network == AddressNetwork::Test,
        "mainnet invitations are not enabled"
    );
    ensure!(*deployment != [0; 32], "zero invitation deployment");
    Ok(())
}

fn check_directory(directory: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir()
            && metadata.permissions().mode() & 0o777 == 0o700
            && metadata.uid() == unsafe { libc::geteuid() },
        "invitation directory must be owned by this user with mode 0700; no symlinks"
    );
    Ok(())
}

fn check_private_file(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() },
        "invitation file must be private, regular, singly linked, and mode 0600"
    );
    Ok(())
}

fn lock_directory(directory: &Path) -> Result<ProcessLock> {
    let path = directory.join(LOCK_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => check_private_file(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let lock = ProcessLock::acquire(&path)?;
    check_private_file(&fs::symlink_metadata(path)?)?;
    Ok(lock)
}

fn random_secret() -> Zeroizing<[u8; 32]> {
    loop {
        let bytes = Zeroizing::new(random32());
        if SecretKey::from_slice(bytes.as_ref()).is_ok() {
            return bytes;
        }
    }
}
