//! Create and reopen an exact sender journal without replacing keys.
use super::{
    FILE, LIMIT, Record, SenderDraft, SenderParameters, check_directory, check_file, lock,
};
use anyhow::{Context, Result, ensure};
use bitcoin::consensus::serialize;
use k256::schnorr::SigningKey;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use zark_protocol::address::{AddressNetwork, ReceivingAddress};
use zark_protocol::handoff::{Digest, OperationScope, TransferContext, recipient_claim_commitment};
use zark_protocol::lineage::LineagePolicy;
use zark_protocol::proof::PinnedVerifier;
use zark_protocol::{random_scalar, random32};
use zeroize::Zeroizing;

impl SenderDraft {
    pub(crate) fn create(
        directory: &Path,
        p: SenderParameters,
        capability: &Digest,
        recipient: &ReceivingAddress,
        policy: &LineagePolicy,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<Self> {
        ensure!(
            recipient.network() == AddressNetwork::Test
                && *recipient.deployment() == policy.deployment,
            "sender recipient deployment"
        );
        let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
        let operation = random32();
        let claim_salt = random32();
        let current = p.certificate.lineage_binding()?;
        let context = TransferContext {
            deployment: policy.deployment,
            coin: current.coin,
            previous_state: current.state,
            operation,
            recipient_claim: recipient_claim_commitment(
                &policy.deployment,
                &current.coin,
                &operation,
                &recipient.claim_key()[1..].try_into()?,
                &claim_salt,
            )?,
            session_auth: session.verifying_key().to_bytes().into(),
            start_revision: p.start_revision,
            scope: OperationScope::Single,
        };
        let record = Record {
            schema: "zark-sender-operation".into(),
            version: 3,
            context,
            recovery_context: p.recovery_context,
            recovery_path: p.recovery_path,
            backing: p.backing,
            activation_input: p.activation_input,
            activation: hex::encode(serialize(&p.activation)),
            certificate: hex::encode(&*p.certificate.encode_private()?),
            server_salt: p.server_salt,
            capability: *capability,
            token: loop {
                let token = random32();
                if token != [0; 32] {
                    break token;
                }
            },
            session: session.to_bytes().into(),
            recipient: recipient.encode(),
            claim_salt,
            masked_salt: random32(),
            bridge_salt: random32(),
            reservation: None,
            batch: None,
            mask: None,
            handover: None,
            offer: None,
            offer_digest: None,
            completion: None,
            cancellation: None,
            retired: false,
            aborted: false,
        };
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        check_directory(directory)?;
        fs::File::open(directory.parent().context("sender parent")?)?.sync_all()?;
        let lock = lock(directory)?;
        let draft = Self {
            directory: directory.into(),
            record,
            policy: policy.clone(),
            _lock: lock,
        };
        draft.verify_current(verifier, scratch)?;
        draft.persist()?;
        Ok(draft)
    }
    pub fn open(directory: &Path, policy: &LineagePolicy) -> Result<Self> {
        check_directory(directory)?;
        let lock = lock(directory)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(FILE))?;
        check_file(&file.metadata()?)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= LIMIT, "sender record size");
        let record: Record =
            serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid sender record"))?;
        let draft = Self {
            directory: directory.into(),
            record,
            policy: policy.clone(),
            _lock: lock,
        };
        draft.validate()?;
        zark_protocol::storage::sync_observed(&file, directory)?;
        Ok(draft)
    }
}
