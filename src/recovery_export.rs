//! Portable native recovery for the isolated private-handoff prototype.
//!
//! A file contains the signed common activation, the recipient's own signed
//! recovery, and its payout secret. No signer/prover/history is consulted. Offline
//! validation cannot establish live chain identity, unspentness, confirmation,
//! maturity, newest ownership, or the truth of unauthenticated deployment labels.
use crate::{
    bitcoin::{attach_signature, backup, cooperative_exit, sighash},
    types::Input,
};
use anyhow::{Context, Result, ensure};
use bitcoin::{
    OutPoint, Transaction, Txid,
    consensus::{deserialize, serialize},
    secp256k1::XOnlyPublicKey,
};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    str::FromStr,
};
use zark_protocol::{
    handoff::{Digest, PROTOCOL_VERSION, RecoveryDelay},
    random32,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SCHEMA: &str = "zark-portable-recovery";
pub const MAX_EXPORT_BYTES: u64 = 16_384;
const MAX_TRANSACTION_BYTES: usize = 1_024;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Prevout {
    txid: String,
    vout: u32,
    amount: u64,
    output_key: Digest,
}

impl Prevout {
    fn from_input(input: &Input) -> Result<Self> {
        Ok(Self {
            txid: input.txid.clone(),
            vout: input.vout,
            amount: input.amount,
            output_key: input.key()?,
        })
    }

    fn outpoint(&self) -> Result<OutPoint> {
        XOnlyPublicKey::from_slice(&self.output_key)
            .map_err(|_| anyhow::anyhow!("invalid portable recovery input key"))?;
        ensure!(
            (1..=2_100_000_000_000_000).contains(&self.amount),
            "portable recovery input amount out of range"
        );
        let txid = Txid::from_str(&self.txid)
            .map_err(|_| anyhow::anyhow!("invalid portable recovery input txid"))?;
        ensure!(txid.to_string() == self.txid, "noncanonical input txid");
        let outpoint = OutPoint::new(txid, self.vout);
        ensure!(!outpoint.is_null(), "null portable recovery input");
        Ok(outpoint)
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    protocol_version: u32,
    deployment: Digest,
    coin: Digest,
    activation_parent: Prevout,
    activation: String,
    backing: Prevout,
    recovery: String,
    fee_sat: u64,
    relative_blocks: u32,
    payout_secret: Digest,
}

struct Validated {
    activation: Transaction,
    recovery: Transaction,
    payout: SigningKey,
}

impl Record {
    fn validate(&self, deployment: &Digest, coin: &Digest) -> Result<Validated> {
        ensure!(
            // Portable recovery verifies fully signed Bitcoin transactions,
            // not application commitments. Preserve v9 exits without migrating
            // a wallet, changing its pins, or admitting a legacy proof suite.
            self.schema == SCHEMA
                && self.version == 1
                && matches!(self.protocol_version, 9 | PROTOCOL_VERSION),
            "unsupported portable recovery schema or version"
        );
        ensure!(
            *deployment != [0; 32]
                && *coin != [0; 32]
                && self.deployment == *deployment
                && self.coin == *coin,
            "portable recovery context mismatch"
        );
        let activation_input = self.activation_parent.outpoint()?;
        let backing_input = self.backing.outpoint()?;
        let activation = transaction(&self.activation)?;
        ensure!(
            self.backing.vout == 0 && activation.compute_txid() == backing_input.txid,
            "activation does not create this recovery backing"
        );
        let mut expected_activation = crate::bitcoin::activation(
            activation_input,
            self.activation_parent.amount,
            &[(self.backing.amount, self.backing.output_key)],
            0,
        )?;
        verify_exact_transaction(
            &activation,
            &mut expected_activation,
            self.activation_parent.amount,
            self.activation_parent.output_key,
        )?;
        let payout = SigningKey::from_bytes(&self.payout_secret)
            .map_err(|_| anyhow::anyhow!("invalid portable recovery payout key"))?;
        let normalized = Zeroizing::new(payout.to_bytes());
        ensure!(
            normalized[..] == self.payout_secret,
            "portable payout secret must use the even-Y BIP340 representative"
        );
        let payout_key: Digest = payout.verifying_key().to_bytes().into();
        let delay = RecoveryDelay::from_sequence(self.relative_blocks)?;
        let recovery = transaction(&self.recovery)?;
        let mut expected_recovery = backup(
            backing_input,
            self.backing.amount,
            self.fee_sat,
            payout_key,
            delay.blocks(),
        )?;
        verify_exact_transaction(
            &recovery,
            &mut expected_recovery,
            self.backing.amount,
            self.backing.output_key,
        )?;
        Ok(Validated {
            activation,
            recovery,
            payout,
        })
    }
}

fn transaction(encoded: &str) -> Result<Transaction> {
    ensure!(
        !encoded.is_empty()
            && encoded.len() <= MAX_TRANSACTION_BYTES * 2
            && encoded.len().is_multiple_of(2)
            && encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid portable recovery transaction encoding or size"
    );
    let tx: Transaction = deserialize(&hex::decode(encoded)?)
        .map_err(|_| anyhow::anyhow!("invalid portable recovery transaction"))?;
    ensure!(
        hex::encode(serialize(&tx)) == encoded,
        "noncanonical portable transaction"
    );
    Ok(tx)
}

fn verify_exact_transaction(
    signed: &Transaction,
    expected: &mut Transaction,
    input_amount: u64,
    input_key: Digest,
) -> Result<()> {
    ensure!(
        signed.input.len() == 1 && signed.input[0].witness.len() == 1,
        "portable recovery requires one key-path signature"
    );
    let signature: [u8; 64] = signed.input[0].witness[0]
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid portable recovery signature size"))?;
    attach_signature(expected, input_amount, input_key, &signature)
        .map_err(|_| anyhow::anyhow!("portable recovery signature does not verify"))?;
    ensure!(
        signed == expected,
        "portable recovery transaction differs from its exact parameters"
    );
    Ok(())
}

/// Validated private export. No public secret getter, Debug, Clone, or serde.
/// Returning Bitcoin transactions does not assert they are spendable yet.
pub struct PortableRecovery {
    record: Record,
}

impl PortableRecovery {
    /// The caller pins the authenticated deployment and coin independently of
    /// this untrusted file. These label checks do not authenticate a blockchain.
    pub fn read(path: &Path, deployment: &Digest, coin: &Digest) -> Result<Self> {
        ensure!(
            *deployment != [0; 32] && *coin != [0; 32],
            "zero expected recovery context"
        );
        check_parent(path)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        check_file(&file.metadata()?)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(MAX_EXPORT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_EXPORT_BYTES,
            "portable recovery file too large"
        );
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private portable recovery record"))?;
        record.validate(deployment, coin)?;
        Ok(Self { record })
    }

    /// Exact signed activation first, own signed recovery second. The caller
    /// must check parent identity, chain state, conflicts and BIP68 maturity.
    pub fn transactions(&self) -> Result<[Transaction; 2]> {
        let valid = self
            .record
            .validate(&self.record.deployment, &self.record.coin)?;
        Ok([valid.activation, valid.recovery])
    }

    pub fn relative_blocks(&self) -> u32 {
        self.record.relative_blocks
    }

    pub fn protocol_version(&self) -> u32 {
        self.record.protocol_version
    }

    /// Signs a bounded single-output spend of the recovered payout. The stored
    /// secret directly controls the raw P2TR output key; do not TapTweak it again.
    /// This performs no broadcast, node query, chain selection or maturity check.
    pub fn sign_payout_spend(
        &self,
        destination_output_key: Digest,
        fee: u64,
    ) -> Result<Transaction> {
        XOnlyPublicKey::from_slice(&destination_output_key)
            .map_err(|_| anyhow::anyhow!("invalid payout destination output key"))?;
        let valid = self
            .record
            .validate(&self.record.deployment, &self.record.coin)?;
        let amount = valid.recovery.output[0].value.to_sat();
        let payout_key: Digest = valid.payout.verifying_key().to_bytes().into();
        let mut spend = cooperative_exit(
            OutPoint::new(valid.recovery.compute_txid(), 0),
            amount,
            fee,
            destination_output_key,
        )?;
        let message = sighash(&spend, amount, payout_key)?;
        let aux = Zeroizing::new(random32());
        let signature = valid
            .payout
            .sign_prehash_with_aux_rand(&message, &aux)
            .map_err(|_| anyhow::anyhow!("payout signature failed"))?;
        attach_signature(&mut spend, amount, payout_key, &signature.to_bytes())?;
        Ok(spend)
    }
}

/// Available only to the validated complete receiver draft, not a public private
/// key export API. References avoid retaining a second long-lived secret copy.
pub(crate) struct CompletedRecovery<'a> {
    pub deployment: &'a Digest,
    pub coin: &'a Digest,
    pub activation_parent: &'a Input,
    pub activation: &'a Transaction,
    pub backing: &'a Input,
    pub recovery: &'a Transaction,
    pub fee_sat: u64,
    pub relative_blocks: u32,
    pub payout_secret: &'a Digest,
}

pub(crate) fn write_completed(path: &Path, material: CompletedRecovery<'_>) -> Result<()> {
    ensure!(
        material.activation_parent.deployment == hex::encode(material.deployment)
            && material.backing.deployment == hex::encode(material.deployment)
            && material.backing.id == hex::encode(material.coin),
        "export source context mismatch"
    );
    let payout = SigningKey::from_bytes(material.payout_secret)
        .map_err(|_| anyhow::anyhow!("invalid export payout key"))?;
    let record = Record {
        schema: SCHEMA.into(),
        version: 1,
        protocol_version: PROTOCOL_VERSION,
        deployment: *material.deployment,
        coin: *material.coin,
        activation_parent: Prevout::from_input(material.activation_parent)?,
        activation: hex::encode(serialize(material.activation)),
        backing: Prevout::from_input(material.backing)?,
        recovery: hex::encode(serialize(material.recovery)),
        fee_sat: material.fee_sat,
        relative_blocks: material.relative_blocks,
        payout_secret: payout.to_bytes().into(),
    };
    record.validate(material.deployment, material.coin)?;
    let bytes = Zeroizing::new(serde_json::to_vec(&record)?);
    ensure!(
        bytes.len() as u64 <= MAX_EXPORT_BYTES,
        "portable recovery export too large"
    );
    check_parent(path)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    check_file(&file.metadata()?)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().context("portable recovery parent")?)?.sync_all()?;
    Ok(())
}

fn check_parent(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path.parent().context("portable recovery parent")?)?;
    ensure!(
        metadata.is_dir()
            && metadata.permissions().mode() & 0o777 == 0o700
            && metadata.uid() == unsafe { libc::geteuid() },
        "portable recovery parent must be owned, private, and mode 0700"
    );
    Ok(())
}

fn check_file(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() },
        "portable recovery file must be owned, regular, private, and mode 0600"
    );
    Ok(())
}
