//! Owner-local joint-parent activation material for the bootstrap.
//! This never broadcasts funding or grants signer allocation authority. The
//! higher-level flow must save the initial active recovery before requesting
//! activation release, and save both before broadcasting the external deposit.
use crate::{
    bitcoin::{attach_signature, sighash},
    signing::{Blinding, FundingKey},
    types::Input,
};
use anyhow::{Context, Result, ensure};
use bitcoin::{
    OutPoint, Transaction, Txid,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zark_protocol::{
    bootstrap::{self, BootstrapBinding},
    handoff::{Digest, FundingOpening, TransferContext, capability_commitment},
    local::ProcessLock,
    point, point_bytes, random32, scalar,
    storage::atomic_write,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const FILE: &str = "bootstrap-draft.json";
const LIMIT: usize = 24_000;

pub struct BootstrapParameters {
    pub context: TransferContext,
    /// The outpoint of the fully signed, still-unbroadcast external deposit.
    pub parent: OutPoint,
    pub amount: u64,
    pub fee: u64,
    pub parent_server: [u8; 64],
    pub active_server: [u8; 64],
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Stage {
    Prepared {},
    NonceBound {
        nonce: String,
        binding: String,
    },
    Complete {
        nonce: String,
        binding: String,
        partial: Digest,
        activation: String,
    },
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    #[zeroize(skip)]
    context: TransferContext,
    txid: Digest,
    vout: u32,
    amount: u64,
    fee: u64,
    parent_server: String,
    active_server: String,
    parent_user: Digest,
    active_user: Digest,
    capability: Digest,
    parent_salt: Digest,
    active_salt: Digest,
    alpha: Digest,
    beta: Digest,
    nonce_salt: Digest,
    state: Stage,
}

struct Native {
    parent: FundingOpening,
    active: FundingOpening,
    parent_key: FundingKey,
    blind: Blinding,
    activation: Transaction,
    capability: Digest,
    blinding: Digest,
}

impl Record {
    fn native(&self) -> Result<Native> {
        ensure!(
            self.schema == "zark-bootstrap" && self.version == 2,
            "unsupported bootstrap record"
        );
        bootstrap::validate_context(&self.context)?;
        let ps = hex::decode(&self.parent_server)?;
        let active_server = hex::decode(&self.active_server)?;
        ensure!(
            hex::encode(&ps) == self.parent_server
                && hex::encode(&active_server) == self.active_server,
            "noncanonical bootstrap point"
        );
        ensure!(
            ps == active_server && self.parent_user == self.active_user,
            "deposit and recovery require the same current authority"
        );
        ensure!(
            scalar(&self.parent_user)? != k256::Scalar::ZERO
                && scalar(&self.active_user)? != k256::Scalar::ZERO,
            "zero bootstrap owner share"
        );
        ensure!(
            self.parent_salt != self.active_salt,
            "distinct funding salts required"
        );
        let parent_key = FundingKey::new(point(&ps)?, scalar(&self.parent_user)?)?;
        let active_key = FundingKey::new(point(&active_server)?, scalar(&self.active_user)?)?;
        let parent = FundingOpening {
            deployment: self.context.deployment,
            coin: self.context.coin,
            salt: self.parent_salt,
            txid: self.txid,
            vout: self.vout,
            amount: self.amount,
            internal_point: point_bytes(parent_key.internal)?,
        };
        parent.commitment()?;
        ensure!(
            self.fee > 0 && self.fee <= 10_000 && self.amount > self.fee + 330,
            "bootstrap fee/amount bounds"
        );
        let activation = crate::bitcoin::activation(
            OutPoint::new(Txid::from_byte_array(self.txid), self.vout),
            self.amount,
            &[(self.amount - self.fee, active_key.xonly()?)],
            0,
        )?;
        let active = FundingOpening {
            deployment: self.context.deployment,
            coin: self.context.coin,
            salt: self.active_salt,
            txid: activation.compute_txid().to_byte_array(),
            vout: 0,
            amount: self.amount - self.fee,
            internal_point: point_bytes(active_key.internal)?,
        };
        let capability = capability_commitment(
            &self.context.deployment,
            &self.context.coin,
            &self.capability,
        )?;
        let blinding = bootstrap::nonce_commitment(
            &self.context,
            &parent.commitment()?,
            &active.commitment()?,
            &capability,
            &self.alpha,
            &self.beta,
            &self.nonce_salt,
        )?;
        Ok(Native {
            parent,
            active,
            parent_key,
            blind: Blinding {
                alpha: scalar(&self.alpha)?,
                beta: scalar(&self.beta)?,
            },
            activation,
            capability,
            blinding,
        })
    }
    fn binding(&self, n: &Native, nonce: &str) -> Result<BootstrapBinding> {
        let ps = hex::decode(&self.parent_server)?;
        let rs = hex::decode(nonce)?;
        ensure!(hex::encode(&rs) == nonce, "noncanonical bootstrap nonce");
        let blinded = n.blind.bind(
            &n.parent_key,
            point(&ps)?,
            point(&rs)?,
            sighash(&n.activation, self.amount, n.parent_key.xonly()?)?,
        )?;
        let binding = BootstrapBinding {
            context: self.context.clone(),
            parent_funding: n.parent.commitment()?,
            active_funding: n.active.commitment()?,
            initial_capability: n.capability,
            parent_server: ps.try_into().map_err(|_| anyhow::anyhow!("parent point"))?,
            active_server: hex::decode(&self.active_server)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("active point"))?,
            nonce_commitment: n.blinding,
            parent_nonce: rs.try_into().map_err(|_| anyhow::anyhow!("parent nonce"))?,
            blinded_challenge: blinded.challenge.to_bytes().into(),
        };
        binding.encode()?;
        Ok(binding)
    }
    fn complete(&self, n: &Native, nonce: &str, partial: &Digest) -> Result<Transaction> {
        self.binding(n, nonce)?;
        let server = point(&hex::decode(&self.parent_server)?)?;
        let rs = point(&hex::decode(nonce)?)?;
        let session = n.blind.bind(
            &n.parent_key,
            server,
            rs,
            sighash(&n.activation, self.amount, n.parent_key.xonly()?)?,
        )?;
        let signature = n
            .blind
            .finish(&n.parent_key, &session, server, rs, scalar(partial)?)?;
        let mut tx = n.activation.clone();
        attach_signature(&mut tx, self.amount, n.parent_key.xonly()?, &signature)?;
        Ok(tx)
    }
    fn validate(&self) -> Result<Native> {
        let n = self.native()?;
        match &self.state {
            Stage::Prepared {} => (),
            Stage::NonceBound { nonce, binding } => {
                ensure!(
                    hex::encode(self.binding(&n, nonce)?.encode()?) == *binding,
                    "frozen bootstrap binding changed"
                );
            }
            Stage::Complete {
                nonce,
                binding,
                partial,
                activation,
            } => {
                ensure!(
                    hex::encode(self.binding(&n, nonce)?.encode()?) == *binding,
                    "frozen bootstrap binding changed"
                );
                ensure!(
                    hex::encode(serialize(&self.complete(&n, nonce, partial)?)) == *activation,
                    "saved activation signature mismatch"
                );
            }
        }
        Ok(n)
    }
}

pub struct BootstrapDraft {
    directory: PathBuf,
    record: Record,
    _lock: ProcessLock,
}
impl BootstrapDraft {
    pub fn create(
        directory: &Path,
        p: BootstrapParameters,
        parent_user: &Digest,
        active_user: &Digest,
        capability: &Digest,
    ) -> Result<Self> {
        let blind = Blinding::default();
        let record = Record {
            schema: "zark-bootstrap".into(),
            version: 2,
            context: p.context,
            txid: p.parent.txid.to_byte_array(),
            vout: p.parent.vout,
            amount: p.amount,
            fee: p.fee,
            parent_server: hex::encode(p.parent_server),
            active_server: hex::encode(p.active_server),
            parent_user: *parent_user,
            active_user: *active_user,
            capability: *capability,
            parent_salt: random32(),
            active_salt: random32(),
            alpha: blind.alpha.to_bytes().into(),
            beta: blind.beta.to_bytes().into(),
            nonce_salt: random32(),
            state: Stage::Prepared {},
        };
        record.validate()?;
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        check_directory(directory)?;
        fs::File::open(directory.parent().context("bootstrap parent directory")?)?.sync_all()?;
        let lock = lock(directory)?;
        let draft = Self {
            directory: directory.into(),
            record,
            _lock: lock,
        };
        draft.persist()?;
        Ok(draft)
    }
    pub fn open(directory: &Path, context: &TransferContext) -> Result<Self> {
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
        ensure!(bytes.len() <= LIMIT, "oversized bootstrap record");
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private bootstrap record"))?;
        ensure!(record.context == *context, "bootstrap context mismatch");
        record.validate()?;
        zark_protocol::storage::sync_observed(&file, directory)?;
        Ok(Self {
            directory: directory.into(),
            record,
            _lock: lock,
        })
    }
    fn persist(&self) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(bytes.len() <= LIMIT, "oversized bootstrap record");
        atomic_write(&self.directory.join(FILE), &bytes)?;
        check_file(&fs::symlink_metadata(self.directory.join(FILE))?)
    }
    /// Public preparation commitments; no outpoint/amount/user point is sent.
    pub fn commitments(&self) -> Result<(Digest, Digest, Digest, Digest)> {
        let n = self.record.validate()?;
        Ok((
            n.parent.commitment()?,
            n.active.commitment()?,
            n.capability,
            n.blinding,
        ))
    }
    /// Owner-local common records for initial recovery, before activation is
    /// signed. They are not an accepted coin and cannot yet be handed onward.
    pub fn local_inputs(&self) -> Result<(Input, Input, Transaction)> {
        let n = self.record.validate()?;
        Ok((input(&n.parent), input(&n.active), n.activation))
    }
    pub fn bind_nonce(
        &mut self,
        context: &TransferContext,
        nonce: [u8; 64],
    ) -> Result<BootstrapBinding> {
        ensure!(
            self.record.context == *context,
            "bootstrap context mismatch"
        );
        let n = self.record.validate()?;
        let nonce = hex::encode(nonce);
        let binding = self.record.binding(&n, &nonce)?;
        match &self.record.state {
            Stage::Prepared {} => {
                self.record.state = Stage::NonceBound {
                    nonce,
                    binding: hex::encode(binding.encode()?),
                }
            }
            Stage::NonceBound { nonce: saved, .. } | Stage::Complete { nonce: saved, .. } => {
                ensure!(*saved == nonce, "bootstrap nonce already frozen")
            }
        }
        self.persist()?;
        Ok(binding)
    }
    /// This native completion check is not evidence that the initial recovery
    /// was saved. Only the higher-level bootstrap workflow can declare readiness.
    pub fn finish(
        &mut self,
        context: &TransferContext,
        nonce: [u8; 64],
        partial: Digest,
    ) -> Result<Transaction> {
        ensure!(
            self.record.context == *context,
            "bootstrap context mismatch"
        );
        let nonce = hex::encode(nonce);
        match &self.record.state {
            Stage::Prepared {} => anyhow::bail!("bootstrap nonce not bound"),
            Stage::NonceBound { nonce: saved, .. } => {
                ensure!(*saved == nonce, "bootstrap response nonce mismatch")
            }
            Stage::Complete {
                nonce: saved,
                partial: old,
                ..
            } => ensure!(
                *saved == nonce && *old == partial,
                "bootstrap permits only exact response retry"
            ),
        }
        let n = self.record.validate()?;
        let tx = self.record.complete(&n, &nonce, &partial)?;
        let binding = hex::encode(self.record.binding(&n, &nonce)?.encode()?);
        self.record.state = Stage::Complete {
            nonce,
            binding,
            partial,
            activation: hex::encode(serialize(&tx)),
        };
        self.persist()?;
        Ok(tx)
    }
    pub fn completed_activation(&self) -> Result<Transaction> {
        self.record.validate()?;
        match &self.record.state {
            Stage::Complete { activation, .. } => Ok(deserialize(&hex::decode(activation)?)?),
            _ => anyhow::bail!("bootstrap activation not complete"),
        }
    }
    pub fn write_authorization_witness(&self, path: &Path) -> Result<()> {
        let n = self.record.validate()?;
        let nonce = match &self.record.state {
            Stage::NonceBound { nonce, .. } | Stage::Complete { nonce, .. } => nonce,
            Stage::Prepared {} => anyhow::bail!("bind bootstrap nonce before proving"),
        };
        let binding = self.record.binding(&n, nonce)?;
        let mut compressed = vec![2];
        compressed.extend_from_slice(&self.record.context.session_auth);
        let session = point_bytes(k256::ProjectivePoint::from(
            *k256::PublicKey::from_sec1_bytes(&compressed)?.as_affine(),
        ))?;
        let value = serde_json::json!({"statement":binding.encode()?,"binding_digest":binding.digest()?,
            "parent_user":self.record.parent_user,"active_user":self.record.active_user,"alpha":self.record.alpha,"beta":self.record.beta,
            "parent_funding_salt":self.record.parent_salt,"active_funding_salt":self.record.active_salt,"nonce_salt":self.record.nonce_salt,
            "txid":self.record.txid,"vout":self.record.vout,"amount":self.record.amount,"fee":self.record.fee,"capability":self.record.capability,
            "session_auth_point":session.as_slice(),"expected_active_txid":n.active.txid,"expected_message":sighash(&n.activation,self.record.amount,n.parent_key.xonly()?)?});
        let bytes = Zeroizing::new(serde_json::to_vec(&value)?);
        check_directory(path.parent().context("bootstrap witness parent")?)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::File::open(path.parent().unwrap())?.sync_all()?;
        Ok(())
    }
    /// Owner-local TOML for the pinned bootstrap circuit; no raw secret getters.
    pub(crate) fn append_authorization_witness(&self, out: &mut String) -> Result<()> {
        let n = self.record.validate()?;
        let nonce = match &self.record.state {
            Stage::NonceBound { nonce, .. } | Stage::Complete { nonce, .. } => nonce,
            Stage::Prepared {} => anyhow::bail!("bind bootstrap nonce before proving"),
        };
        let binding = self.record.binding(&n, nonce)?;
        fn field(out: &mut String, name: &str, bytes: &[u8]) -> Result<()> {
            use std::fmt::Write;
            writeln!(out, "{name} = {}", serde_json::to_string(bytes)?)?;
            Ok(())
        }
        field(out, "statement", &binding.encode()?)?;
        field(out, "binding_digest", &binding.digest()?)?;
        for (name, value) in [
            ("parent_user", &self.record.parent_user),
            ("active_user", &self.record.active_user),
            ("alpha", &self.record.alpha),
            ("beta", &self.record.beta),
            ("parent_funding_salt", &self.record.parent_salt),
            ("active_funding_salt", &self.record.active_salt),
            ("nonce_salt", &self.record.nonce_salt),
            ("txid", &self.record.txid),
            ("capability", &self.record.capability),
        ] {
            field(out, name, value)?;
        }
        out.push_str(&format!(
            "vout = {}\namount = {}\nfee = {}\n",
            self.record.vout, self.record.amount, self.record.fee
        ));
        let session = k256::schnorr::VerifyingKey::from_bytes(&self.record.context.session_auth)?;
        field(
            out,
            "session_auth_point",
            &point_bytes((*session.as_affine()).into())?,
        )
    }
}
fn input(f: &FundingOpening) -> Input {
    Input {
        deployment: hex::encode(f.deployment),
        id: hex::encode(f.coin),
        funding_salt: hex::encode(f.salt),
        internal_point: hex::encode(f.internal_point),
        txid: Txid::from_byte_array(f.txid).to_string(),
        vout: f.vout,
        amount: f.amount,
    }
}
fn check_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.permissions().mode() & 0o777 == 0o700,
        "bootstrap directory must be private and owned"
    );
    Ok(())
}
fn check_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.permissions().mode() & 0o777 == 0o600,
        "bootstrap record must be private, owned and regular"
    );
    Ok(())
}
fn lock(directory: &Path) -> Result<ProcessLock> {
    let path = directory.join("bootstrap.lock");
    match fs::symlink_metadata(&path) {
        Ok(m) => check_file(&m)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let lock = ProcessLock::acquire(&path)?;
    check_file(&fs::symlink_metadata(path)?)?;
    Ok(lock)
}
