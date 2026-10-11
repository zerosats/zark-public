//! Durable current-owner cooperative-exit material. This validates actual
//! Bitcoin signing, not historical ownership or current signer entitlement.
//! The separate composed exit proof and current server state gate issuance.
use crate::{
    bitcoin::{attach_signature, cooperative_exit, sighash},
    common,
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
    exit::{self, ExitOpening},
    handoff::{
        Digest, FundingOpening, RecoverySchedule, ServerShareOpening, SigningBinding, StateOpening,
        TransferContext, capability_commitment, policy_commitment,
    },
    lineage::{IssuanceBinding, LineagePolicy},
    local::ProcessLock,
    point, point_bytes, random32, scalar,
    storage::atomic_write,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const FILE: &str = "cooperative-exit.json";
const LIMIT: usize = 40_000;

pub struct ExitParameters {
    pub context: TransferContext,
    pub backing: Input,
    pub activation_input: Input,
    pub activation: Transaction,
    pub server: [u8; 64],
    pub current_recovery: Digest,
    pub current_issuance: Digest,
    pub server_salt: Digest,
    pub schedule: RecoverySchedule,
    /// An existing Bitcoin P2TR output key, not another TapTweak input.
    pub destination: Digest,
    pub fee: u64,
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
        transaction: String,
    },
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    #[zeroize(skip)]
    context: TransferContext,
    #[zeroize(skip)]
    backing: Input,
    #[zeroize(skip)]
    activation_input: Input,
    activation: String,
    server: String,
    current_recovery: Digest,
    current_issuance: Digest,
    server_salt: Digest,
    initial: u32,
    gap: u32,
    margin: u32,
    destination: Digest,
    fee: u64,
    user: Digest,
    capability: Digest,
    alpha: Digest,
    beta: Digest,
    exit_salt: Digest,
    nonce_salt: Digest,
    state: Stage,
}

struct Native {
    funding: FundingOpening,
    deposit: FundingOpening,
    key: FundingKey,
    blind: Blinding,
    transaction: Transaction,
    message: Digest,
    exit: Digest,
    blinding: Digest,
    capability: Digest,
    policy: Digest,
}

impl Record {
    fn native(&self) -> Result<Native> {
        ensure!(
            self.schema == "zark-cooperative-exit" && self.version == 3,
            "unsupported exit record"
        );
        exit::validate_context(&self.context)?;
        let activation: Transaction = deserialize(&hex::decode(&self.activation)?)?;
        ensure!(
            hex::encode(serialize(&activation)) == self.activation,
            "noncanonical exit activation"
        );
        let funding = common::validate(
            &self.context.deployment,
            &self.context.coin,
            &self.backing,
            &self.activation_input,
            &activation,
        )?;
        let deposit = common::funding(&self.context.deployment, &self.activation_input)?;
        ensure!(
            deposit.coin == self.context.coin && deposit.internal_point == funding.internal_point,
            "direct exit requires shared deposit and recovery authority"
        );
        let activation_fee = deposit
            .amount
            .checked_sub(funding.amount)
            .context("activation amount exceeds deposit")?;
        ensure!(
            (1..=10_000).contains(&activation_fee),
            "activation fee bounds"
        );
        let server_bytes: [u8; 64] = hex::decode(&self.server)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("exit server point"))?;
        ensure!(
            hex::encode(server_bytes) == self.server,
            "noncanonical exit server point"
        );
        ensure!(
            scalar(&self.user)? != k256::Scalar::ZERO,
            "zero exit user share"
        );
        let key = FundingKey::new(point(&server_bytes)?, scalar(&self.user)?)?;
        ensure!(
            point_bytes(key.internal)? == funding.internal_point
                && key.xonly()? == funding.output_key()?,
            "exit user/server backing mismatch"
        );
        let capability = capability_commitment(
            &self.context.deployment,
            &self.context.coin,
            &self.capability,
        )?;
        let policy = policy_commitment(RecoverySchedule {
            initial: self.initial,
            gap: self.gap,
            margin: self.margin,
        })?;
        let state = StateOpening {
            deployment: self.context.deployment,
            coin: self.context.coin,
            funding: funding.commitment()?,
            capability,
            recovery: self.current_recovery,
            server_share: ServerShareOpening {
                deployment: self.context.deployment,
                coin: self.context.coin,
                server: server_bytes,
                salt: self.server_salt,
            }
            .commitment()?,
            policy,
            issuance: self.current_issuance,
        }
        .commitment()?;
        ensure!(
            state == self.context.previous_state,
            "exit is not bound to current state opening"
        );
        let opening = ExitOpening {
            deployment: self.context.deployment,
            coin: self.context.coin,
            funding: funding.commitment()?,
            salt: self.exit_salt,
            destination: self.destination,
            fee: self.fee,
        };
        opening.require_funding(&funding)?;
        let exit = opening.commitment()?;
        let blinding = exit::nonce_commitment(
            &self.context,
            &opening.funding,
            &exit,
            &self.alpha,
            &self.beta,
            &self.nonce_salt,
        )?;
        let blind = Blinding {
            alpha: scalar(&self.alpha)?,
            beta: scalar(&self.beta)?,
        };
        let transaction = cooperative_exit(
            OutPoint::new(Txid::from_byte_array(deposit.txid), deposit.vout),
            deposit.amount,
            self.fee,
            self.destination,
        )?;
        let message = sighash(&transaction, deposit.amount, key.xonly()?)?;
        Ok(Native {
            funding,
            deposit,
            key,
            blind,
            transaction,
            message,
            exit,
            blinding,
            capability,
            policy,
        })
    }

    fn binding(&self, native: &Native, nonce: &str) -> Result<SigningBinding> {
        let server = point(&hex::decode(&self.server)?)?;
        let rs = point(&hex::decode(nonce)?)?;
        ensure!(
            hex::encode(point_bytes(rs)?) == nonce,
            "noncanonical exit nonce"
        );
        let session = native.blind.bind(&native.key, server, rs, native.message)?;
        let funding = native.funding.commitment()?;
        let binding = SigningBinding {
            context: self.context.clone(),
            funding,
            refresh_commitment: exit::share_commitment(
                &self.context,
                &funding,
                &point_bytes(server)?,
            )?,
            previous_capability: native.capability,
            next_capability: exit::terminal_capability(&self.context)?,
            recovery: native.exit,
            nonce_commitment: native.blinding,
            draft_server: point_bytes(server)?,
            server_nonce: point_bytes(rs)?,
            blinded_challenge: session.challenge.to_bytes().into(),
        };
        binding.encode()?;
        Ok(binding)
    }

    fn completed(&self, native: &Native, nonce: &str, partial: &Digest) -> Result<Transaction> {
        let server = point(&hex::decode(&self.server)?)?;
        let rs = point(&hex::decode(nonce)?)?;
        let session = native.blind.bind(&native.key, server, rs, native.message)?;
        let signature = native
            .blind
            .finish(&native.key, &session, server, rs, scalar(partial)?)?;
        let mut tx = native.transaction.clone();
        attach_signature(
            &mut tx,
            native.deposit.amount,
            native.key.xonly()?,
            &signature,
        )?;
        Ok(tx)
    }

    fn validate(&self) -> Result<Native> {
        let native = self.native()?;
        match &self.state {
            Stage::Prepared {} => (),
            Stage::NonceBound { nonce, binding } => {
                ensure!(
                    hex::encode(self.binding(&native, nonce)?.encode()?) == *binding,
                    "frozen exit binding changed"
                );
            }
            Stage::Complete {
                nonce,
                binding,
                partial,
                transaction,
            } => {
                ensure!(
                    hex::encode(self.binding(&native, nonce)?.encode()?) == *binding,
                    "frozen exit binding changed"
                );
                ensure!(
                    hex::encode(serialize(&self.completed(&native, nonce, partial)?))
                        == *transaction,
                    "saved exit signature mismatch"
                );
            }
        }
        Ok(native)
    }
}

pub struct ExitDraft {
    directory: PathBuf,
    record: Record,
    _lock: ProcessLock,
}
impl ExitDraft {
    pub fn create(
        directory: &Path,
        p: ExitParameters,
        user: &Digest,
        capability: &Digest,
    ) -> Result<Self> {
        let blind = Blinding::default();
        let record = Record {
            schema: "zark-cooperative-exit".into(),
            version: 3,
            context: p.context,
            backing: p.backing,
            activation_input: p.activation_input,
            activation: hex::encode(serialize(&p.activation)),
            server: hex::encode(p.server),
            current_recovery: p.current_recovery,
            current_issuance: p.current_issuance,
            server_salt: p.server_salt,
            initial: p.schedule.initial,
            gap: p.schedule.gap,
            margin: p.schedule.margin,
            destination: p.destination,
            fee: p.fee,
            user: *user,
            capability: *capability,
            alpha: blind.alpha.to_bytes().into(),
            beta: blind.beta.to_bytes().into(),
            exit_salt: random32(),
            nonce_salt: random32(),
            state: Stage::Prepared {},
        };
        record.validate()?;
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        check_directory(directory)?;
        fs::File::open(directory.parent().context("exit parent directory")?)?.sync_all()?;
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
        ensure!(bytes.len() <= LIMIT, "oversized exit record");
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private exit record"))?;
        ensure!(record.context == *context, "exit context mismatch");
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
        ensure!(bytes.len() <= LIMIT, "oversized exit record");
        atomic_write(&self.directory.join(FILE), &bytes)?;
        check_file(&fs::symlink_metadata(self.directory.join(FILE))?)
    }

    /// These are the only pre-nonce commitments sent to the blind signer.
    pub fn commitments(&self) -> Result<(Digest, Digest, Digest)> {
        let n = self.record.validate()?;
        Ok((n.funding.commitment()?, n.exit, n.blinding))
    }
    pub(crate) fn owner_commitments(&self) -> Result<(Digest, Digest)> {
        let n = self.record.validate()?;
        let server: [u8; 64] = hex::decode(&self.record.server)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("exit server point"))?;
        Ok((
            n.capability,
            ServerShareOpening {
                deployment: self.record.context.deployment,
                coin: self.record.context.coin,
                server,
                salt: self.record.server_salt,
            }
            .commitment()?,
        ))
    }
    pub(crate) fn require_destination(&self, destination: &Digest, fee: u64) -> Result<()> {
        self.record.validate()?;
        ensure!(
            self.record.destination == *destination && self.record.fee == fee,
            "saved exit destination changed"
        );
        Ok(())
    }
    pub(crate) fn owner_authorization(
        &self,
    ) -> Result<zark_protocol::owner_auth::OwnerAuthorization> {
        let (funding, exit, blinding) = self.commitments()?;
        let (_, server_share) = self.owner_commitments()?;
        zark_protocol::owner_auth::OwnerAuthorization::sign_exit(
            &self.record.context,
            &funding,
            &server_share,
            &exit,
            &blinding,
            &self.record.capability,
        )
    }
    pub fn signing_binding(&self) -> Result<SigningBinding> {
        let n = self.record.validate()?;
        match &self.record.state {
            Stage::NonceBound { nonce, .. } | Stage::Complete { nonce, .. } => {
                self.record.binding(&n, nonce)
            }
            Stage::Prepared {} => anyhow::bail!("exit nonce not yet bound"),
        }
    }

    pub fn bind_nonce(
        &mut self,
        context: &TransferContext,
        nonce: [u8; 64],
    ) -> Result<SigningBinding> {
        ensure!(self.record.context == *context, "exit context mismatch");
        let native = self.record.validate()?;
        let nonce = hex::encode(nonce);
        let binding = self.record.binding(&native, &nonce)?;
        match &self.record.state {
            Stage::Prepared {} => {
                self.record.state = Stage::NonceBound {
                    nonce,
                    binding: hex::encode(binding.encode()?),
                }
            }
            Stage::NonceBound { nonce: saved, .. } | Stage::Complete { nonce: saved, .. } => {
                ensure!(*saved == nonce, "exit nonce already frozen")
            }
        }
        self.persist()?;
        Ok(binding)
    }

    pub fn finish(
        &mut self,
        context: &TransferContext,
        nonce: [u8; 64],
        partial: Digest,
    ) -> Result<Transaction> {
        ensure!(self.record.context == *context, "exit context mismatch");
        let nonce = hex::encode(nonce);
        match &self.record.state {
            Stage::Prepared {} => anyhow::bail!("exit nonce is not bound"),
            Stage::NonceBound { nonce: saved, .. } => {
                ensure!(*saved == nonce, "exit response nonce mismatch")
            }
            Stage::Complete {
                nonce: saved,
                partial: old,
                ..
            } => ensure!(
                *saved == nonce && *old == partial,
                "exit permits only exact response retry"
            ),
        }
        let native = self.record.validate()?;
        let transaction = self.record.completed(&native, &nonce, &partial)?;
        let binding = hex::encode(self.record.binding(&native, &nonce)?.encode()?);
        self.record.state = Stage::Complete {
            nonce,
            binding,
            partial,
            transaction: hex::encode(serialize(&transaction)),
        };
        self.persist()?;
        Ok(transaction)
    }

    pub fn completed_transaction(&self) -> Result<Transaction> {
        self.record.validate()?;
        match &self.record.state {
            Stage::Complete { transaction, .. } => Ok(deserialize(&hex::decode(transaction)?)?),
            _ => anyhow::bail!("cooperative exit is not complete"),
        }
    }

    /// Explicit private witness export for the pinned exit prover. The caller
    /// adds only its own current certificate/key/proof. No server secret, old
    /// recovery transaction or predecessor history is available to this writer.
    pub fn write_authorization_witness(&self, path: &Path, policy: &LineagePolicy) -> Result<()> {
        let value = self.authorization_values(policy)?;
        let bytes = Zeroizing::new(serde_json::to_vec(&value)?);
        check_directory(path.parent().context("exit witness parent")?)?;
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
    pub(crate) fn authorization_values(&self, policy: &LineagePolicy) -> Result<serde_json::Value> {
        let native = self.record.validate()?;
        let nonce = match &self.record.state {
            Stage::NonceBound { nonce, .. } | Stage::Complete { nonce, .. } => nonce,
            Stage::Prepared {} => anyhow::bail!("bind exit nonce before proving"),
        };
        policy.require(
            &self.record.context.deployment,
            &native.policy,
            &policy.origin_key,
            &policy.role_hashes,
        )?;
        let binding = self.record.binding(&native, nonce)?;
        let signing = binding.encode()?;
        let binding_digest = binding.digest()?;
        let mut compressed = vec![2];
        compressed.extend_from_slice(&self.record.destination);
        let destination = point_bytes(k256::ProjectivePoint::from(
            *k256::PublicKey::from_sec1_bytes(&compressed)?.as_affine(),
        ))?;
        compressed.truncate(1);
        compressed.extend_from_slice(&self.record.context.session_auth);
        let session = point_bytes(k256::ProjectivePoint::from(
            *k256::PublicKey::from_sec1_bytes(&compressed)?.as_affine(),
        ))?;
        let composed = IssuanceBinding {
            signing: binding,
            policy: native.policy,
            origin_key: policy.origin_key,
            role_hashes: policy.role_hashes,
        };
        Ok(
            serde_json::json!({"statement":composed.encode()?,"signing":signing,"binding_digest":binding_digest,
            "capability":self.record.capability,"current_recovery":self.record.current_recovery,"current_issuance":self.record.current_issuance,
            "server_salt":self.record.server_salt,"user":self.record.user,"alpha":self.record.alpha,"beta":self.record.beta,
            "funding_salt":native.funding.salt,"exit_salt":self.record.exit_salt,"nonce_salt":self.record.nonce_salt,
            "txid":native.funding.txid,"vout":native.funding.vout,"amount":native.funding.amount,"fee":self.record.fee,
            "deposit_txid":native.deposit.txid,"deposit_vout":native.deposit.vout,"deposit_amount":native.deposit.amount,
            "destination":destination.as_slice(),"session_auth_point":session.as_slice(),"expected_message":native.message}),
        )
    }
}

fn check_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.permissions().mode() & 0o777 == 0o700,
        "exit directory must be owned and private"
    );
    Ok(())
}
fn check_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.permissions().mode() & 0o777 == 0o600,
        "exit record must be a private owned regular file"
    );
    Ok(())
}
fn lock(directory: &Path) -> Result<ProcessLock> {
    let path = directory.join("cooperative-exit.lock");
    match fs::symlink_metadata(&path) {
        Ok(m) => check_file(&m)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let guard = ProcessLock::acquire(&path)?;
    check_file(&fs::symlink_metadata(path)?)?;
    Ok(guard)
}
