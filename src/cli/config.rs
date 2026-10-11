//! Authenticate local assets and configure native journal/prover access.
use super::storage::{initialize_metadata, read_metadata, read_private};
use super::{Kind, Metadata};
use crate::chain::ChainConfig;
use crate::envelope::OfferContext;
use crate::invitation::LocalInvitation;
use crate::origin::OriginJournal;
use crate::prover::{BinaryPin, Program, Prover};
use crate::receiver::ReceiverJournal;
use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use serde::Deserialize;
use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use zark_protocol::address::AddressNetwork;
use zark_protocol::assets::{
    MAX_CONFIG_BYTES, MAX_CRS_BYTES, MAX_EXECUTABLE_BYTES, is_crs_runtime_lock,
    read_bounded as read_public_asset, sha256_bounded,
};
use zark_protocol::deployment::{Deployment, Manifest};
use zark_protocol::handoff::Digest;
use zark_protocol::lineage::LineagePolicy;
use zark_protocol::proof::{ArtifactPin, PinnedVerifier};
use zark_protocol::remote::RemoteEndpoint;
use zark_protocol::timing::{Phase, Span};
use zark_protocol::{hash, hex32, network};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub(super) version: u32,
    pub(super) deployment: Deployment,
    pub(super) manifest: PathBuf,
    pub(super) manifest_sha256: String,
    pub(super) programs: PathBuf,
    pub(super) nargo: BinaryPin,
    pub(super) bb: BinaryPin,
    #[serde(default)]
    pub(super) fast_runtime: Option<crate::prover::FastRuntime>,
    pub(super) crs: PathBuf,
    /// Pins for every CRS file; names must be plain file names, never paths.
    pub(super) crs_sha256: BTreeMap<String, String>,
    pub(super) bitcoin_cli_sha256: String,
    pub(super) endpoint: RemoteEndpoint,
    pub(super) chain: ChainConfig,
}
pub(super) struct App {
    pub(super) config: Config,
    pub(super) policy: LineagePolicy,
    manifest: Manifest,
    proofs_enabled: bool,
    crs_authenticated: OnceCell<()>,
    verifier: OnceCell<PinnedVerifier>,
    prover: OnceCell<Prover>,
    pub(super) control: Digest,
}
impl App {
    pub(super) fn load(path: &Path, need_proofs: bool) -> Result<Self> {
        let _timing = Span::new(Phase::AppLoad);
        let bytes = read_private(path, 1_000_000)?;
        crate::prover::FastRuntime::reject_retired(&bytes)?;
        let config: Config = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private wallet configuration"))?;
        ensure!(
            config.version == 10,
            "v10 requires a fresh configuration; keep the v9 wallet and recovery application for existing coins"
        );
        ensure!(
            config.chain.deployment.id()? == config.deployment.id()?,
            "wallet and Bitcoin deployment disagree"
        );
        config.endpoint.validate()?;
        for path in [
            &config.manifest,
            &config.programs,
            &config.crs,
            &config.nargo.path,
            &config.bb.path,
            &config.chain.bitcoin_cli,
            &config.chain.datadir,
            &config.endpoint.ca_certificate,
        ] {
            ensure!(path.is_absolute(), "configuration paths must be absolute");
        }
        if let Some(path) = &config.endpoint.credential_file {
            ensure!(path.is_absolute(), "configuration paths must be absolute");
        }
        let bytes = read_public_asset(&config.manifest, MAX_CONFIG_BYTES)?;
        ensure!(
            hash(&[&bytes]) == hex32(&config.manifest_sha256)?,
            "manifest SHA256 pin mismatch"
        );
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        let policy = config.deployment.lineage_policy(&manifest)?;
        if need_proofs {
            ensure!(
                sha256_bounded(&config.chain.bitcoin_cli, MAX_EXECUTABLE_BYTES)?
                    == hex32(&config.bitcoin_cli_sha256)?,
                "Bitcoin CLI SHA256 pin mismatch"
            );
        }
        let control = hex32(&config.deployment.control_key)?;
        Ok(Self {
            config,
            policy,
            manifest,
            proofs_enabled: need_proofs,
            crs_authenticated: OnceCell::new(),
            verifier: OnceCell::new(),
            prover: OnceCell::new(),
            control,
        })
    }
    // Authentication is completed before the first use, including recovery
    // fallback paths. Commands that only poll a saved journal need no prover.
    fn authenticate_crs(&self) -> Result<()> {
        ensure!(
            self.proofs_enabled,
            "proof assets unavailable for this command"
        );
        if self.crs_authenticated.get().is_some() {
            return Ok(());
        }
        let _timing = Span::new(Phase::CrsAuthentication);
        let config = &self.config;
        ensure!(
            config.crs_sha256.contains_key("bn254_g1.dat")
                && config.crs_sha256.contains_key("bn254_g1_compressed.dat"),
            "required CRS pins missing"
        );
        for (name, pin) in &config.crs_sha256 {
            ensure!(
                Path::new(name).components().count() == 1
                    && name.ends_with(".dat")
                    && !name.starts_with('.'),
                "invalid CRS pin name"
            );
            ensure!(
                sha256_bounded(&config.crs.join(name), MAX_CRS_BYTES)? == hex32(pin)?,
                "CRS SHA256 pin mismatch"
            );
        }
        for entry in fs::read_dir(&config.crs)? {
            let entry = entry?;
            if is_crs_runtime_lock(&entry.path())? {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type()?.is_file() {
                ensure!(
                    config.crs_sha256.contains_key(&name),
                    "unpinned file in CRS directory"
                );
            }
        }
        self.crs_authenticated
            .set(())
            .map_err(|_| anyhow::anyhow!("CRS already initialized"))?;
        Ok(())
    }
    pub(super) fn v(&self) -> Result<&PinnedVerifier> {
        if self.verifier.get().is_none() {
            self.authenticate_crs()?;
            let _timing = Span::new(Phase::VerifierInitialization);
            let config = &self.config;
            let verifier = config.deployment.verifier(
                &self.manifest,
                config.manifest.parent().context("manifest parent")?,
                ArtifactPin {
                    path: config.bb.path.clone(),
                    sha256: hex32(&config.bb.sha256)?,
                },
                &config.crs,
            )?;
            self.verifier
                .set(verifier)
                .map_err(|_| anyhow::anyhow!("verifier already initialized"))?;
        }
        self.verifier.get().context("proof verifier unavailable")
    }
    pub(super) fn p(&self) -> Result<&Prover> {
        if self.prover.get().is_none() {
            self.authenticate_crs()?;
            let _timing = Span::new(Phase::ProverInitialization);
            let config = &self.config;
            let prover = Prover::new(
                &config.manifest,
                &hex32(&config.manifest_sha256)?,
                config.nargo.clone(),
                config.bb.clone(),
                config.crs.clone(),
                serde_json::from_slice::<Vec<Program>>(&read_public_asset(
                    &config.programs,
                    MAX_CONFIG_BYTES,
                )?)?,
            )?;
            let prover = if let Some(runtime) = &config.fast_runtime {
                prover.with_fast_runtime(runtime.clone())?
            } else {
                prover
            };
            self.prover
                .set(prover)
                .map_err(|_| anyhow::anyhow!("prover already initialized"))?;
        }
        self.prover.get().context("prover unavailable")
    }
    pub(super) fn network(&self) -> Network {
        match self.config.deployment.network {
            network::Network::Regtest => Network::Regtest,
            network::Network::CustomSignet => Network::Signet,
        }
    }
    pub(super) fn metadata(&self, path: &Path) -> Result<Metadata> {
        let metadata = read_metadata(path)?;
        ensure!(
            metadata.version == 10
                && metadata.deployment == hex::encode(self.policy.deployment)
                && metadata.manifest_sha256 == self.config.manifest_sha256,
            "operation belongs to a different pinned deployment"
        );
        Ok(metadata)
    }
    pub(super) fn initialize(&self, path: &Path, kind: Kind) -> Result<Metadata> {
        let expected = Metadata {
            version: 10,
            deployment: hex::encode(self.policy.deployment),
            manifest_sha256: self.config.manifest_sha256.clone(),
            kind,
        };
        initialize_metadata(path, &expected)
    }
    pub(super) fn invitation(&self, path: &Path) -> Result<LocalInvitation> {
        LocalInvitation::open(path, AddressNetwork::Test, self.policy.deployment)
    }
    pub(super) fn origin(&self, path: &Path, metadata: &Metadata) -> Result<OriginJournal> {
        let Kind::Origin {
            amount,
            activation_fee,
            recovery_fee,
        } = metadata.kind
        else {
            anyhow::bail!("operation is not an origin")
        };
        let journal = OriginJournal::open(&path.join("journal"), &self.policy)?;
        journal.require_parameters(amount, activation_fee, recovery_fee)?;
        Ok(journal)
    }
    pub(super) fn receiver(
        &self,
        path: &Path,
        metadata: &Metadata,
    ) -> Result<(LocalInvitation, ReceiverJournal)> {
        let Kind::Receiver {
            invitation,
            coin,
            transfer_operation,
            offer_sha256,
            recovery_fee,
            batch: _,
            expected_amount,
            ..
        } = &metadata.kind
        else {
            anyhow::bail!("operation is not a receiver")
        };
        let invitation = self.invitation(invitation)?;
        let context = OfferContext {
            deployment: self.policy.deployment,
            coin: hex32(coin)?,
            operation: hex32(transfer_operation)?,
        };
        let journal =
            ReceiverJournal::open(&path.join("journal"), &invitation, &context, &self.policy)?;
        journal.require_cli_parameters(&hex32(offer_sha256)?, *recovery_fee)?;
        if let Some(amount) = expected_amount {
            journal.require_expected_amount(*amount)?;
        }
        Ok((invitation, journal))
    }
}
