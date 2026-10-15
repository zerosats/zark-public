//! Zark signer service entry point. All requests pass through the host's
//! credential guard and the engine's durable authorization and proof checks.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use k256::schnorr::SigningKey;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use zark_protocol::{
    deployment::{Deployment, Manifest},
    handoff::{Digest, TransferContext},
    hash, hex32,
    local::ProcessLock,
    proof::ArtifactPin,
    random_scalar,
};
use zark_signer::{
    engine::{Admission, Engine},
    host::{self, HostedConfig},
};
use zeroize::Zeroizing;

#[path = "main/bitcoin_tip.rs"]
mod bitcoin_tip;

#[derive(Parser)]
#[command(about = "Zark research signer with authenticated TLS and durable proof-gated issuance")]
struct Args {
    /// Trusted operator configuration, kept separate from peer messages.
    #[arg(
        long,
        required_unless_present = "generate_key",
        conflicts_with = "generate_key"
    )]
    config: Option<PathBuf>,
    /// Validate deployment, all proof assets, paths and signing keys, then exit.
    #[arg(
        long,
        requires = "config",
        conflicts_with = "repair_interrupted_checkpoint"
    )]
    check_config: bool,
    /// Repair only one inspected DB-commit/checkpoint-publication gap, then exit.
    #[arg(long, requires = "config", conflicts_with = "check_config")]
    repair_interrupted_checkpoint: bool,
    /// Create one fresh normalized Schnorr key; print only its public key.
    #[arg(long, conflicts_with_all = ["config", "check_config", "repair_interrupted_checkpoint"])]
    generate_key: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePin {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrsPins {
    directory: PathBuf,
    bn254_g1_sha256: String,
    bn254_g1_compressed_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    deployment: FilePin,
    manifest: FilePin,
    suite_directory: PathBuf,
    bb: FilePin,
    crs: CrsPins,
    database: PathBuf,
    checkpoint: PathBuf,
    control_key: PathBuf,
    origin_key: PathBuf,
    hosted: PathBuf,
    #[serde(default)]
    batch_bitcoin: Option<bitcoin_tip::Config>,
}

/// Context admission complements, and does not replace, host's exact
/// credential/scope/rate/deadline guard. This private type and its Engine are
/// instantiated only here; the Engine is passed only to host::serve.
struct ConfiguredAdmission {
    deployment: Digest,
    hosted: PathBuf,
}

impl Admission for ConfiguredAdmission {
    fn authorize(&self, context: &TransferContext) -> Result<()> {
        context.encode()?;
        ensure!(
            context.deployment == self.deployment,
            "private admission deployment mismatch"
        );
        let config = read_hosted(&self.hosted)?;
        ensure!(
            config.admits_coin(&hex::encode(context.coin))?,
            "private coin is not currently admitted"
        );
        Ok(())
    }
}

fn canonical_digest(text: &str) -> Result<Digest> {
    let digest = hex32(text)?;
    ensure!(
        digest != [0; 32] && hex::encode(digest) == text,
        "invalid configured digest"
    );
    Ok(digest)
}

fn trusted_metadata(metadata: &fs::Metadata) -> Result<()> {
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && (metadata.uid() == uid || metadata.uid() == 0)
            && metadata.permissions().mode() & 0o022 == 0,
        "operator input must be a trusted regular file without shared write access"
    );
    Ok(())
}

fn open_trusted(path: &Path) -> Result<fs::File> {
    ensure!(path.is_absolute(), "operator paths must be absolute");
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    trusted_metadata(&file.metadata()?)?;
    Ok(file)
}

fn read_trusted(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = open_trusted(path)?;
    ensure!(
        file.metadata()?.len() <= limit,
        "operator input exceeds byte bound"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "operator input exceeds byte bound"
    );
    Ok(bytes)
}

fn read_pinned(pin: &FilePin, limit: u64) -> Result<Vec<u8>> {
    let bytes = read_trusted(&pin.path, limit)?;
    ensure!(
        hash(&[&bytes]) == canonical_digest(&pin.sha256)?,
        "operator file pin mismatch"
    );
    Ok(bytes)
}

fn check_file_pin(path: &Path, expected: &str, maximum: u64) -> Result<()> {
    let mut file = open_trusted(path)?;
    ensure!(
        file.metadata()?.len() <= maximum,
        "pinned asset exceeds byte bound"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut count = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        ensure!(count <= maximum, "pinned asset exceeds byte bound");
        hash.update(&buffer[..read]);
    }
    let actual: Digest = hash.finalize().into();
    ensure!(
        actual == canonical_digest(expected)?,
        "pinned asset checksum mismatch"
    );
    Ok(())
}

fn private_directory(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "private directory must be absolute");
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o777 == 0o700,
        "state and checkpoint directories must be owned and mode 0700"
    );
    Ok(path.canonicalize()?)
}

fn private_path(path: &Path) -> Result<PathBuf> {
    let parent = private_directory(path.parent().context("private file parent")?)?;
    let path = parent.join(path.file_name().context("private filename")?);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file()
                    && metadata.nlink() == 1
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.permissions().mode() & 0o777 == 0o600,
                "private state file must be owned, singly linked and mode 0600"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(path)
}

fn read_key(path: &Path) -> Result<SigningKey> {
    let path = private_path(path)?;
    let bytes = Zeroizing::new(read_trusted(&path, 32)?);
    ensure!(
        bytes.len() == 32,
        "signing key must contain exactly 32 raw bytes"
    );
    let key = SigningKey::from_bytes(&bytes).map_err(|_| anyhow::anyhow!("invalid signing key"))?;
    ensure!(
        key.to_bytes()[..] == bytes[..],
        "signing key must use normalized BIP340 scalar"
    );
    Ok(key)
}

fn read_hosted(path: &Path) -> Result<HostedConfig> {
    HostedConfig::parse(&read_trusted(path, 1_000_000)?)
        .map_err(|_| anyhow::anyhow!("invalid trusted v10 hosted configuration"))
}

fn generate_key(path: &Path) -> Result<()> {
    let path = private_path(path)?;
    let key = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let bytes = Zeroizing::new(key.to_bytes().to_vec());
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().context("key parent")?)?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"public_key": hex::encode(key.verifying_key().to_bytes())})
    );
    Ok(())
}

fn run(args: Args) -> Result<()> {
    if let Some(path) = args.generate_key {
        return generate_key(&path);
    }
    let path = args.config.context("operator configuration required")?;
    let mut config: Config = serde_json::from_slice(&read_trusted(&path, 1_000_000)?)
        .map_err(|_| anyhow::anyhow!("invalid v10 operator configuration"))?;
    ensure!(config.version == 10, "operator configuration version");
    let deployment: Deployment =
        serde_json::from_slice(&read_pinned(&config.deployment, 64 * 1024)?)
            .map_err(|_| anyhow::anyhow!("invalid pinned deployment"))?;
    let manifest: Manifest = serde_json::from_slice(&read_pinned(&config.manifest, 128 * 1024)?)
        .map_err(|_| anyhow::anyhow!("invalid pinned suite manifest"))?;
    let policy = deployment.lineage_policy(&manifest)?;
    let control = read_key(&config.control_key)?;
    let origin = read_key(&config.origin_key)?;
    ensure!(
        control.verifying_key().to_bytes()[..] == canonical_digest(&deployment.control_key)?
            && origin.verifying_key().to_bytes()[..] == canonical_digest(&deployment.origin_key)?,
        "local signing keys differ from authenticated deployment"
    );
    ensure!(
        control.verifying_key() != origin.verifying_key(),
        "control and origin keys must be independent"
    );

    // Validate paths before Engine can create any database/checkpoint state.
    config.database = private_path(&config.database)?;
    config.checkpoint = private_path(&config.checkpoint)?;
    let database_parent = config.database.parent().context("database parent")?;
    ensure!(
        !config.checkpoint.starts_with(database_parent),
        "checkpoint must be independently retained outside database directory"
    );
    let lock_path = private_path(&database_parent.join("zark-service.lock"))?;
    for reserved in [&config.database, &config.checkpoint, &lock_path] {
        for input in [
            &config.control_key,
            &config.origin_key,
            &config.hosted,
            &config.deployment.path,
            &config.manifest.path,
            &config.bb.path,
            &path,
        ] {
            ensure!(
                *reserved != input.canonicalize()?,
                "state path aliases operator input"
            );
        }
        if let Some(bitcoin) = &config.batch_bitcoin {
            for input in bitcoin.input_paths() {
                ensure!(
                    *reserved != input.canonicalize()?,
                    "state path aliases Bitcoin tip source"
                );
            }
        }
    }
    ensure!(
        config.database != lock_path,
        "database aliases service lock"
    );
    let hosted = read_hosted(&config.hosted)?;
    // Key and certificate parsing is repeated by the listener; these checks
    // prevent weak file ownership/modes even when --check-config is used.
    let mut tls_files = vec![(&hosted.certificate, &hosted.private_key)];
    if let Some(browser) = &hosted.browser {
        tls_files.push((&browser.certificate, &browser.private_key));
    }
    for (certificate, private_key) in tls_files {
        private_path(private_key)?;
        let tls_key = Zeroizing::new(read_trusted(private_key, 1_000_000)?);
        let tls_certificate = read_trusted(certificate, 1_000_000)?;
        let certificates = rustls_pemfile::certs(&mut tls_certificate.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let tls_private = rustls_pemfile::private_key(&mut tls_key.as_slice())?
            .context("TLS private key is missing")?;
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, tls_private)?;
    }
    ensure!(
        config.suite_directory.is_absolute() && config.crs.directory.is_absolute(),
        "suite and CRS directories must be absolute"
    );
    for role in &manifest.roles {
        for artifact in ["circuit.json", "vk", "vk.json"] {
            open_trusted(&config.suite_directory.join(&role.role).join(artifact))?;
        }
    }
    check_file_pin(&config.bb.path, &config.bb.sha256, 128 * 1024 * 1024)?;
    ensure!(
        open_trusted(&config.bb.path)?
            .metadata()?
            .permissions()
            .mode()
            & 0o111
            != 0,
        "pinned verifier is not executable"
    );
    let batch_tip = bitcoin_tip::open(config.batch_bitcoin.as_ref(), &deployment)?;
    check_file_pin(
        &config.crs.directory.join("bn254_g1.dat"),
        &config.crs.bn254_g1_sha256,
        8 * 1024 * 1024 * 1024,
    )?;
    check_file_pin(
        &config.crs.directory.join("bn254_g1_compressed.dat"),
        &config.crs.bn254_g1_compressed_sha256,
        8 * 1024 * 1024 * 1024,
    )?;
    let verifier = deployment.verifier(
        &manifest,
        &config.suite_directory,
        ArtifactPin {
            path: config.bb.path,
            sha256: canonical_digest(&config.bb.sha256)?,
        },
        &config.crs.directory,
    )?;
    if args.check_config {
        println!(
            "{}",
            serde_json::json!({"configuration_valid":true,"version":10,
            "deployment":hex::encode(policy.deployment),"suite":hex::encode(manifest.id()?)})
        );
        return Ok(());
    }
    let _service_lock = ProcessLock::acquire(&lock_path)?;
    private_path(&lock_path)?;
    let admission = Arc::new(ConfiguredAdmission {
        deployment: policy.deployment,
        hosted: config.hosted.clone(),
    });
    let engine = if args.repair_interrupted_checkpoint {
        Engine::repair_and_open(
            &config.database,
            &config.checkpoint,
            policy,
            verifier,
            admission,
            batch_tip,
            control,
            origin,
        )?
    } else {
        Engine::open(
            &config.database,
            &config.checkpoint,
            policy,
            verifier,
            admission,
            batch_tip,
            control,
            origin,
        )?
    }
    .with_capacity_limits(hosted.storage_limits)?;
    if args.repair_interrupted_checkpoint {
        println!(
            "{}",
            serde_json::json!({"checkpoint_repaired":true,"version":10,"listener_started":false})
        );
        return Ok(());
    }
    eprintln!("zark_storage_usage {}", engine.storage_usage()?);
    host::serve(&config.hosted, Arc::new(engine))
}

fn exit_status(error: &anyhow::Error) -> i32 {
    if error.is::<bitcoin_tip::StartupUnavailable>() {
        75
    } else {
        78
    }
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        // No request, key bytes or private persisted record is ever printed.
        eprintln!("zark signer: {error}");
        // Configuration/state failures require operator inspection; node warmup retries.
        std::process::exit(exit_status(&error));
    }
}

#[cfg(test)]
#[path = "main/tests.rs"]
mod tests;
