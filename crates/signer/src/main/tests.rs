use super::*;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::time::{SystemTime, UNIX_EPOCH};
use zark_protocol::{random32, scalar};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("zark-signer-config-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path.canonicalize()?))
    }
    fn file(&self, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = self.0.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(bytes)?;
        Ok(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn signing_key_requires_exact_private_file_and_normalized_scalar() -> Result<()> {
    let scratch = Scratch::new()?;
    let key = SigningKey::from_bytes(&[7; 32])?;
    let normalized: Digest = key.to_bytes().into();
    let path = scratch.file("key", &normalized)?;
    assert_eq!(read_key(&path)?.verifying_key(), key.verifying_key());
    let negated: Digest = (-scalar(&normalized)?).to_bytes().into();
    assert!(read_key(&scratch.file("negated", &negated)?).is_err());
    assert!(read_key(&scratch.file("short", &[1; 31])?).is_err());
    assert!(read_key(&scratch.file("hex", hex::encode(normalized).as_bytes())?).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(read_key(&path).is_err());
    Ok(())
}

#[test]
fn key_reader_rejects_symlinks_hardlinks_and_shared_directories() -> Result<()> {
    let scratch = Scratch::new()?;
    let key = SigningKey::from_bytes(&[7; 32])?;
    let path = scratch.file("key", &key.to_bytes())?;
    let linked = scratch.0.join("link");
    symlink(&path, &linked)?;
    assert!(read_key(&linked).is_err());
    fs::hard_link(&path, scratch.0.join("hardlink"))?;
    assert!(read_key(&path).is_err());
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755))?;
    assert!(private_path(&scratch.0.join("new-key")).is_err());
    Ok(())
}

#[test]
fn key_generation_never_overwrites_a_saved_key() -> Result<()> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("fresh");
    generate_key(&path)?;
    let original = Zeroizing::new(fs::read(&path)?);
    read_key(&path)?;
    assert!(generate_key(&path).is_err());
    assert_eq!(*original, fs::read(&path)?);
    Ok(())
}

#[test]
fn trusted_pins_are_exact_and_bounded() -> Result<()> {
    let scratch = Scratch::new()?;
    let path = scratch.file("asset", b"qualified bytes")?;
    let digest = hex::encode(hash(&[b"qualified bytes"]));
    check_file_pin(&path, &digest, 100)?;
    assert!(check_file_pin(&path, &digest, 4).is_err());
    assert!(check_file_pin(&path, &"ab".repeat(32), 100).is_err());
    fs::write(&path, b"replaced bytes")?;
    assert!(check_file_pin(&path, &digest, 100).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
    assert!(read_trusted(&path, 100).is_err());
    assert!(canonical_digest(&"AB".repeat(32)).is_err());
    Ok(())
}

fn hosted_value(coin: Digest, expires: u64) -> serde_json::Value {
    serde_json::json!({"version":10,"listen":"127.0.0.1:7448",
        "certificate":"/synthetic/certificate.pem","private_key":"/synthetic/key.pem",
        "credentials":[{"sha256":hex::encode(hash(&[b"synthetic-token"])),
            "coins":[hex::encode(coin)],"expires_at":expires,"max_inflight":1,"requests_per_minute":10}],
        "network_workers":1,"proof_workers":1,"queue_capacity":1})
}

#[test]
fn configured_admission_binds_deployment_coin_and_current_expiry() -> Result<()> {
    let scratch = Scratch::new()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let path = scratch.file(
        "hosted.json",
        &serde_json::to_vec(&hosted_value([2; 32], now + 60))?,
    )?;
    let admission = ConfiguredAdmission {
        deployment: [1; 32],
        hosted: path.clone(),
    };
    let key = SigningKey::from_bytes(&[7; 32])?;
    let context = TransferContext {
        start_revision: 0,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: [3; 32],
        operation: [4; 32],
        recipient_claim: [5; 32],
        session_auth: key.verifying_key().to_bytes().into(),
    };
    admission.authorize(&context)?;
    let mut other = context.clone();
    other.deployment = [9; 32];
    assert!(admission.authorize(&other).is_err());
    other = context.clone();
    other.coin = [9; 32];
    assert!(admission.authorize(&other).is_err());
    fs::write(&path, serde_json::to_vec(&hosted_value([2; 32], now - 1))?)?;
    assert!(admission.authorize(&context).is_err());
    let mut changed = hosted_value([2; 32], now + 60);
    changed["credentials"] = serde_json::json!([]);
    changed["public_access"] =
        serde_json::json!({"max_inflight":2,"requests_per_minute":60,"allocations_per_minute":10});
    fs::write(&path, serde_json::to_vec(&changed)?)?;
    admission.authorize(&context)?;
    admission.authorize(&other)?; // A new coin requires no pre-registration.
    other.deployment = [9; 32];
    assert!(admission.authorize(&other).is_err());
    changed["version"] = 7.into();
    fs::write(&path, serde_json::to_vec(&changed)?)?;
    assert!(admission.authorize(&context).is_err());
    Ok(())
}

#[test]
fn service_lock_excludes_second_service_and_survives_failed_attempt() -> Result<()> {
    let scratch = Scratch::new()?;
    let path = private_path(&scratch.0.join("zark-service.lock"))?;
    let first = ProcessLock::acquire(&path)?;
    assert!(ProcessLock::acquire(&path).is_err());
    assert!(ProcessLock::acquire(&path).is_err());
    drop(first);
    ProcessLock::acquire(&path)?;
    Ok(())
}

#[test]
fn cli_requires_explicit_repair_and_separates_key_generation() {
    assert!(Args::try_parse_from(["signer"]).is_err());
    let args = Args::try_parse_from(["signer", "--config", "/operator.json"]).unwrap();
    assert!(!args.repair_interrupted_checkpoint && !args.check_config);
    assert!(Args::try_parse_from(["signer", "--repair-interrupted-checkpoint"]).is_err());
    assert!(
        Args::try_parse_from([
            "signer",
            "--config",
            "/operator.json",
            "--check-config",
            "--repair-interrupted-checkpoint"
        ])
        .is_err()
    );
    assert!(
        Args::try_parse_from([
            "signer",
            "--config",
            "/operator.json",
            "--generate-key",
            "/key"
        ])
        .is_err()
    );
}

#[test]
fn startup_retry_is_distinct_from_fatal_configuration_and_state() {
    assert_eq!(exit_status(&anyhow::anyhow!("checkpoint mismatch")), 78);
    assert_eq!(exit_status(&anyhow::anyhow!("pinned file mismatch")), 78);
    let unavailable = anyhow::anyhow!("RPC connection failed")
        .context(bitcoin_tip::StartupUnavailable)
        .context("startup");
    assert_eq!(exit_status(&unavailable), 75);
}
