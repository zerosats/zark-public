//! Explicit actual-backend regression for owner-local proving and exact retry.
//! Reads only generated synthetic qualification inputs, never a live wallet.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zark_protocol::{hex32, random32};
use zark_wallet::prover::{BinaryPin, Program, Prover};

#[derive(Deserialize)]
struct Config {
    manifest: PathBuf,
    manifest_sha256: String,
    programs: PathBuf,
    nargo: BinaryPin,
    bb: BinaryPin,
    crs: PathBuf,
}

#[test]
#[ignore = "explicit local real prover qualification; requires ZARK_RUN_REAL_PROVER=1 and assembled suite"]
fn actual_proof_stays_owner_local_and_resumes_only_exact_verified_output() -> Result<()> {
    ensure!(
        std::env::var("ZARK_RUN_REAL_PROVER").as_deref() == Ok("1"),
        "explicit real prover opt-in required"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let config: Config = serde_json::from_slice(&fs::read(
        std::env::var_os("ZARK_REAL_FLOW_CONFIG")
            .context("set authenticated ZARK_REAL_FLOW_CONFIG")?,
    )?)?;
    let programs: Vec<Program> = serde_json::from_slice(&fs::read(&config.programs)?)?;
    let prover = Prover::new(
        &config.manifest,
        &hex32(&config.manifest_sha256)?,
        config.nargo,
        config.bb,
        config.crs,
        programs,
    )?;
    let directory = root
        .join("work")
        .join(format!("zark-prover-real-{}", hex::encode(random32())));
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let source = PathBuf::from(
        std::env::var_os("ZARK_PLAN_C_SENDER_WITNESS")
            .context("set a fresh synthetic sender_from_origin witness")?,
    );
    let values: toml::Value = toml::from_str(&fs::read_to_string(source)?)?;
    let values = serde_json::to_value(values)?;
    let statement: Vec<u8> = values["statement"]
        .as_array()
        .context("synthetic public statement array")?
        .iter()
        .map(|value| {
            let byte = if let Some(integer) = value.as_u64() {
                integer
            } else {
                let text = value.as_str().context("synthetic public byte")?;
                if let Some(hex) = text.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)?
                } else {
                    text.parse()?
                }
            };
            u8::try_from(byte).context("synthetic public field is not a byte")
        })
        .collect::<Result<_>>()?;
    let input = directory.join("input.toml");
    prover.write_json_witness("sender_from_origin", &values, &input)?;
    let job = directory.join("job");
    let proof = prover.prove("sender_from_origin", &input, &job, &statement)?;
    assert_eq!(proof.len(), 458 * 32);
    assert_eq!(
        fs::metadata(job.join("witness.gz"))?.permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        proof,
        prover.prove("sender_from_origin", &input, &job, &statement)?
    );
    let mut wrong = statement.clone();
    wrong[10] ^= 1;
    assert!(
        prover
            .prove("sender_from_origin", &input, &job, &wrong)
            .is_err()
    );
    let completed: serde_json::Value =
        serde_json::from_slice(&fs::read(job.join("completed.json"))?)?;
    let output = job
        .join(format!(
            "attempt-{}",
            completed["attempt"].as_str().unwrap()
        ))
        .join("proof");
    let mut damaged = proof;
    damaged[100] ^= 1;
    fs::write(output, damaged)?;
    assert!(
        prover
            .prove("sender_from_origin", &input, &job, &statement)
            .is_err(),
        "a corrupted completed result is not silently replaced"
    );
    // An interrupted, uncommitted attempt must not become a permanent barrier.
    let incomplete = directory.join("interrupted-job");
    fs::DirBuilder::new().mode(0o700).create(&incomplete)?;
    let abandoned = incomplete.join(format!("attempt-{}", hex::encode(random32())));
    fs::DirBuilder::new().mode(0o700).create(&abandoned)?;
    fs::write(abandoned.join("proof"), b"truncated")?;
    let second = prover.prove("sender_from_origin", &input, &incomplete, &statement)?;
    assert_eq!(second.len(), 458 * 32);
    fs::write(
        directory.join("report.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
        "real_external_verification":true,"owner_local_witness_mode":"0600","exact_retry":true,
        "changed_statement_rejected":true,"corrupted_completed_result_rejected":true,"incomplete_attempt_resumable":true,
        "full_wallet_flow":false}))?,
    )?;
    println!(
        "Real prover report: {}",
        directory.join("report.json").display()
    );
    Ok(())
}
