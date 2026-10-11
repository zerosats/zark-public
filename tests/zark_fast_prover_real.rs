//! Explicit synthetic application-path qualification and four-population timing.
//! No live wallet, Bitcoin RPC, signer, or public deployment is modified.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::Instant,
};
use zark_protocol::{hash, hex32, random32};
use zark_wallet::prover::{BinaryPin, FastRuntime, Program, Prover};

#[derive(Clone, Deserialize)]
struct Config {
    manifest: PathBuf,
    manifest_sha256: String,
    programs: PathBuf,
    nargo: BinaryPin,
    bb: BinaryPin,
    crs: PathBuf,
    fast_runtime: FastRuntime,
    fixtures: PathBuf,
}

fn fixture(path: &Path) -> Result<Value> {
    let input: toml::Value = toml::from_str(&fs::read_to_string(path)?)?;
    let mut value = serde_json::to_value(input)?;
    // Qualified TOML uses decimal strings even for u8 arrays. Only the public
    // statement is normalized here; the prover derives its packed fields anew.
    let bytes = value["statement"]
        .as_array()
        .context("statement")?
        .iter()
        .map(|v| {
            v.as_u64()
                .map(Ok)
                .unwrap_or_else(|| v.as_str().context("byte")?.parse().map_err(Into::into))
                .and_then(|n| u8::try_from(n).map_err(Into::into))
        })
        .collect::<Result<Vec<_>>>()?;
    value["statement"] = json!(bytes);
    Ok(value)
}

fn proof_fields(proof: &[u8]) -> Value {
    json!(
        proof
            .chunks_exact(32)
            .map(|f| format!("0x{}", hex::encode(f)))
            .collect::<Vec<_>>()
    )
}

fn sample(
    prover: &Prover,
    root: &Path,
    role: &str,
    label: &str,
    values: &Value,
) -> Result<(Vec<u8>, Value)> {
    let started = Instant::now();
    let input = root.join(format!("{label}.toml"));
    let statement: Vec<u8> = serde_json::from_value(values["statement"].clone())?;
    prover.write_json_witness(role, values, &input)?;
    let input_seconds = started.elapsed().as_secs_f64();
    let job = root.join(label);
    let (proof, timing) = prover.prove_measured(role, &input, &job, &statement)?;
    ensure!(!timing.reused, "benchmark must execute a fresh job");
    let row = json!({"role":role,"population":label,"input_serialization_seconds":input_seconds,
        "user_visible_seconds":started.elapsed().as_secs_f64(),"timing":timing,
        "witness_plus_prove_seconds":timing.witness_seconds+timing.prove_seconds,
        "proof_sha256":hex::encode(hash(&[&proof])), "externally_verified":true});
    Ok((proof, row))
}

fn memory() -> Value {
    let read = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    json!({"vm_stat":read("/usr/bin/vm_stat", &[]),
        "swap":read("/usr/sbin/sysctl", &["vm.swapusage"])})
}

/// Built by `cargo build --example malicious-fast-helper` beside this test.
fn malicious_helper() -> Result<PathBuf> {
    let path = std::env::current_exe()?
        .parent()
        .and_then(Path::parent)
        .context("test target directory")?
        .join("examples/malicious-fast-helper");
    ensure!(
        path.is_file(),
        "build the test-only helper first: cargo build --example malicious-fast-helper"
    );
    Ok(path)
}

fn open(config: &Config) -> Result<Prover> {
    Prover::new(
        &config.manifest,
        &hex32(&config.manifest_sha256)?,
        config.nargo.clone(),
        config.bb.clone(),
        config.crs.clone(),
        serde_json::from_slice::<Vec<Program>>(&fs::read(&config.programs)?)?,
    )?
    .with_fast_runtime(config.fast_runtime.clone())
}

#[test]
#[ignore = "requires explicit ZARK_RUN_FAST_PROVER=1 and isolated authenticated ZARK_FAST_PROVER_CONFIG"]
fn application_prover_qualifies_six_roles_and_measures_fresh_linked_transfers() -> Result<()> {
    ensure!(
        std::env::var("ZARK_RUN_FAST_PROVER").as_deref() == Ok("1"),
        "explicit opt-in required"
    );
    let config: Config = serde_json::from_slice(&fs::read(
        std::env::var_os("ZARK_FAST_PROVER_CONFIG").context("isolated fast prover config")?,
    )?)?;
    let initialize = Instant::now();
    let prover = open(&config)?;
    let initialization_seconds = initialize.elapsed().as_secs_f64();
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("work/integrate-fast-prover");
    fs::create_dir_all(&parent)?;
    let root = parent.join(format!("application-{}", hex::encode(random32())));
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut report = json!({"completed":false,"measurement_version":2,"source":"Rust application Prover API",
        "witness_scope":"helper startup, direct execution and cleanup; asset validation reported separately",
        "live_bitcoin":false,"live_signer":false,"initialization_seconds":initialization_seconds,
        "memory_before":memory(),"samples":[],"other_roles":[]});
    report["manifest_sha256"] = json!(config.manifest_sha256);
    let save = |report: &Value| -> Result<()> {
        zark_protocol::storage::atomic_write(
            &root.join("report.json"),
            &serde_json::to_vec_pretty(report)?,
        )
    };
    save(&report)?;
    for (role, name) in [
        ("deposit_authorization", "deposit"),
        ("exit_from_origin", "exit-0"),
        ("exit_from_transfer", "exit-2"),
    ] {
        let values = fixture(&config.fixtures.join(format!("{name}.toml")))?;
        let (_, row) = sample(&prover, &root, role, name, &values)?;
        report["other_roles"].as_array_mut().unwrap().push(row);
        save(&report)?;
    }
    for round in 1..=5 {
        for (population, sender_role, sender_name, receiver_name) in [
            ("repeat", "sender_from_transfer", "sender-2", "receiver-2"),
            ("origin", "sender_from_origin", "sender-1", "receiver-1"),
        ] {
            let sender = fixture(&config.fixtures.join(format!("{sender_name}.toml")))?;
            let (proof, row) = sample(
                &prover,
                &root,
                sender_role,
                &format!("{population}-sender-{round}"),
                &sender,
            )?;
            let sender_sha = hex::encode(hash(&[&proof]));
            report["samples"].as_array_mut().unwrap().push(row);
            save(&report)?;
            let mut receiver = fixture(&config.fixtures.join(format!("{receiver_name}.toml")))?;
            receiver["handover_proof"] = proof_fields(&proof);
            let (_, mut row) = sample(
                &prover,
                &root,
                "receiver_authorization",
                &format!("{population}-receiver-{round}"),
                &receiver,
            )?;
            row["own_fresh_sender_proof_sha256"] = json!(sender_sha);
            report["samples"].as_array_mut().unwrap().push(row);
            save(&report)?;
        }
    }
    let mut populations = serde_json::Map::new();
    for name in [
        "repeat-sender",
        "repeat-receiver",
        "origin-sender",
        "origin-receiver",
    ] {
        let rows: Vec<_> = report["samples"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["population"].as_str().unwrap().starts_with(name))
            .collect();
        let mut values: Vec<_> = rows
            .iter()
            .map(|r| r["witness_plus_prove_seconds"].as_f64().unwrap())
            .collect();
        values.sort_by(f64::total_cmp);
        ensure!(values.len() == 5, "five fresh samples required");
        populations.insert(name.into(),json!({"mean_seconds":values.iter().sum::<f64>()/5.0,
            "median_seconds":values[2],"max_seconds":values[4],
            "user_visible_mean_seconds":rows.iter().map(|r|r["user_visible_seconds"].as_f64().unwrap()).sum::<f64>()/5.0}));
    }
    report["populations"] = json!(populations);
    report["memory_after"] = memory();
    save(&report)?;
    // Reopen the application prover and require exact completed output. A
    // corrupted completed proof is rejected instead of replaced with a new one.
    let reopened = open(&config)?;
    let input = root.join("origin-sender-1.toml");
    let job = root.join("origin-sender-1");
    let values = fixture(&input)?;
    let statement: Vec<u8> = serde_json::from_value(values["statement"].clone())?;
    let (proof, timing) =
        reopened.prove_measured("sender_from_origin", &input, &job, &statement)?;
    ensure!(timing.reused, "restart must reuse exact verified proof");
    let mut changed = statement.clone();
    changed[10] ^= 1;
    ensure!(
        reopened
            .prove("sender_from_origin", &input, &job, &changed)
            .is_err(),
        "changed retry admitted"
    );
    let completed: Value = serde_json::from_slice(&fs::read(job.join("completed.json"))?)?;
    let proof_path = job
        .join(format!(
            "attempt-{}",
            completed["attempt"].as_str().unwrap()
        ))
        .join("proof");
    let mut corrupt = proof.clone();
    corrupt[100] ^= 1;
    fs::write(&proof_path, corrupt)?;
    ensure!(
        reopened
            .prove("sender_from_origin", &input, &job, &statement)
            .is_err(),
        "corrupted receipt admitted"
    );
    fs::write(&proof_path, &proof)?; // Restore this isolated synthetic fixture for evidence inspection.
    report["restart_exact_retry_changed_input_and_corruption_controls"] = json!(true);
    // Native hints are untrusted even when the runtime is locally configured.
    // The test-only examples/malicious-fast-helper.rs flips one honest limb of
    // the oracle named in its file name; each copy is explicitly pinned.
    let malicious = |name: &str| -> Result<BinaryPin> {
        let path = root.join(name);
        fs::copy(malicious_helper()?, &path)?;
        Ok(BinaryPin {
            sha256: hex::encode(hash(&[&fs::read(&path)?])),
            path,
        })
    };
    let changed_helper = root.join("changed-helper");
    fs::copy(&config.fast_runtime.helper.path, &changed_helper)?;
    let mut mutant = config.clone();
    mutant.fast_runtime.helper.path = changed_helper.clone();
    let authenticated = open(&mutant)?;
    fs::copy(malicious_helper()?, &changed_helper)?;
    let changed_job = root.join("changed-runtime-job");
    ensure!(
        authenticated
            .prove("sender_from_origin", &input, &changed_job, &statement)
            .is_err()
            && !changed_job.exists(),
        "changed authenticated runtime reached private job preparation"
    );
    ensure!(
        open(&mutant).is_err(),
        "restart skipped full asset authentication"
    );
    report["runtime_mutation_and_restart_pin_controls"] = json!(true);
    for (helper, job, message) in [
        (
            "malicious-batch-helper",
            "malicious-batch-hint-job",
            "malicious batch-GLV transcript admitted",
        ),
        (
            "malicious-fixed-helper",
            "malicious-fixed-hint-job",
            "malicious fixed-generator transcript admitted",
        ),
    ] {
        let mut mutant = config.clone();
        mutant.fast_runtime.helper = malicious(helper)?;
        let evil = open(&mutant)?;
        let evil_job = root.join(job);
        ensure!(
            evil.prove("sender_from_origin", &input, &evil_job, &statement)
                .is_err(),
            "{message}"
        );
        ensure!(
            !evil_job.join("completed.json").exists(),
            "failed hint committed output"
        );
    }
    // Invalid packing must fail inside the circuit, not merely at output check.
    let mut packed: toml::Value = toml::from_str(&fs::read_to_string(&input)?)?;
    packed["packed"].as_array_mut().context("packed input")?[0] = toml::Value::String("0".into());
    let bad_input = root.join("bad-packing.toml");
    zark_protocol::storage::atomic_write(&bad_input, toml::to_string(&packed)?.as_bytes())?;
    let bad_job = root.join("bad-packing-job");
    ensure!(
        reopened
            .prove("sender_from_origin", &bad_input, &bad_job, &statement)
            .is_err(),
        "incorrect packed statement admitted"
    );
    ensure!(
        !bad_job.join("completed.json").exists(),
        "failed packing committed output"
    );
    report["malicious_hint_and_packing_controls"] = json!(true);
    report["completed"] = json!(true);
    save(&report)?;
    println!(
        "Application proof measurements: {}",
        root.join("report.json").display()
    );
    Ok(())
}
