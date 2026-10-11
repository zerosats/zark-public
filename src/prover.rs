//! Owner-local v10 proving. Shared circuit/key directories contain public assets;
//! private TOML, witnesses and proof intermediates stay in a private job directory.
//! Child CPU time, wall time and output-file size are bounded. Worker counts
//! are explicit per phase. Memory and aggregate job storage are not capped.
//! This is not an OS sandbox against a malicious executable or another process
//! running as the wallet's user.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
use zark_protocol::{
    assets::{
        MAX_CIRCUIT_BYTES, MAX_CONFIG_BYTES, MAX_EXECUTABLE_BYTES, read_bounded, sha256_bounded,
    },
    deployment::{Manifest, ROLE_NAMES},
    handoff::Digest,
    hash, hex32,
    local::ProcessLock,
    proof::PROOF_BYTES,
    public_fields, random32,
    storage::atomic_write,
    verifier::verify_proof_with_threads,
};
use zeroize::Zeroizing;

#[derive(Default, Serialize)]
pub struct ProvingTimings {
    pub asset_validation_seconds: f64,
    pub input_preparation_seconds: f64,
    pub witness_seconds: f64,
    pub witness_asset_validation_seconds: f64,
    pub prove_seconds: f64,
    pub verify_seconds: f64,
    pub persistence_seconds: f64,
    pub output_validation_verify_persistence_seconds: f64,
    pub total_seconds: f64,
    pub reused: bool,
}

const MAX_INPUT: usize = 4 * 1024 * 1024;

pub(crate) fn packed_witness(output: &mut String, statement: &[u8]) -> Result<()> {
    use std::fmt::Write;
    output.push_str("packed = [");
    for (i, field) in public_fields(statement).chunks_exact(32).enumerate() {
        if i != 0 {
            output.push(',');
        }
        write!(output, "\"0x{}\"", hex::encode(field))?;
    }
    output.push_str("]\n");
    Ok(())
}
mod assets;
mod process;
mod runtime;
use assets::AuthenticatedAssets;
use process::run;
pub use runtime::FastRuntime;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryPin {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub role: String,
    pub directory: PathBuf,
    /// Nargo's compiled artifact. It must match this role's circuit.json pin.
    pub artifact: PathBuf,
}

pub struct Prover {
    suite: Manifest,
    suite_id: Digest,
    suite_directory: PathBuf,
    nargo: BinaryPin,
    bb: BinaryPin,
    crs: PathBuf,
    programs: BTreeMap<String, Program>,
    runtime: Option<FastRuntime>,
    assets: AuthenticatedAssets,
    runtime_assets: Option<AuthenticatedAssets>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Job {
    version: u32,
    role: String,
    suite: String,
    input_sha256: String,
    statement: String,
    nargo_sha256: String,
    bb_sha256: String,
    #[serde(default)]
    runtime_identity: Option<String>,
}

impl Job {
    /// Why a saved job cannot resume as `expected`. Both are refusals; naming a
    /// runtime-only difference keeps a job frozen under a retired helper from
    /// looking like changed private input.
    fn mismatch(&self, expected: &Self) -> &'static str {
        let same_inputs = Self {
            runtime_identity: expected.runtime_identity.clone(),
            ..self.clone()
        } == *expected;
        if same_inputs {
            "proof job is frozen under a different prover runtime; finish it with that runtime"
        } else {
            "proof job is frozen for different inputs"
        }
    }
}

impl Prover {
    /// Convert only the exact pinned circuit ABI inputs to private TOML. Native
    /// fixture metadata is not a circuit input and is never passed to Nargo.
    pub fn write_json_witness(
        &self,
        role: &str,
        values: &serde_json::Value,
        path: &Path,
    ) -> Result<()> {
        let program = self.check_program(role)?;
        let artifact: serde_json::Value =
            serde_json::from_slice(&read_bounded(&program.artifact, MAX_CIRCUIT_BYTES)?)?;
        self.assets.check()?;
        let parameters = artifact["abi"]["parameters"]
            .as_array()
            .context("compiled prover ABI")?;
        let mut table = toml::map::Map::new();
        for p in parameters {
            let name = p["name"].as_str().context("prover ABI parameter")?;
            // Construct the packed public input from authoritative canonical
            // bytes; the circuit independently binds every statement byte.
            let packed;
            let value = if name == "packed" {
                let statement: Vec<u8> = serde_json::from_value(
                    values
                        .get("statement")
                        .context("missing statement")?
                        .clone(),
                )?;
                packed = serde_json::Value::Array(
                    public_fields(&statement)
                        .chunks_exact(32)
                        .map(|field| serde_json::Value::String(format!("0x{}", hex::encode(field))))
                        .collect(),
                );
                &packed
            } else {
                values.get(name).context("missing private circuit input")?
            };
            ensure!(
                table.insert(name.into(), toml_value(value)?).is_none(),
                "duplicate prover ABI parameter"
            );
        }
        let text = Zeroizing::new(toml::to_string(&toml::Value::Table(table))?);
        ensure!(text.len() <= MAX_INPUT, "private TOML input too large");
        check_directory(path.parent().context("private witness parent")?)?;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::File::open(path.parent().unwrap())?.sync_all()?;
        Ok(())
    }
    /// The manifest hash and executable pins must be authenticated by the local
    /// deployment configuration, never supplied by an incoming coin or offer.
    pub fn new(
        manifest_path: &Path,
        manifest_sha256: &Digest,
        nargo: BinaryPin,
        bb: BinaryPin,
        crs: PathBuf,
        programs: Vec<Program>,
    ) -> Result<Self> {
        let bytes = read_bounded(manifest_path, MAX_CONFIG_BYTES)?;
        ensure!(
            *manifest_sha256 != [0; 32] && hash(&[&bytes]) == *manifest_sha256,
            "prover manifest pin mismatch"
        );
        let suite: Manifest = serde_json::from_slice(&bytes)?;
        let directory = manifest_path
            .parent()
            .context("suite directory")?
            .canonicalize()?;
        let mut registry = BTreeMap::new();
        for mut p in programs {
            ensure!(ROLE_NAMES.contains(&p.role.as_str()), "unknown prover role");
            p.directory = p.directory.canonicalize()?;
            p.artifact = p.artifact.canonicalize()?;
            ensure!(
                p.artifact.starts_with(&p.directory),
                "compiled circuit outside its program"
            );
            ensure!(
                registry.insert(p.role.clone(), p).is_none(),
                "duplicate prover role"
            );
        }
        ensure!(
            registry.len() == ROLE_NAMES.len(),
            "incomplete prover programs"
        );
        let mut files = vec![nargo.path.clone(), bb.path.clone()];
        for role in ROLE_NAMES {
            for name in ["circuit.json", "vk", "vk.json"] {
                files.push(directory.join(role).join(name));
            }
            files.push(registry[role].artifact.clone());
        }
        let assets = AuthenticatedAssets::authenticate(&files, || {
            suite.check_artifacts(&directory)?;
            check_binary(&nargo)?;
            check_binary(&bb)?;
            for pin in &suite.roles {
                ensure!(
                    sha256_bounded(&registry[&pin.role].artifact, MAX_CIRCUIT_BYTES as u64)?
                        == hex32(&pin.compiled_artifact_sha256)?,
                    "compiled prover artifact changed"
                );
            }
            Ok(())
        })?;
        let prover = Self {
            suite_id: suite.id()?,
            suite,
            suite_directory: directory,
            nargo,
            bb,
            crs: crs.canonicalize()?,
            programs: registry,
            runtime: None,
            assets,
            runtime_assets: None,
        };
        Ok(prover)
    }

    pub fn with_fast_runtime(mut self, runtime: FastRuntime) -> Result<Self> {
        self.runtime_assets = Some(runtime.authenticate()?);
        self.runtime = Some(runtime);
        Ok(self)
    }

    fn check_program(&self, role: &str) -> Result<&Program> {
        self.assets.check()?;
        self.programs.get(role).context("unknown prover role")
    }

    fn check_assets(&self) -> Result<()> {
        self.assets.check()?;
        if let Some(assets) = &self.runtime_assets {
            assets.check()?;
        }
        Ok(())
    }

    /// Resume is permitted only for the identical private input, statement and
    /// pinned suite. An existing proof is externally verified before reuse.
    pub fn prove(
        &self,
        role: &str,
        input: &Path,
        job_directory: &Path,
        statement: &[u8],
    ) -> Result<Vec<u8>> {
        self.prove_measured(role, input, job_directory, statement)
            .map(|(proof, _)| proof)
    }

    /// Measures the same application path, including authentication, exact-job
    /// preparation, helper lifecycle, output verification and durable receipt.
    pub fn prove_measured(
        &self,
        role: &str,
        input: &Path,
        job_directory: &Path,
        statement: &[u8],
    ) -> Result<(Vec<u8>, ProvingTimings)> {
        let started = Instant::now();
        let mut timings = ProvingTimings::default();
        let program = self.check_program(role)?;
        let pin = self
            .suite
            .roles
            .iter()
            .find(|p| p.role == role)
            .context("prover role pin")?;
        ensure!(
            statement.len() == pin.public_bytes as usize,
            "prover statement ABI mismatch"
        );
        self.check_assets()?;
        timings.asset_validation_seconds = started.elapsed().as_secs_f64();
        let preparation = Instant::now();
        let private_input = read_private(input, MAX_INPUT)?;
        let parent = job_directory.parent().context("proof job parent")?;
        check_directory(parent)?;
        if !job_directory.try_exists()? {
            fs::DirBuilder::new().mode(0o700).create(job_directory)?;
            fs::File::open(parent)?.sync_all()?;
        }
        check_directory(job_directory)?;
        let directory = job_directory.canonicalize()?;
        ensure!(
            !directory.starts_with(&self.suite_directory)
                && !directory.starts_with(&program.directory),
            "private prover job must not use a shared circuit directory"
        );
        let _lock = ProcessLock::acquire(&directory.join(".lock"))?;
        let expected = Job {
            version: 1,
            role: role.into(),
            suite: hex::encode(self.suite_id),
            input_sha256: hex::encode(hash(&[&private_input])),
            statement: hex::encode(statement),
            nargo_sha256: self.nargo.sha256.clone(),
            bb_sha256: self.bb.sha256.clone(),
            runtime_identity: self
                .runtime
                .as_ref()
                .map(FastRuntime::identity)
                .transpose()?,
        };
        let record = directory.join("job.json");
        if record.try_exists()? {
            let saved: Job = serde_json::from_slice(&read_private(&record, 32_768)?)
                .map_err(|_| anyhow::anyhow!("invalid private proof job"))?;
            ensure!(saved == expected, "{}", saved.mismatch(&expected));
            ensure!(
                *read_private(&directory.join("input.toml"), MAX_INPUT)? == *private_input,
                "frozen prover input changed"
            );
        } else {
            // Input is written first; interrupted preparation can only finish
            // for the exact same input on retry.
            let saved = directory.join("input.toml");
            if saved.try_exists()? {
                ensure!(
                    *read_private(&saved, MAX_INPUT)? == *private_input,
                    "incomplete proof job has different input"
                );
            } else {
                atomic_write(&saved, &private_input)?;
            }
            atomic_write(&record, &serde_json::to_vec(&expected)?)?;
        }
        let receipt = directory.join("completed.json");
        timings.input_preparation_seconds = preparation.elapsed().as_secs_f64();
        let verification = Instant::now();
        if receipt.try_exists()? {
            let completed: Completion = serde_json::from_slice(&read_private(&receipt, 1024)?)
                .map_err(|_| anyhow::anyhow!("invalid proof completion receipt"))?;
            ensure!(
                hex::encode(hex32(&completed.attempt)?) == completed.attempt,
                "invalid proof attempt"
            );
            let proof = self.check_output(
                role,
                &directory,
                &directory.join(format!("attempt-{}", completed.attempt)),
                statement,
                &mut timings,
            )?;
            ensure!(
                hash(&[&proof]) == hex32(&completed.proof_sha256)?,
                "completed proof changed"
            );
            timings.reused = true;
            timings.output_validation_verify_persistence_seconds =
                verification.elapsed().as_secs_f64();
            timings.total_seconds = started.elapsed().as_secs_f64();
            return Ok((proof, timings));
        }
        // An interrupted BB process may leave a truncated proof. Such files
        // have no completion receipt and are never mistaken for a frozen result.
        let attempt = hex::encode(random32());
        let output = directory.join(format!("attempt-{attempt}"));
        fs::DirBuilder::new().mode(0o700).create(&output)?;
        let witness_started = Instant::now();
        self.check_assets()?;
        timings.witness_asset_validation_seconds = witness_started.elapsed().as_secs_f64();
        if let Some(runtime) = &self.runtime {
            runtime.execute(role, &program.artifact, &directory)?;
        } else {
            let mut execute = Command::new(&self.nargo.path);
            execute
                .arg("execute")
                .arg(directory.join("witness"))
                .arg("--program-dir")
                .arg(&program.directory)
                .arg("--prover-name")
                .arg(directory.join("input"));
            run(
                &mut execute,
                &directory,
                "private witness execution failed",
                4,
                false,
            )?;
        }
        let witness_checking = Instant::now();
        self.check_assets()?;
        let witness = directory.join("witness.gz");
        let metadata = fs::symlink_metadata(&witness)?;
        check_private_file(&metadata)?;
        ensure!(metadata.len() > 0, "empty private witness");
        timings.witness_asset_validation_seconds += witness_checking.elapsed().as_secs_f64();
        timings.witness_seconds =
            witness_started.elapsed().as_secs_f64() - timings.witness_asset_validation_seconds;
        let proof_started = Instant::now();
        let mut prove = Command::new(
            self.runtime
                .as_ref()
                .map_or(&self.bb.path, |r| &r.prover.path),
        );
        prove
            .args(["prove", "-t", "noir-recursive", "-b"])
            .arg(&program.artifact)
            .arg("-w")
            .arg(&witness)
            .arg("-k")
            .arg(self.suite_directory.join(role).join("vk"))
            .arg("-o")
            .arg(&output)
            .arg("-c")
            .arg(&self.crs);
        run(
            &mut prove,
            &directory,
            "private proving failed",
            self.runtime.as_ref().map_or(4, |r| r.prove_threads),
            self.runtime.is_some(),
        )?;
        timings.prove_seconds = proof_started.elapsed().as_secs_f64();
        let verification = Instant::now();
        let proof = self.check_output(role, &directory, &output, statement, &mut timings)?;
        let receipt_started = Instant::now();
        atomic_write(
            &receipt,
            &serde_json::to_vec(&Completion {
                attempt,
                proof_sha256: hex::encode(hash(&[&proof])),
            })?,
        )?;
        timings.persistence_seconds += receipt_started.elapsed().as_secs_f64();
        timings.output_validation_verify_persistence_seconds = verification.elapsed().as_secs_f64();
        timings.total_seconds = started.elapsed().as_secs_f64();
        Ok((proof, timings))
    }

    fn check_output(
        &self,
        role: &str,
        directory: &Path,
        output: &Path,
        statement: &[u8],
        timings: &mut ProvingTimings,
    ) -> Result<Vec<u8>> {
        self.check_assets()?;
        let proof = read_private(&output.join("proof"), PROOF_BYTES)?;
        ensure!(proof.len() == PROOF_BYTES, "private proof size mismatch");
        let public = read_private(&output.join("public_inputs"), statement.len() * 32)?;
        ensure!(
            *public == public_fields(statement),
            "prover public statement mismatch"
        );
        let verify_started = Instant::now();
        verify_proof_with_threads(
            &self.bb.path,
            &self.suite_directory.join(role).join("vk"),
            &self.crs,
            directory,
            &proof,
            statement,
            self.runtime.as_ref().map_or(2, |r| r.verify_threads),
        )?;
        timings.verify_seconds += verify_started.elapsed().as_secs_f64();
        // Reject asset changes during verification before committing a receipt
        // or acknowledging an exact retry.
        self.check_assets()?;
        let persistence_started = Instant::now();
        fs::File::open(output.join("proof"))?.sync_all()?;
        fs::File::open(output.join("public_inputs"))?.sync_all()?;
        fs::File::open(output)?.sync_all()?;
        fs::File::open(directory)?.sync_all()?;
        timings.persistence_seconds += persistence_started.elapsed().as_secs_f64();
        Ok(proof.to_vec())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    attempt: String,
    proof_sha256: String,
}

fn toml_value(value: &serde_json::Value) -> Result<toml::Value> {
    Ok(match value {
        serde_json::Value::Array(values) => {
            toml::Value::Array(values.iter().map(toml_value).collect::<Result<_>>()?)
        }
        serde_json::Value::Bool(v) => toml::Value::Boolean(*v),
        serde_json::Value::Number(v) => {
            toml::Value::Integer(v.as_i64().context("private witness integer range")?)
        }
        serde_json::Value::String(v) => toml::Value::String(v.clone()),
        _ => anyhow::bail!("unsupported private witness ABI value"),
    })
}

fn check_binary(pin: &BinaryPin) -> Result<()> {
    let digest = hex32(&pin.sha256)?;
    ensure!(
        digest != [0; 32]
            && hex::encode(digest) == pin.sha256
            && sha256_bounded(&pin.path, MAX_EXECUTABLE_BYTES)? == digest,
        "prover executable pin mismatch"
    );
    Ok(())
}
fn check_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700,
        "proof directory must be private and owned"
    );
    Ok(())
}
fn check_private_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o600,
        "proof input/output must be a private owned file"
    );
    Ok(())
}
fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    check_directory(path.parent().context("private file parent")?)?;
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    check_private_file(&f.metadata()?)?;
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut f).take((limit + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "private proof file exceeds limit");
    Ok(bytes)
}

#[cfg(test)]
#[path = "prover_tests.rs"]
mod tests;
