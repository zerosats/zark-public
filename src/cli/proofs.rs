//! Freeze private witness inputs and resume only the same proof job.
use super::config::App;
use super::storage::{initialize_cli_local, new_directory, read_private, write_new};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::path::Path;
use zark_protocol::hash;

impl App {
    pub(super) fn prove(
        &self,
        root: &Path,
        role: &str,
        step: &str,
        writer: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let input_timing =
            zark_protocol::timing::Span::new(zark_protocol::timing::Phase::ProofInputFreeze);
        let input_directory = root.join("proofs").join(format!("{step}-input"));
        let intent =
            serde_json::to_vec(&json!({"role":role,"step":step,"metadata":self.metadata(root)?}))?;
        let path = initialize_cli_local(
            &input_directory,
            &intent,
            |attempt| {
                new_directory(attempt)?;
                let path = attempt.join("input.toml");
                writer(&path)?;
                let bytes = read_private(&path, 4_000_000)?;
                public_inputs(role, &path)?;
                // Only the successful writer can publish this completion pin.
                write_new(
                    &attempt.join("input.sha256"),
                    hex::encode(hash(&[&bytes])).as_bytes(),
                )?;
                Ok(path)
            },
            |published| {
                let path = published.join("input.toml");
                let bytes = read_private(&path, 4_000_000)?;
                ensure!(
                    *read_private(&published.join("input.sha256"), 64)?
                        == hex::encode(hash(&[&bytes])).as_bytes(),
                    "completed private witness changed"
                );
                public_inputs(role, &path)?;
                Ok(path)
            },
        )?;
        let bytes = public_inputs(role, &path)?;
        drop(input_timing);
        eprintln!("Proving {step}…");
        let (proof, timings) = self.p()?.prove_measured(
            role,
            &path,
            &root.join("proofs").join(format!("{step}-job")),
            &bytes,
        )?;
        // Opt-in diagnostics contain only durations and a reuse flag. Never
        // include witness values, operation paths or peer-controlled text.
        if std::env::var("ZARK_TIMINGS").as_deref() == Ok("1") {
            eprintln!("ZARK_PROOF_TIMING {}", serde_json::to_string(&timings)?);
        }
        Ok(proof)
    }
}

pub(super) fn public_inputs(role: &str, path: &Path) -> Result<Vec<u8>> {
    let bytes = read_private(path, 4_000_000)?;
    let value = parse_private_witness(&bytes)?;
    ensure!(
        zark_protocol::deployment::ROLE_NAMES.contains(&role),
        "unsupported proof role"
    );
    toml_bytes(&value, "statement")
}
pub(super) fn parse_private_witness(bytes: &[u8]) -> Result<toml::Value> {
    // TOML diagnostics include offending source lines. Never retain that error
    // as a cause: the CLI prints the complete cause chain on failure.
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("invalid private witness encoding"))?;
    toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid private witness TOML"))
}
pub(super) fn toml_bytes(value: &toml::Value, name: &str) -> Result<Vec<u8>> {
    value
        .get(name)
        .and_then(toml::Value::as_array)
        .context("missing public witness field")?
        .iter()
        .map(|field| {
            let n = if let Some(n) = field.as_integer() {
                u64::try_from(n)?
            } else {
                let s = field.as_str().context("public field must be a byte")?;
                if let Some(s) = s.strip_prefix("0x") {
                    u64::from_str_radix(s, 16)?
                } else {
                    s.parse()?
                }
            };
            u8::try_from(n).context("public field exceeds byte range")
        })
        .collect()
}
