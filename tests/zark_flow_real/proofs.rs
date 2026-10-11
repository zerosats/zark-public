//! Pinned proof jobs and byte-valued witness parsing.
use super::*;

impl Proofs {
    pub(super) fn owner_directory(&self, step: &str) -> PathBuf {
        let sender_step = ["reservation", "sender", "handover"]
            .iter()
            .any(|suffix| step.ends_with(&format!("-{suffix}")));
        let owner = OWNERS
            .windows(2)
            .find(|pair| step.starts_with(&format!("{}-{}-", pair[0], pair[1])))
            .map(|pair| if sender_step { pair[0] } else { pair[1] })
            .or_else(|| {
                OWNERS
                    .iter()
                    .copied()
                    .find(|owner| step.starts_with(&format!("{owner}-")))
            })
            .unwrap_or("alice");
        self.root.join(owner)
    }
    pub(super) fn input(&self, step: &str) -> PathBuf {
        self.owner_directory(step).join(format!("{step}.toml"))
    }
    pub(super) fn prove(&self, role: &str, step: &str) -> Result<Vec<u8>> {
        let input = self.input(step);
        let statement = public_inputs(role, &input)?;
        eprintln!("real-flow: proving {step} ({role})");
        let proof = self
            .prover
            .prove(
                role,
                &input,
                &self.owner_directory(step).join(format!("{step}-job")),
                &statement,
            )
            .with_context(|| format!("real proof stage {step}"))?;
        *self.counts.borrow_mut().entry(role.into()).or_default() += 1;
        Ok(proof)
    }
}

/// Read only public ABI fields from locally built private witnesses. Independent
/// wallet and Engine verifiers subsequently bind these bytes to current state.
pub(super) fn public_inputs(role: &str, path: &Path) -> Result<Vec<u8>> {
    let text = Zeroizing::new(fs::read_to_string(path)?);
    let document: toml::Value = toml::from_str(&text)?;
    ensure!(ROLE_NAMES.contains(&role), "unsupported proof role");
    toml_bytes(&document, "statement")
}

pub(super) fn toml_bytes(document: &toml::Value, name: &str) -> Result<Vec<u8>> {
    document
        .get(name)
        .and_then(toml::Value::as_array)
        .context("public witness array")?
        .iter()
        .map(|value| {
            let integer = if let Some(integer) = value.as_integer() {
                u64::try_from(integer)?
            } else {
                let string = value.as_str().context("public witness byte")?;
                if let Some(hex) = string.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)?
                } else {
                    string.parse()?
                }
            };
            u8::try_from(integer).context("public witness field is not a byte")
        })
        .collect()
}
