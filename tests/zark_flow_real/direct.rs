//! Negative witnesses against a successfully completed synthetic real-proof run.
//! Baselines must execute first, and failures must name the expected constraint.
use super::*;

fn execute(
    config: &Config,
    program: &Program,
    directory: &Path,
    name: &str,
    value: &toml::Value,
    rejection: Option<&str>,
) -> Result<()> {
    let input = directory.join(format!("{name}.toml"));
    write_private(&input, toml::to_string(value)?.as_bytes())?;
    let output = Command::new(&config.nargo.path)
        .arg("execute")
        .arg(directory.join(name))
        .arg("--program-dir")
        .arg(&program.directory)
        .arg("-p")
        .arg(input.with_extension(""))
        .output()?;
    let log = String::from_utf8_lossy(&output.stderr).to_string()
        + &String::from_utf8_lossy(&output.stdout);
    write_private(&directory.join(format!("{name}.log")), log.as_bytes())?;
    match rejection {
        Some(message) => ensure!(
            !output.status.success() && log.contains(message),
            "{name}: expected constraint rejection {message}, got {log}"
        ),
        None => ensure!(output.status.success(), "{name}: baseline failed: {log}"),
    }
    Ok(())
}

pub(super) fn run() -> Result<()> {
    let config = Config::read()?;
    let run = PathBuf::from(
        std::env::var_os("ZARK_REAL_FLOW_RUN")
            .context("set ZARK_REAL_FLOW_RUN to a completed synthetic flow")?,
    );
    let report: Value = serde_json::from_slice(&fs::read(run.join("flow-report.json"))?)?;
    ensure!(
        report["fresh_signer_allocation"] == true
            && report["activation_published_during_exit"] == false
            && report["all_flow_roles_proved_and_externally_verified"] == true,
        "requires a successful fresh direct-exit flow"
    );
    let programs: Vec<Program> = serde_json::from_slice(&fs::read(&config.programs)?)?;
    let directory = run.join(format!(
        "direct-exit-rejections-{}",
        hex::encode(random32())
    ));
    private_dir(&directory)?;
    for (role, step, cases) in [
        (
            "exit_from_transfer",
            "carol-exit",
            vec![
                (
                    "deposit_txid",
                    "direct exit must spend the exact deposit behind this coin",
                ),
                (
                    "deposit_vout",
                    "direct exit must spend the exact deposit behind this coin",
                ),
                ("deposit_amount", "blinded immediate Bitcoin exit challenge"),
            ],
        ),
        (
            "deposit_authorization",
            "alice-deposit",
            vec![("parent_vout", "actual joint parent funding")],
        ),
    ] {
        let program = programs
            .iter()
            .find(|p| p.role == role)
            .context("proof program")?;
        let owner = if step.starts_with("carol-") {
            "carol"
        } else {
            "alice"
        };
        // The completed flow deliberately renames this directory while testing
        // recovery without access to any prover or private witness material.
        let input = run
            .join("proofs-unavailable")
            .join(owner)
            .join(format!("{step}.toml"));
        let baseline: toml::Value = fs::read_to_string(input)?.parse()?;
        execute(
            &config,
            program,
            &directory,
            &format!("{step}-baseline"),
            &baseline,
            None,
        )?;
        for (field, rejection) in cases {
            let mut changed = baseline.clone();
            let value = changed.get_mut(field).context("witness field")?;
            match value {
                toml::Value::Array(bytes) => {
                    let index = 0;
                    bytes[index] =
                        toml::Value::Integer(bytes[index].as_integer().context("byte")? ^ 1);
                }
                toml::Value::Integer(n) => *n += 1,
                _ => anyhow::bail!("unexpected witness type"),
            }
            execute(
                &config,
                program,
                &directory,
                &format!("wrong-{field}"),
                &changed,
                Some(rejection),
            )?;
        }
    }
    eprintln!(
        "Direct-exit constraint rejection logs: {}",
        directory.display()
    );
    Ok(())
}
