//! One desktop-owned process, one immutable configuration, serial requests.
//! Journals are reopened for every command and their existing locks are held
//! only by that command. No private operation or current ownership is cached.
use super::{
    arguments::{Action, Cli},
    commands::execute_with_app,
    config::App,
};
use anyhow::{Result, ensure};
use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, Read, Write},
    path::Path,
};
mod assets;
use assets::{Assets, Stamp};

const MAX_REQUEST: usize = 128 * 1024;
const MAX_RESPONSE: usize = 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    id: u64,
    args: Vec<String>,
}

fn parse(bytes: &[u8], path: &Path, expected: u64) -> Result<Cli> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid worker request"))?;
    ensure!(
        request.version == 1
            && request.id == expected
            && !request.args.is_empty()
            && request.args.len() <= 128
            && request.args.iter().all(|s| s.len() <= 4096
                && !s.contains('\0')
                && s != "--config"
                && !s.starts_with("--config=")),
        "invalid worker request"
    );
    let mut args = vec![
        std::ffi::OsString::from("zark-wallet"),
        "--config".into(),
        path.as_os_str().to_owned(),
    ];
    args.extend(request.args.into_iter().map(Into::into));
    let cli = Cli::try_parse_from(args).map_err(|_| anyhow::anyhow!("invalid worker command"))?;
    ensure!(
        !matches!(cli.command, Action::Worker),
        "nested wallet worker is not permitted"
    );
    Ok(cli)
}
fn line(input: &mut impl BufRead) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let count = input
        .take((MAX_REQUEST + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if count == 0 {
        return Ok(None);
    }
    ensure!(
        count <= MAX_REQUEST && bytes.last() == Some(&b'\n'),
        "invalid worker framing"
    );
    Ok(Some(bytes))
}
fn send(output: &mut impl Write, value: Value) -> Result<()> {
    let bytes = serde_json::to_vec(&value)?;
    ensure!(bytes.len() <= MAX_RESPONSE, "worker response too large");
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn failure() -> Value {
    json!({"api_version":1,"ok":false,"error":{"code":"operation_failed",
        "message":"Wallet worker unavailable; restart the wallet and resume the saved operation."}})
}
fn run(path: &Path, input: &mut impl BufRead, output: &mut impl Write) -> Result<()> {
    ensure!(path.is_absolute(), "worker config must be absolute");
    let config_before = Stamp::read(path)?;
    let app = App::load(path, false)?;
    let assets = Assets::capture(&app, path)?;
    // Re-read/authenticate the configuration and Bitcoin executable AFTER the
    // snapshot, as well as fully authenticating the proof assets below.
    let app = App::load(path, true)?;
    app.v()?;
    app.p()?;
    config_before.check(path)?;
    assets.check()?;
    send(output, json!({"worker_version":1,"ready":true}))?;
    // A short read-only RPC outside any operation; failures leave discovery
    // to the first observation, exactly as without this warm-up.
    let chain = app.config.chain.clone();
    std::thread::spawn(move || chain.discover_observation());
    let mut id = 1u64;
    while let Some(bytes) = line(input)? {
        // Fail closed for the lifetime of this worker. Never refresh stamps or
        // accept a different configuration/asset set in a warm process.
        let cli = match parse(&bytes, path, id).and_then(|cli| {
            assets.check()?;
            Ok(cli)
        }) {
            Ok(cli) => cli,
            Err(_) => {
                send(
                    output,
                    json!({"worker_version":1,"id":id,"fatal":true,"response":failure()}),
                )?;
                return Ok(());
            }
        };
        // This is the SAME command implementation as the one-shot CLI. A lost
        // response is uncertain, not permission to execute again automatically.
        let result = execute_with_app(&app, cli.command);
        if assets.check().is_err() {
            send(
                output,
                json!({"worker_version":1,"id":id,"fatal":true,"response":failure()}),
            )?;
            return Ok(());
        }
        let response = match result {
            Ok(value) => json!({"api_version":1,"ok":true,"result":value}),
            Err(error) => json!({"api_version":1,"ok":false,"error":{"code":"operation_failed",
                "message":error.to_string(),"next_action":"Fix the reported cause and resume the same operation; do not delete its journal."}}),
        };
        send(
            output,
            json!({"worker_version":1,"id":id,"response":response}),
        )?;
        id = id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("worker request limit"))?;
    }
    Ok(())
}
pub(super) fn main(path: &Path) -> i32 {
    match run(path, &mut io::stdin().lock(), &mut io::stdout().lock()) {
        Ok(()) => 0,
        Err(_) => {
            // Never expose configuration, parser input or asset paths through
            // worker startup errors. EOF/invalid framing cannot trigger work.
            eprintln!("Wallet worker stopped; preserve journals and restart the wallet.");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_has_bounded_frames_and_rejects_incomplete_input() -> Result<()> {
        assert!(line(&mut &b""[..])?.is_none());
        assert_eq!(line(&mut &b"{}\nnext\n"[..])?, Some(b"{}\n".to_vec()));
        assert!(line(&mut &b"{}"[..]).is_err());
        assert!(line(&mut vec![b'x'; MAX_REQUEST + 1].as_slice()).is_err());
        Ok(())
    }
    #[test]
    fn worker_binds_sequence_config_and_command_without_clap_exit() -> Result<()> {
        let path = Path::new("/synthetic/wallet.json");
        let request =
            |args: Value| serde_json::to_vec(&json!({"version":1,"id":1,"args":args})).unwrap();
        assert!(parse(&request(json!(["verify-assets"])), path, 1).is_ok());
        for args in [
            json!(["worker"]),
            json!(["--help"]),
            json!(["verify-assets", "--config=/other"]),
            json!(["unknown"]),
        ] {
            assert!(parse(&request(args), path, 1).is_err());
        }
        assert!(parse(&request(json!(["verify-assets"])), path, 2).is_err());
        Ok(())
    }
}
