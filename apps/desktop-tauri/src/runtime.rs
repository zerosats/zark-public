//! Locates the Node runtime that coordinates the wallet.
//!
//! From a checkout, run-wallet.sh builds the wallet and passes the runtime
//! through the environment. A packaged app carries the runtime, the wallet CLI
//! and usually Node under its resources, and its entry point runs setup itself.

use std::path::{Path, PathBuf};

pub const NODE_MISSING: &str =
    "Zark needs Node.js 20 or newer. Install it from nodejs.org and reopen Zark.";

pub struct Runtime {
    pub node: PathBuf,
    pub entry: PathBuf,
    /// Extra environment for the runtime process.
    pub env: Vec<(String, String)>,
}

/// The runtime for this launch, or a message explaining why none was found.
pub fn locate(resources: Option<PathBuf>) -> Result<Runtime, &'static str> {
    if let (Some(node), Some(entry)) = (
        std::env::var_os("ZARK_NODE"),
        std::env::var_os("ZARK_DESKTOP_RUNTIME"),
    ) {
        return Ok(Runtime {
            node: node.into(),
            entry: entry.into(),
            env: Vec::new(),
        });
    }
    let bundle = resources
        .map(|dir| dir.join("app"))
        .ok_or("Launch with run-wallet.sh")?;
    let entry = bundle.join("apps/desktop/runtime/app.mjs");
    let wallet = bundle.join("bin/zark-wallet");
    if !entry.is_file() || !wallet.is_file() {
        return Err("Launch with run-wallet.sh");
    }
    let bundled = bundle.join("node/bin/node");
    let node = if bundled.is_file() {
        bundled
    } else {
        system_node().ok_or(NODE_MISSING)?
    };
    let mut env = vec![(
        "ZARK_WALLET_BINARY".to_owned(),
        wallet.to_string_lossy().into_owned(),
    )];
    env.push(("ZARK_NODE".to_owned(), node.to_string_lossy().into_owned()));
    Ok(Runtime { node, entry, env })
}

/// A `node` on PATH, or in the usual install locations: apps started from
/// Finder or a desktop launcher do not inherit a login shell's PATH. The
/// runtime itself rejects versions older than 20 with a clear message.
fn system_node() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut candidates: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    candidates.extend(["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"].map(PathBuf::from));
    if let Some(home) = &home {
        candidates.extend(nvm_versions(home));
        candidates.push(home.join(".local/bin"));
    }
    candidates
        .into_iter()
        .map(|dir| dir.join("node"))
        .find(|node| is_executable(node))
}

/// nvm installs, newest version first.
fn nvm_versions(home: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(home.join(".nvm/versions/node")) else {
        return Vec::new();
    };
    let mut versions: Vec<(Vec<u32>, PathBuf)> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let parts = name
                .strip_prefix('v')?
                .split('.')
                .map(|part| part.parse().ok())
                .collect::<Option<Vec<u32>>>()?;
            Some((parts, entry.path().join("bin")))
        })
        .collect();
    versions.sort_by(|a, b| b.0.cmp(&a.0));
    versions.into_iter().map(|(_, bin)| bin).collect()
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvm_versions_are_newest_first_and_ignore_other_entries() {
        let home = std::env::temp_dir().join(format!("zark-nvm-{}", std::process::id()));
        for name in ["v18.20.0", "v22.1.0", "v20.19.5", "system"] {
            std::fs::create_dir_all(home.join(".nvm/versions/node").join(name).join("bin"))
                .unwrap();
        }
        let found: Vec<String> = nvm_versions(&home)
            .iter()
            .map(|bin| {
                bin.parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(found, ["v22.1.0", "v20.19.5", "v18.20.0"]);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_packaged_app_needs_its_runtime_and_wallet() {
        let missing = std::env::temp_dir().join(format!("zark-empty-{}", std::process::id()));
        if std::env::var_os("ZARK_NODE").is_none() {
            assert_eq!(
                locate(Some(missing)).err(),
                Some("Launch with run-wallet.sh")
            );
            assert_eq!(locate(None).err(), Some("Launch with run-wallet.sh"));
        }
    }
}
