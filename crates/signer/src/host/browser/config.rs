//! Exact browser origin and HTTP authority policy; never a source of coin authority.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub allowed_origins: Vec<String>,
    /// HTTP Host authorities, including the port when it is not 443.
    pub allowed_hosts: Vec<String>,
}
fn authority(value: &str) -> bool {
    let (host, port) = value
        .split_once(':')
        .map_or((value, None), |(h, p)| (h, Some(p)));
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && port.is_none_or(|p| p.parse::<u16>().is_ok_and(|n| n != 0 && n.to_string() == p))
}
fn origin(value: &str) -> bool {
    if let Some(host) = value.strip_prefix("https://") {
        return authority(host) && !host.ends_with(":443");
    }
    // Explicit development entries only. No general plaintext web origins.
    if let Some(host) = value.strip_prefix("http://") {
        return authority(host)
            && !host.ends_with(":80")
            && matches!(host.split(':').next(), Some("localhost" | "127.0.0.1"));
    }
    false
}
impl Config {
    pub(in crate::host) fn validate(&self) -> Result<()> {
        ensure!(
            !self.allowed_origins.is_empty()
                && self.allowed_origins.len() <= 32
                && self.allowed_origins.iter().all(|v| origin(v))
                && self.allowed_origins.iter().collect::<BTreeSet<_>>().len()
                    == self.allowed_origins.len(),
            "invalid browser origins"
        );
        ensure!(
            !self.allowed_hosts.is_empty()
                && self.allowed_hosts.len() <= 16
                && self.allowed_hosts.iter().all(|v| authority(v))
                && self.allowed_hosts.iter().collect::<BTreeSet<_>>().len()
                    == self.allowed_hosts.len(),
            "invalid browser hosts"
        );
        Ok(())
    }
    pub(super) fn response_origin(
        &self,
        host: Option<&str>,
        origin: Option<&str>,
        same_origin_read: bool,
    ) -> Option<String> {
        let host = host.filter(|v| self.allowed_hosts.iter().any(|h| h == v))?;
        // Browsers omit Origin on same-origin GET. Only the read-only health
        // route may infer it, and it must still be explicitly configured.
        let origin = match origin {
            Some(origin) => origin.to_string(),
            None if same_origin_read => format!("https://{host}"),
            None => return None,
        };
        self.allowed_origins
            .iter()
            .any(|o| o == &origin)
            .then_some(origin)
    }
}
