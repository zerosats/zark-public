//! Hosted TLS configuration and trusted credential scope checks.
use super::{
    BTreeSet, Context, Deserialize, Path, PathBuf, Result, SocketAddr, SystemTime, UNIX_EPOCH,
    ensure, hex32, read_bounded,
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedConfig {
    pub version: u32,
    pub listen: SocketAddr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    #[serde(default)]
    pub credentials: Vec<Credential>,
    /// Opt-in self-service access. Session signatures and all Engine checks still apply.
    #[serde(default)]
    pub public_access: Option<PublicAccess>,
    /// Optional encrypted delivery and public offer board on the same TLS socket.
    #[serde(default)]
    pub messaging: Option<crate::mail::Config>,
    pub network_workers: usize,
    pub proof_workers: usize,
    pub queue_capacity: usize,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAccess {
    pub max_inflight: usize,
    pub requests_per_minute: usize,
    pub allocations_per_minute: usize,
    #[serde(default = "default_peer_inflight")]
    pub peer_max_inflight: usize,
    #[serde(default = "default_peer_rate")]
    pub peer_requests_per_minute: usize,
}
fn default_peer_inflight() -> usize {
    2
}
fn default_peer_rate() -> usize {
    60
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub sha256: String,
    pub coins: Vec<String>,
    pub expires_at: u64,
    pub max_inflight: usize,
    pub requests_per_minute: usize,
}
impl HostedConfig {
    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&read_bounded(path, 1_000_000)?)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 1_000_000,
            "private hosted configuration size"
        );
        let config: Self = serde_json::from_slice(bytes)?;
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.version == 10, "private hosted version");
        if let Some(mail) = &self.messaging {
            mail.validate()?;
        }
        ensure!(
            (1..=16).contains(&self.network_workers)
                && (1..=4).contains(&self.proof_workers)
                && (1..=64).contains(&self.queue_capacity),
            "private hosted capacity"
        );
        ensure!(self.credentials.len() <= 1024, "private credential count");
        if let Some(public) = &self.public_access {
            ensure!(
                (1..=8).contains(&public.max_inflight)
                    && (1..=600).contains(&public.requests_per_minute)
                    && (1..=60).contains(&public.allocations_per_minute)
                    && public.allocations_per_minute <= public.requests_per_minute
                    && (1..=8).contains(&public.peer_max_inflight)
                    && (1..=600).contains(&public.peer_requests_per_minute),
                "public admission capacity"
            );
        }
        let mut seen = BTreeSet::new();
        for c in &self.credentials {
            ensure!(
                hex::encode(hex32(&c.sha256)?) == c.sha256 && seen.insert(&c.sha256),
                "private credential identity"
            );
            ensure!(
                !c.coins.is_empty()
                    && c.coins.len() <= 1000
                    && (1..=8).contains(&c.max_inflight)
                    && (1..=600).contains(&c.requests_per_minute),
                "private credential scope or capacity"
            );
            let mut coins = BTreeSet::new();
            for coin in &c.coins {
                ensure!(
                    hex::encode(hex32(coin)?) == *coin && coins.insert(coin),
                    "private credential coin"
                );
            }
        }
        Ok(())
    }
    pub(super) fn credential(&self, digest: Option<&str>, coin: &str) -> Result<&Credential> {
        let digest = digest.context("private credential rejected")?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.credentials
            .iter()
            .find(|c| c.sha256 == digest && c.expires_at > now && c.coins.iter().any(|v| v == coin))
            .context("private credential rejected")
    }
    /// The Engine also checks deployment and the exact signed request. This is
    /// only the operator's hosting policy, not evidence of coin ownership.
    pub fn admits_coin(&self, coin: &str) -> Result<bool> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(self.public_access.is_some()
            || self
                .credentials
                .iter()
                .any(|c| c.expires_at > now && c.coins.iter().any(|v| v == coin)))
    }
    pub(super) fn authorize(&self, digest: Option<&str>, coin: &str) -> Result<()> {
        if self.public_access.is_none() {
            self.credential(digest, coin)?;
        }
        Ok(())
    }
}
