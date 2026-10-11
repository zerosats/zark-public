//! Bounded encrypted mail and public offer discovery. No coin authority lives here.
//! Independent storage: never import mailbox state into the signing database.
mod state;
use state::{
    Claim, Mailbox, Message, Offer, State, check_ciphertext, legacy_swap_version, validate_state,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    hash,
    local::ProcessLock,
    mail::{self, ITEM_TTL, MAILBOX_TTL, MAX_CIPHERTEXT, MAX_WIRE, Request},
    random32,
    storage::atomic_write,
};

const MAX_STATE: usize = 32 * 1024 * 1024;
const MAX_BOXES: usize = 1024;
const MAX_OFFERS: usize = 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub directory: PathBuf,
    pub requests_per_minute: usize,
    #[serde(default = "default_peer_inflight")]
    pub max_inflight: usize,
    #[serde(default = "default_peer_inflight")]
    pub peer_max_inflight: usize,
    #[serde(default = "default_peer_rate")]
    pub peer_requests_per_minute: usize,
}
fn default_peer_inflight() -> usize {
    2
}
fn default_peer_rate() -> usize {
    240
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.directory.is_absolute()
                && (1..=6000).contains(&self.requests_per_minute)
                && (1..=16).contains(&self.max_inflight)
                && (1..=16).contains(&self.peer_max_inflight)
                && (1..=6000).contains(&self.peer_requests_per_minute),
            "invalid mail configuration"
        );
        Ok(())
    }
}
struct Live {
    state: State,
    fault: bool,
}
pub struct Service {
    file: PathBuf,
    deployment: [u8; 32],
    live: Mutex<Live>,
    _lock: ProcessLock,
}

fn parse<T: DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| anyhow::anyhow!("invalid_request"))
}
fn ttl(value: Option<u64>, max: u64) -> Result<u64> {
    let v = value.unwrap_or(max);
    ensure!((1..=max).contains(&v), "invalid_request");
    Ok(v)
}
fn authorized(token: Option<&str>, expected: &str) -> bool {
    token.is_some_and(|t| mail::digest(t).is_ok() && hex::encode(hash(&[t.as_bytes()])) == expected)
}
fn require_auth(token: Option<&str>, expected: &str) -> Result<()> {
    ensure!(authorized(token, expected), "unauthorized");
    Ok(())
}
fn mailbox<'a>(s: &'a State, id: &str, now: u64) -> Result<&'a Mailbox> {
    mail::digest(id)?;
    let b = s.mailboxes.get(id).context("mailbox_not_found")?;
    ensure!(b.expires_at > now, "mailbox_expired");
    Ok(b)
}
fn private(path: &Path, directory: bool) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        (if directory {
            m.is_dir()
        } else {
            m.is_file() && m.nlink() == 1
        }) && m.permissions().mode() & 0o077 == 0
            && m.uid() == unsafe { libc::geteuid() },
        "unsafe mail storage"
    );
    Ok(())
}
impl Service {
    pub fn open(config: &Config, deployment: [u8; 32]) -> Result<Self> {
        config.validate()?;
        if !config.directory.try_exists()? {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&config.directory)?;
        }
        private(&config.directory, true)?;
        let lock_path = config.directory.join("mail.lock");
        if lock_path.exists() {
            private(&lock_path, false)?;
        }
        let lock = ProcessLock::acquire(&lock_path)?;
        let file = config.directory.join("mail-v1.json");
        let state = if file.try_exists()? {
            private(&file, false)?;
            let mut bytes = Vec::new();
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&file)?
                .take((MAX_STATE + 1) as u64)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= MAX_STATE, "mail storage quota");
            let s: State = serde_json::from_slice(&bytes)?;
            validate_state(&s, &deployment)?;
            s
        } else {
            let s = State {
                version: 1,
                deployment: hex::encode(deployment),
                mailboxes: BTreeMap::new(),
                offers: BTreeMap::new(),
            };
            atomic_write(&file, &serde_json::to_vec(&s)?)?;
            s
        };
        Ok(Self {
            file,
            deployment,
            live: Mutex::new(Live {
                state,
                fault: false,
            }),
            _lock: lock,
        })
    }
    pub fn handle(&self, request: Request, now: u64) -> Value {
        match self.execute(request, now) {
            Ok(result) => json!({"ok":true,"result":result}),
            Err(e) => {
                let code = match e.to_string().as_str() {
                    "unauthorized" => "unauthorized",
                    "mailbox_not_found" => "mailbox_not_found",
                    "mailbox_expired" => "mailbox_expired",
                    "mailbox_exists" => "mailbox_exists",
                    "message_replayed" => "message_replayed",
                    "message_conflict" => "message_conflict",
                    "offer_not_found" => "offer_not_found",
                    "offer_expired" => "offer_expired",
                    "offer_terms_conflict" => "offer_terms_conflict",
                    "offer_claimed" => "offer_claimed",
                    "offer_unavailable" => "offer_unavailable",
                    "unsupported_swap_version" => "unsupported_swap_version",
                    "address_in_use" => "address_in_use",
                    "quota" => "storage_quota",
                    "storage_fault" => "storage_fault",
                    _ => "invalid_request",
                };
                json!({"ok":false,"error":{"code":code,"message":"Messaging request was not completed."}})
            }
        }
    }
    fn address(&self, a: &str) -> Result<ReceivingAddress> {
        ReceivingAddress::decode(a, AddressNetwork::Test, &self.deployment)
    }
    fn execute(&self, r: Request, now: u64) -> Result<Value> {
        ensure!(
            r.version == 1 && r.path.len() <= 512 && now < u64::MAX - MAILBOX_TTL,
            "invalid_request"
        );
        if let Some(t) = &r.bearer {
            mail::digest(t)?;
        }
        let mut live = self
            .live
            .lock()
            .map_err(|_| anyhow::anyhow!("storage_fault"))?;
        ensure!(!live.fault, "storage_fault");
        let mut next = live.state.clone();
        let mut changed = false;
        for b in next.mailboxes.values_mut() {
            let before = b.messages.len();
            b.messages.retain(|_, m| m.expires_at > now);
            changed |= before != b.messages.len();
        }
        let result = self.apply(&mut next, r, now, &mut changed)?;
        ensure!(serde_json::to_vec(&result)?.len() + 128 < MAX_WIRE, "quota");
        if changed {
            let bytes = serde_json::to_vec(&next)?;
            ensure!(bytes.len() <= MAX_STATE, "quota");
            if atomic_write(&self.file, &bytes).is_err() {
                live.fault = true;
                anyhow::bail!("storage_fault");
            }
            live.state = next;
        }
        Ok(result)
    }
    fn apply(&self, s: &mut State, r: Request, now: u64, changed: &mut bool) -> Result<Value> {
        let parts: Vec<_> = r.path.split('/').collect();
        let token = r.bearer.as_deref();
        if r.method == "GET" && r.path == "/health" {
            return Ok(json!({"service":"zark-mail","version":1}));
        }
        if r.method == "POST" && r.path == "/v1/mailboxes" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields, rename_all = "camelCase")]
            struct Body {
                receive_address: String,
                read_token_hash: String,
                signature: String,
                ttl_ms: u64,
            }
            let b: Body = parse(r.body)?;
            let address = self.address(&b.receive_address)?;
            mail::verify_registration(&address, &b.read_token_hash, b.ttl_ms, &b.signature)?;
            let id = hex::encode(hash(&[b.receive_address.as_bytes()]));
            if let Some(old) = s.mailboxes.get(&id) {
                ensure!(
                    old.read_token_hash == b.read_token_hash && old.ttl == b.ttl_ms,
                    "mailbox_exists"
                );
                ensure!(old.expires_at > now, "mailbox_expired");
            } else {
                ensure!(s.mailboxes.len() < MAX_BOXES, "quota");
                s.mailboxes.insert(
                    id.clone(),
                    Mailbox {
                        read_token_hash: b.read_token_hash,
                        ttl: b.ttl_ms,
                        created_at: now,
                        expires_at: now + b.ttl_ms,
                        messages: BTreeMap::new(),
                        seen: BTreeMap::new(),
                    },
                );
                *changed = true;
            }
            let saved = &s.mailboxes[&id];
            return Ok(
                json!({"addressHash":id,"createdAt":saved.created_at,"expiresAt":saved.expires_at}),
            );
        }
        if parts.len() >= 5 && parts[..3] == ["", "v1", "mailboxes"] && parts[4] == "messages" {
            let id = parts[3];
            mailbox(s, id, now)?;
            let b = s.mailboxes.get_mut(id).expect("checked mailbox");
            if parts.len() == 5 && r.method == "POST" {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields, rename_all = "camelCase")]
                struct Body {
                    id: String,
                    ciphertext: String,
                    ttl_ms: Option<u64>,
                }
                let v: Body = parse(r.body)?;
                mail::digest(&v.id)?;
                check_ciphertext(&v.ciphertext)?;
                let ttl = ttl(v.ttl_ms, ITEM_TTL)?;
                let digest = hex::encode(hash(&[v.ciphertext.as_bytes(), &ttl.to_le_bytes()]));
                if let Some(old) = b.seen.get(&v.id) {
                    ensure!(*old == digest, "message_conflict");
                    anyhow::bail!("message_replayed");
                }
                ensure!(b.messages.len() < 32 && b.seen.len() < 256, "quota");
                let expires = b.expires_at.min(now + ttl);
                b.seen.insert(v.id.clone(), digest);
                b.messages.insert(
                    v.id.clone(),
                    Message {
                        id: v.id.clone(),
                        ciphertext: v.ciphertext,
                        created_at: now,
                        expires_at: expires,
                    },
                );
                *changed = true;
                return Ok(json!({"id":v.id,"createdAt":now,"expiresAt":expires}));
            }
            require_auth(token, &b.read_token_hash)?;
            if parts.len() == 5 && r.method == "GET" {
                let mut messages: Vec<_> = b.messages.values().collect();
                messages.sort_by_key(|m| (m.created_at, &m.id));
                let mut output = Vec::new();
                let mut size = 128;
                for m in messages {
                    let v = serde_json::to_value(m)?;
                    size += serde_json::to_vec(&v)?.len() + 1;
                    if size >= MAX_WIRE - 256 {
                        break;
                    }
                    output.push(v);
                }
                return Ok(json!({"messages":output}));
            }
            if parts.len() == 6 && r.method == "DELETE" {
                mail::digest(parts[5])?;
                *changed |= b.messages.remove(parts[5]).is_some();
                return Ok(json!({"acknowledged":true}));
            }
        }
        if r.path == "/v1/offers" && r.method == "GET" {
            return Ok(
                json!({"offers":s.offers.values().filter(|o| o.status == "open" && o.expires_at > now).map(|o|o.public(false)).collect::<Vec<_>>()}),
            );
        }
        if r.path == "/v1/offers" && r.method == "POST" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields, rename_all = "camelCase")]
            struct Body {
                amount_sat: u64,
                #[serde(default = "legacy_swap_version")]
                swap_version: u32,
                receive_address: String,
                address_hash: String,
                owner_token_hash: String,
                ttl_ms: Option<u64>,
            }
            let b: Body = parse(r.body)?;
            self.address(&b.receive_address)?;
            mail::digest(&b.owner_token_hash)?;
            ensure!(
                b.address_hash == hex::encode(hash(&[b.receive_address.as_bytes()]))
                    && (1..=2_100_000_000_000_000).contains(&b.amount_sat)
                    && (1..=2).contains(&b.swap_version),
                "invalid_request"
            );
            let box_ = mailbox(s, &b.address_hash, now)?;
            require_auth(token, &box_.read_token_hash)?;
            let duration = ttl(b.ttl_ms, ITEM_TTL)?;
            if let Some(old) = s
                .offers
                .values()
                .find(|o| o.owner_token_hash == b.owner_token_hash)
            {
                ensure!(
                    old.address_hash == b.address_hash
                        && old.amount_sat == b.amount_sat
                        && old.swap_version == b.swap_version
                        && old.ttl == duration,
                    "offer_terms_conflict"
                );
                ensure!(old.expires_at > now, "offer_expired");
                return Ok(old.public(false));
            }
            ensure!(s.offers.len() < MAX_OFFERS, "quota");
            ensure!(!address_in_use(s, &b.address_hash, now), "address_in_use");
            let id = hex::encode(random32());
            let offer = Offer {
                id: id.clone(),
                amount_sat: b.amount_sat,
                swap_version: b.swap_version,
                receive_address: b.receive_address,
                address_hash: b.address_hash,
                owner_token_hash: b.owner_token_hash,
                ttl: duration,
                created_at: now,
                expires_at: box_.expires_at.min(now + duration),
                status: "open".into(),
                claim: None,
            };
            let result = offer.public(false);
            s.offers.insert(id, offer);
            *changed = true;
            return Ok(result);
        }
        if parts.len() >= 4 && parts[..3] == ["", "v1", "offers"] {
            mail::identifier(parts[3])?;
            let offer = s.offers.get(parts[3]).context("offer_not_found")?;
            ensure!(offer.expires_at > now, "offer_expired");
            if parts.len() == 4 && r.method == "GET" {
                ensure!(
                    authorized(token, &offer.owner_token_hash)
                        || offer
                            .claim
                            .as_ref()
                            .is_some_and(|c| authorized(token, &c.claim_token_hash)),
                    "unauthorized"
                );
                return Ok(offer.public(true));
            }
            if parts.len() == 4 && r.method == "DELETE" {
                require_auth(token, &offer.owner_token_hash)?;
                ensure!(offer.status != "claimed", "offer_claimed");
                let offer = s.offers.get_mut(parts[3]).expect("checked offer");
                *changed |= offer.status != "cancelled";
                offer.status = "cancelled".into();
                return Ok(offer.public(false));
            }
            if parts.len() == 5 && parts[4] == "claim" && r.method == "POST" {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields, rename_all = "camelCase")]
                struct Body {
                    receive_address: String,
                    address_hash: String,
                    claim_token_hash: String,
                    #[serde(default = "legacy_swap_version")]
                    swap_version: u32,
                }
                let b: Body = parse(r.body)?;
                self.address(&b.receive_address)?;
                mail::digest(&b.claim_token_hash)?;
                ensure!(
                    b.address_hash == hex::encode(hash(&[b.receive_address.as_bytes()]))
                        && b.address_hash != offer.address_hash,
                    "invalid_request"
                );
                ensure!(
                    b.swap_version == offer.swap_version,
                    "unsupported_swap_version"
                );
                require_auth(token, &mailbox(s, &b.address_hash, now)?.read_token_hash)?;
                if offer.claim.as_ref().is_some_and(|c| {
                    c.address_hash == b.address_hash && c.claim_token_hash == b.claim_token_hash
                }) {
                    return Ok(offer.public(true));
                }
                ensure!(offer.status == "open", "offer_unavailable");
                ensure!(!address_in_use(s, &b.address_hash, now), "address_in_use");
                let offer = s.offers.get_mut(parts[3]).expect("checked offer");
                offer.status = "claimed".into();
                offer.claim = Some(Claim {
                    receive_address: b.receive_address,
                    address_hash: b.address_hash,
                    claim_token_hash: b.claim_token_hash,
                    claimed_at: now,
                });
                *changed = true;
                return Ok(offer.public(true));
            }
        }
        anyhow::bail!("invalid_request")
    }
}
fn address_in_use(s: &State, address: &str, now: u64) -> bool {
    s.offers.values().any(|o| {
        o.expires_at > now
            && o.status != "cancelled"
            && (o.address_hash == address
                || o.claim.as_ref().is_some_and(|c| c.address_hash == address))
    })
}
