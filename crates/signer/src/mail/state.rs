//! Persisted encrypted-mail records and bounded state validation. No signing authority is stored here.
use super::{
    AddressNetwork, BTreeMap, Deserialize, ITEM_TTL, MAILBOX_TTL, MAX_BOXES, MAX_CIPHERTEXT,
    MAX_OFFERS, ReceivingAddress, Result, Serialize, Value, ensure, hash, json, mail, ttl,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Message {
    pub(super) id: String,
    pub(super) ciphertext: String,
    pub(super) created_at: u64,
    pub(super) expires_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Mailbox {
    pub(super) read_token_hash: String,
    pub(super) ttl: u64,
    pub(super) created_at: u64,
    pub(super) expires_at: u64,
    pub(super) messages: BTreeMap<String, Message>,
    pub(super) seen: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Claim {
    pub(super) receive_address: String,
    pub(super) address_hash: String,
    pub(super) claim_token_hash: String,
    pub(super) claimed_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Offer {
    pub(super) id: String,
    pub(super) amount_sat: u64,
    #[serde(default = "legacy_swap_version")]
    pub(super) swap_version: u32,
    pub(super) receive_address: String,
    pub(super) address_hash: String,
    pub(super) owner_token_hash: String,
    pub(super) ttl: u64,
    pub(super) created_at: u64,
    pub(super) expires_at: u64,
    pub(super) status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) claim: Option<Claim>,
}
impl Offer {
    pub(super) fn public(&self, details: bool) -> Value {
        let mut v = json!({"id":self.id,"amountSat":self.amount_sat,"swapVersion":self.swap_version,"receiveAddress":self.receive_address,
            "addressHash":self.address_hash,"createdAt":self.created_at,"expiresAt":self.expires_at,"status":self.status});
        if details && let Some(c) = &self.claim {
            v["claim"] = json!({"receiveAddress":c.receive_address,"addressHash":c.address_hash,"claimedAt":c.claimed_at});
        }
        v
    }
}
pub(super) fn legacy_swap_version() -> u32 {
    1
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub(super) version: u32,
    pub(super) deployment: String,
    pub(super) mailboxes: BTreeMap<String, Mailbox>,
    pub(super) offers: BTreeMap<String, Offer>,
}
pub(super) fn check_ciphertext(c: &str) -> Result<()> {
    ensure!(
        (64..=MAX_CIPHERTEXT).contains(&c.len())
            && c.len().is_multiple_of(2)
            && c.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_request"
    );
    Ok(())
}
pub(super) fn validate_state(s: &State, deployment: &[u8; 32]) -> Result<()> {
    ensure!(
        s.version == 1
            && s.deployment == hex::encode(deployment)
            && s.mailboxes.len() <= MAX_BOXES
            && s.offers.len() <= MAX_OFFERS,
        "invalid mail storage"
    );
    for (id, b) in &s.mailboxes {
        mail::digest(id)?;
        mail::digest(&b.read_token_hash)?;
        ttl(Some(b.ttl), MAILBOX_TTL)?;
        ensure!(
            b.created_at.checked_add(b.ttl) == Some(b.expires_at)
                && b.messages.len() <= 32
                && b.seen.len() <= 256,
            "invalid mail storage"
        );
        for (id, digest) in &b.seen {
            mail::digest(id)?;
            mail::digest(digest)?;
        }
        for (id, m) in &b.messages {
            mail::digest(id)?;
            check_ciphertext(&m.ciphertext)?;
            ensure!(
                m.id == *id
                    && b.seen.contains_key(id)
                    && m.expires_at > m.created_at
                    && m.expires_at <= b.expires_at,
                "invalid mail storage"
            );
        }
    }
    for (id, o) in &s.offers {
        mail::identifier(id)?;
        mail::digest(&o.owner_token_hash)?;
        ttl(Some(o.ttl), ITEM_TTL)?;
        ReceivingAddress::decode(&o.receive_address, AddressNetwork::Test, deployment)?;
        ensure!(
            o.id == *id
                && o.address_hash == hex::encode(hash(&[o.receive_address.as_bytes()]))
                && s.mailboxes.contains_key(&o.address_hash)
                && (1..=2_100_000_000_000_000).contains(&o.amount_sat)
                && (1..=2).contains(&o.swap_version)
                && o.expires_at > o.created_at
                && matches!(o.status.as_str(), "open" | "claimed" | "cancelled")
                && (o.status == "claimed") == o.claim.is_some(),
            "invalid mail storage"
        );
        if let Some(c) = &o.claim {
            ReceivingAddress::decode(&c.receive_address, AddressNetwork::Test, deployment)?;
            mail::digest(&c.claim_token_hash)?;
            ensure!(
                c.address_hash == hex::encode(hash(&[c.receive_address.as_bytes()]))
                    && s.mailboxes.contains_key(&c.address_hash)
                    && c.address_hash != o.address_hash
                    && c.claimed_at >= o.created_at
                    && c.claimed_at < o.expires_at,
                "invalid mail storage"
            );
        }
    }
    Ok(())
}
