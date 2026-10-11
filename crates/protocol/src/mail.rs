//! Versioned mailbox transport, separate from coin authority and proof statements.
use crate::{address::ReceivingAddress, hash, hex32};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ALPN: &[u8] = b"zark-mail/1";
/// Identical bounded frames, sequentially reused on authenticated TLS.
pub const SESSION_ALPN: &[u8] = b"zark-mail/1-session";
pub fn is_alpn(protocol: Option<&[u8]>) -> bool {
    protocol == Some(ALPN) || protocol == Some(SESSION_ALPN)
}
pub const MAX_WIRE: usize = 3_000_000;
pub const MAX_CIPHERTEXT: usize = 2_800_000;
pub const MAILBOX_TTL: u64 = 7 * 24 * 60 * 60 * 1000;
pub const ITEM_TTL: u64 = 24 * 60 * 60 * 1000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<String>,
    #[serde(default)]
    pub body: Value,
}
pub fn identifier(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid_request"
    );
    Ok(())
}
pub fn digest(value: &str) -> Result<[u8; 32]> {
    let bytes = hex32(value).map_err(|_| anyhow::anyhow!("invalid_request"))?;
    ensure!(hex::encode(bytes) == value, "invalid_request");
    Ok(bytes)
}
pub fn registration_digest(
    address: &ReceivingAddress,
    token_hash: &str,
    ttl: u64,
) -> Result<[u8; 32]> {
    ensure!((1..=MAILBOX_TTL).contains(&ttl), "invalid_request");
    Ok(hash(&[
        b"ZARK/mailbox-registration/v1",
        address.encode().as_bytes(),
        &digest(token_hash)?,
        &ttl.to_le_bytes(),
    ]))
}
pub fn verify_registration(
    address: &ReceivingAddress,
    token_hash: &str,
    ttl: u64,
    signature: &str,
) -> Result<()> {
    let raw = hex::decode(signature).map_err(|_| anyhow::anyhow!("invalid_request"))?;
    ensure!(hex::encode(&raw) == signature, "invalid_request");
    let key = VerifyingKey::from_bytes(&address.claim_key()[1..])?;
    key.verify_raw(
        &registration_digest(address, token_hash, ttl)?,
        &Signature::try_from(raw.as_slice())?,
    )?;
    Ok(())
}

/// Authenticate private swap coordination, separately from registration and
/// ownership authorization. Encryption alone does not identify a sender.
pub fn peer_message_digest(
    address: &ReceivingAddress,
    recipient: &str,
    message: &Value,
) -> Result<[u8; 32]> {
    let recipient = ReceivingAddress::decode(recipient, address.network(), address.deployment())?;
    ensure!(message.is_object(), "invalid peer message");
    let bytes = serde_json::to_vec(&(address.encode(), recipient.encode(), message))?;
    ensure!(bytes.len() <= MAX_CIPHERTEXT, "peer message too large");
    Ok(hash(&[b"ZARK/swap-peer-message/v2", &bytes]))
}

pub fn verify_peer_message(
    address: &ReceivingAddress,
    recipient: &str,
    message: &Value,
    signature: &str,
) -> Result<()> {
    let raw = hex::decode(signature)?;
    ensure!(
        hex::encode(&raw) == signature,
        "noncanonical peer signature"
    );
    VerifyingKey::from_bytes(&address.claim_key()[1..])?.verify_raw(
        &peer_message_digest(address, recipient, message)?,
        &Signature::try_from(raw.as_slice())?,
    )?;
    Ok(())
}
