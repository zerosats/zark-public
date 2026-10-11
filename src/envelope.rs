//! Isolated confidential transfer-offer envelopes, never signer messages.
//!
//! Anonymous ephemeral ECDH plus AEAD authenticates ciphertext integrity, NOT
//! sender identity or ownership. Anyone knowing a receiving address can encrypt
//! an offer. A verified handover authorization is still required by the protocol.
use anyhow::{Result, ensure};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, ecdh::SharedSecret};
use ring::{aead, hkdf};
use serde::{Deserialize, Serialize};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    handoff::PROTOCOL_VERSION,
    random32,
};
use zeroize::Zeroizing;

pub const ENVELOPE_VERSION: u8 = 1;
pub const MAX_ENVELOPE_BYTES: usize = crate::invitation::MAX_OFFER_BYTES;
// Reserve fixed JSON/header overhead and the 16-byte Poly1305 tag. Hex doubles
// ciphertext size; successful encryption must fit the invitation reservation cap.
pub const MAX_PLAINTEXT_BYTES: usize = (MAX_ENVELOPE_BYTES - 256) / 2 - 16;

/// Expected peer context, obtained independently of the untrusted envelope.
/// The associated-data role is fixed to transfer_offer in this prototype.
#[derive(Clone, PartialEq, Eq)]
pub struct OfferContext {
    pub deployment: [u8; 32],
    pub coin: [u8; 32],
    pub operation: [u8; 32],
}

impl OfferContext {
    fn validate(&self, address: &ReceivingAddress) -> Result<()> {
        ensure!(
            address.network() == AddressNetwork::Test,
            "mainnet envelopes are not enabled"
        );
        ensure!(
            self.deployment != [0; 32] && self.coin != [0; 32] && self.operation != [0; 32],
            "zero offer context"
        );
        ensure!(
            *address.deployment() == self.deployment,
            "offer deployment mismatch"
        );
        Ok(())
    }

    fn associated_data(
        &self,
        address: &ReceivingAddress,
        ephemeral: &[u8; 33],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>> {
        self.validate(address)?;
        let address = address.encode();
        let mut aad = Vec::with_capacity(384);
        aad.extend_from_slice(b"ZARK/address-envelope/aad/v1");
        aad.push(ENVELOPE_VERSION);
        aad.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        aad.extend_from_slice(&self.deployment);
        aad.extend_from_slice(&self.coin);
        aad.extend_from_slice(&self.operation);
        aad.push(1); // Exactly one allowed role: transfer_offer.
        aad.extend_from_slice(&(address.len() as u16).to_le_bytes());
        aad.extend_from_slice(address.as_bytes());
        aad.extend_from_slice(ephemeral);
        aad.extend_from_slice(nonce);
        Ok(aad)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOffer {
    version: u8,
    ephemeral_key: String,
    nonce: String,
    ciphertext: String,
}

/// Ciphertext transport only. Explicit access avoids automatic log rendering.
pub struct SealedOffer {
    bytes: Vec<u8>,
}
impl SealedOffer {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// An ephemeral library key with explicit best-effort erasure on drop.
struct EphemeralKey(SecretKey);
impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

fn ephemeral_key() -> EphemeralKey {
    loop {
        let bytes = Zeroizing::new(random32());
        if let Ok(key) = SecretKey::from_slice(bytes.as_ref()) {
            return EphemeralKey(key);
        }
    }
}

struct KeyLength;
impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}

fn encryption_key(shared: &SharedSecret, aad: &[u8]) -> Result<aead::LessSafeKey> {
    let shared_bytes = Zeroizing::new(shared.secret_bytes());
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"ZARK/address-envelope/extract/v1");
    let prk = salt.extract(shared_bytes.as_ref());
    let info = [b"ZARK/address-envelope/key/v1".as_slice(), aad];
    let okm = prk
        .expand(&info, KeyLength)
        .map_err(|_| anyhow::anyhow!("envelope key derivation failed"))?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    okm.fill(bytes.as_mut())
        .map_err(|_| anyhow::anyhow!("envelope key derivation failed"))?;
    let key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, bytes.as_ref())
        .map_err(|_| anyhow::anyhow!("envelope key initialization failed"))?;
    Ok(aead::LessSafeKey::new(key))
}

/// Fresh ephemeral key and nonce for every encryption. This does not identify
/// the sender, validate ownership, or reserve the recipient's invitation.
pub fn encrypt_offer(
    address: &ReceivingAddress,
    context: &OfferContext,
    plaintext: &[u8],
) -> Result<SealedOffer> {
    encrypt_with_role(address, context, plaintext, b"")
}

fn encrypt_with_role(
    address: &ReceivingAddress,
    context: &OfferContext,
    plaintext: &[u8],
    role: &[u8],
) -> Result<SealedOffer> {
    context.validate(address)?;
    ensure!(
        !plaintext.is_empty() && plaintext.len() <= MAX_PLAINTEXT_BYTES,
        "invalid offer plaintext size"
    );
    let ephemeral = ephemeral_key();
    let public = PublicKey::from_secret_key(&Secp256k1::new(), &ephemeral.0).serialize();
    let recipient = PublicKey::from_slice(address.envelope_key())
        .map_err(|_| anyhow::anyhow!("invalid envelope recipient key"))?;
    let mut shared = SharedSecret::new(&recipient, &ephemeral.0);
    let nonce: [u8; 12] = random32()[..12].try_into()?;
    let mut aad = context.associated_data(address, &public, &nonce)?;
    aad.extend_from_slice(role);
    let result = encryption_key(&shared, &aad);
    shared.non_secure_erase();
    let key = result?;
    let mut ciphertext = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(&aad),
        &mut *ciphertext,
    )
    .map_err(|_| anyhow::anyhow!("offer encryption failed"))?;
    let wire = WireOffer {
        version: ENVELOPE_VERSION,
        ephemeral_key: hex::encode(public),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(&*ciphertext),
    };
    let bytes = serde_json::to_vec(&wire)?;
    ensure!(
        bytes.len() <= MAX_ENVELOPE_BYTES,
        "offer envelope too large"
    );
    Ok(SealedOffer { bytes })
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Called only by the private invitation adapter; the long-lived key is never
/// returned. Successful decryption itself still does not reserve or accept a coin.
pub(crate) fn decrypt_offer(
    address: &ReceivingAddress,
    context: &OfferContext,
    envelope_secret: &[u8; 32],
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_with_role(address, context, envelope_secret, bytes, b"")
}

fn decrypt_with_role(
    address: &ReceivingAddress,
    context: &OfferContext,
    envelope_secret: &[u8; 32],
    bytes: &[u8],
    role: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    context.validate(address)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_ENVELOPE_BYTES,
        "invalid offer envelope size"
    );
    let wire: WireOffer =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid offer envelope"))?;
    ensure!(
        wire.version == ENVELOPE_VERSION,
        "unsupported envelope version"
    );
    ensure!(
        wire.ephemeral_key.len() == 66
            && wire.nonce.len() == 24
            && (34..=(MAX_PLAINTEXT_BYTES + 16) * 2).contains(&wire.ciphertext.len())
            && wire.ciphertext.len().is_multiple_of(2)
            && lower_hex(&wire.ephemeral_key)
            && lower_hex(&wire.nonce)
            && lower_hex(&wire.ciphertext),
        "invalid envelope field encoding or length"
    );
    ensure!(
        serde_json::to_vec(&wire)? == bytes,
        "noncanonical offer envelope"
    );
    let public: [u8; 33] = hex::decode(&wire.ephemeral_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ephemeral key length"))?;
    ensure!(matches!(public[0], 2 | 3), "invalid ephemeral key encoding");
    let sender =
        PublicKey::from_slice(&public).map_err(|_| anyhow::anyhow!("invalid ephemeral key"))?;
    let recipient = EphemeralKey(
        SecretKey::from_slice(envelope_secret)
            .map_err(|_| anyhow::anyhow!("invalid private envelope key"))?,
    );
    ensure!(
        PublicKey::from_secret_key(&Secp256k1::new(), &recipient.0).serialize()
            == *address.envelope_key(),
        "private envelope key does not match address"
    );
    let nonce: [u8; 12] = hex::decode(&wire.nonce)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid nonce length"))?;
    let mut aad = context.associated_data(address, &public, &nonce)?;
    aad.extend_from_slice(role);
    let mut shared = SharedSecret::new(&sender, &recipient.0);
    let result = encryption_key(&shared, &aad);
    shared.non_secure_erase();
    let key = result?;
    let mut plaintext = Zeroizing::new(hex::decode(&wire.ciphertext)?);
    let length = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad),
            &mut plaintext,
        )
        .map_err(|_| anyhow::anyhow!("offer authentication failed"))?
        .len();
    plaintext.truncate(length);
    Ok(plaintext)
}

// The outer delivery envelope needs only an address and opaque message ID.
// A separate AEAD domain prevents cross-use with legacy coin-offer envelopes.
fn message_context(address: &ReceivingAddress, id: &str) -> Result<OfferContext> {
    zark_protocol::mail::identifier(id)?;
    Ok(OfferContext {
        deployment: *address.deployment(),
        coin: zark_protocol::hash(&[b"ZARK/mail/no-coin/v1"]),
        operation: zark_protocol::hash(&[b"ZARK/mail/id/v1", id.as_bytes()]),
    })
}
pub fn encrypt_message(address: &ReceivingAddress, id: &str, plaintext: &[u8]) -> Result<String> {
    ensure!(plaintext.len() <= 600_000, "private message size");
    let sealed = encrypt_with_role(
        address,
        &message_context(address, id)?,
        plaintext,
        b"ZARK/mail-envelope/v1",
    )?;
    let encoded = hex::encode(sealed.as_bytes());
    ensure!(
        encoded.len() <= zark_protocol::mail::MAX_CIPHERTEXT,
        "private message size"
    );
    Ok(encoded)
}
pub(crate) fn decrypt_message(
    address: &ReceivingAddress,
    id: &str,
    secret: &[u8; 32],
    ciphertext: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        ciphertext.len() <= zark_protocol::mail::MAX_CIPHERTEXT,
        "private message size"
    );
    let bytes = hex::decode(ciphertext)?;
    ensure!(hex::encode(&bytes) == ciphertext, "noncanonical message");
    let plaintext = decrypt_with_role(
        address,
        &message_context(address, id)?,
        secret,
        &bytes,
        b"ZARK/mail-envelope/v1",
    )?;
    ensure!(plaintext.len() <= 600_000, "private message size");
    Ok(plaintext)
}
