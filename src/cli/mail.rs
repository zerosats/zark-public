//! Local delivery encryption and authenticated peer messages.
use super::config::App;
use super::storage::{absolute, read_private, write_new};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use zark_protocol::address::{AddressNetwork, ReceivingAddress};
use zeroize::Zeroizing;

pub(super) fn execute(app: &App, input: PathBuf, output: PathBuf) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
    enum Crypto {
        Register {
            invitation: PathBuf,
            token_hash: String,
            ttl: u64,
        },
        Seal {
            address: String,
            id: String,
            message: Value,
        },
        Open {
            invitation: PathBuf,
            id: String,
            ciphertext: String,
        },
        SignPeer {
            invitation: PathBuf,
            recipient: String,
            message: Value,
        },
        VerifyPeer {
            address: String,
            recipient: String,
            message: Value,
            signature: String,
        },
    }
    let command: Crypto = serde_json::from_slice(&read_private(&input, 3_000_000)?)
        .map_err(|_| anyhow::anyhow!("invalid mail crypto input"))?;
    let result = match command {
        Crypto::SignPeer {
            invitation,
            recipient,
            message,
        } => {
            let invitation = app.invitation(&absolute(&invitation)?)?;
            json!({"signature":invitation.sign_peer_message(&recipient, &message)?})
        }
        Crypto::VerifyPeer {
            address,
            recipient,
            message,
            signature,
        } => {
            // Invalid peer input is a definitive rejection, distinct from
            // process/configuration failures that the GUI must retry.
            let verified = verify_mail_peer(
                &app.policy.deployment,
                &address,
                &recipient,
                &message,
                &signature,
            );
            json!({"verified":verified})
        }
        Crypto::Register {
            invitation,
            token_hash,
            ttl,
        } => {
            let invitation = app.invitation(&absolute(&invitation)?)?;
            json!({"signature":invitation.mail_registration(&token_hash,ttl)?})
        }
        Crypto::Seal {
            address,
            id,
            message,
        } => {
            let address =
                ReceivingAddress::decode(&address, AddressNetwork::Test, &app.policy.deployment)?;
            let bytes = Zeroizing::new(serde_json::to_vec(&message)?);
            json!({"ciphertext":crate::envelope::encrypt_message(&address,&id,&bytes)?})
        }
        Crypto::Open {
            invitation,
            id,
            ciphertext,
        } => {
            let invitation = app.invitation(&absolute(&invitation)?)?;
            let bytes = invitation
                .decrypt_message(&id, &ciphertext)
                .map_err(|_| anyhow::anyhow!("invalid encrypted message"))?;
            json!({"message":serde_json::from_slice::<Value>(&bytes).map_err(|_|anyhow::anyhow!("invalid encrypted message"))?})
        }
    };
    write_new(
        &absolute(&output)?,
        &Zeroizing::new(serde_json::to_vec(&result)?),
    )?;
    Ok(json!({"completed":true}))
}

pub(super) fn verify_mail_peer(
    deployment: &[u8; 32],
    address: &str,
    recipient: &str,
    message: &Value,
    signature: &str,
) -> bool {
    // k256's signature conversion assumes enough bytes for its first scalar.
    if signature.len() != 128 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    ReceivingAddress::decode(address, AddressNetwork::Test, deployment)
        .and_then(|address| {
            zark_protocol::mail::verify_peer_message(&address, recipient, message, signature)
        })
        .is_ok()
}
