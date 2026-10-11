//! Validate exact signer response shapes and frozen request bytes.
use super::persistence::decode_hex;
use super::{RecoveryRequest, RequestRecord};
use anyhow::{Result, ensure};
use zark_protocol::handoff::TransferContext;
use zark_protocol::session::Purpose;
use zark_protocol::wire::{Command, Request};

pub(super) fn checked_recovery_request(
    context: &TransferContext,
    purpose: Purpose,
    saved: &RequestRecord,
    expected_body: &[u8],
) -> Result<RecoveryRequest> {
    let command = Command::decode(expected_body)?;
    ensure!(
        command.purpose() == purpose
            && saved.body == hex::encode(expected_body)
            && saved.digest == command.digest(context)?,
        "frozen recovery request differs from saved native context"
    );
    let signature: [u8; 64] = decode_hex(&saved.signature, 64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("recovery request signature size"))?;
    Request::from_body(context.clone(), expected_body, signature)?;
    Ok(RecoveryRequest {
        body: expected_body.to_vec(),
        signature,
    })
}

pub(super) fn exact_response_fields(value: &serde_json::Value, names: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("recipient response must be an object"))?;
    ensure!(
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name)),
        "unexpected recipient response fields"
    );
    Ok(())
}
pub(super) fn response_bytes<const N: usize>(
    value: &serde_json::Value,
    name: &str,
) -> Result<[u8; N]> {
    let array = value
        .get(name)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("recipient response field shape"))?;
    ensure!(array.len() == N, "recipient response field length");
    let mut bytes = [0; N];
    for (index, element) in array.iter().enumerate() {
        bytes[index] = element
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| anyhow::anyhow!("recipient response byte"))?;
    }
    Ok(bytes)
}
