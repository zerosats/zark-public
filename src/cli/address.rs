//! Validate receiving addresses and extract Bitcoin destinations.
use anyhow::{Result, ensure};
use bitcoin::{Address, Network};
use std::str::FromStr;
use zark_protocol::address::{AddressNetwork, ReceivingAddress};
use zark_protocol::handoff::Digest;

pub(super) fn taproot_destination(address: &Address) -> Result<Digest> {
    let script = address.script_pubkey();
    let bytes = script.as_bytes();
    ensure!(
        bytes.len() == 34 && bytes[..2] == [0x51, 0x20],
        "this prototype requires a Taproot Bitcoin exit address"
    );
    Ok(bytes[2..].try_into()?)
}

pub(super) fn validate_address(
    encoded: &str,
    deployment: &Digest,
    bitcoin_network: Network,
) -> Result<&'static str> {
    if encoded.starts_with("tzark1") {
        ReceivingAddress::decode(encoded, AddressNetwork::Test, deployment)
            .map_err(|_| anyhow::anyhow!("invalid Zark receiving address"))?;
        Ok("zark")
    } else {
        let address = Address::from_str(encoded)
            .and_then(|address| address.require_network(bitcoin_network))
            .map_err(|_| anyhow::anyhow!("invalid Bitcoin receiving address"))?;
        taproot_destination(&address)?;
        Ok("bitcoin")
    }
}
