//! Native common-activation checks shared by isolated wallet components.
use crate::{bitcoin::attach_signature, types::Input};
use anyhow::{Result, ensure};
use bitcoin::{OutPoint, Transaction, Txid, consensus::serialize, hashes::Hash};
use std::str::FromStr;
use zark_protocol::{
    handoff::{Digest, FundingOpening},
    hex32,
};

pub(crate) fn funding(deployment: &Digest, input: &Input) -> Result<FundingOpening> {
    ensure!(
        input.deployment == hex::encode(deployment),
        "common input deployment mismatch"
    );
    let txid = Txid::from_str(&input.txid)?;
    ensure!(
        txid.to_string() == input.txid,
        "common input transaction encoding"
    );
    for value in [&input.id, &input.funding_salt, &input.internal_point] {
        ensure!(
            hex::encode(hex::decode(value)?) == *value,
            "noncanonical common input hex"
        );
    }
    let value = FundingOpening {
        deployment: *deployment,
        coin: hex32(&input.id)?,
        salt: hex32(&input.funding_salt)?,
        txid: txid.to_byte_array(),
        vout: input.vout,
        amount: input.amount,
        internal_point: hex::decode(&input.internal_point)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("common input point"))?,
    };
    value.commitment()?;
    Ok(value)
}

pub(crate) fn validate(
    deployment: &Digest,
    coin: &Digest,
    backing: &Input,
    parent: &Input,
    activation: &Transaction,
) -> Result<FundingOpening> {
    let output = funding(deployment, backing)?;
    let input = funding(deployment, parent)?;
    ensure!(
        output.coin == *coin
            && output.vout == 0
            && activation.compute_txid().to_byte_array() == output.txid,
        "common activation backing mismatch"
    );
    ensure!(
        activation.input.len() == 1 && activation.input[0].witness.len() == 1,
        "common activation witness shape"
    );
    let sig: [u8; 64] = activation.input[0].witness[0]
        .try_into()
        .map_err(|_| anyhow::anyhow!("common activation signature"))?;
    let mut expected = crate::bitcoin::activation(
        OutPoint::new(Txid::from_byte_array(input.txid), input.vout),
        input.amount,
        &[(output.amount, output.output_key()?)],
        0,
    )?;
    attach_signature(&mut expected, input.amount, input.output_key()?, &sig)?;
    ensure!(
        serialize(&expected) == serialize(activation),
        "invalid signed common activation"
    );
    Ok(output)
}
