//! One authorization for the exact initial activation and recovery signatures.
//! Public fields are commitments and blinded signing data, never Bitcoin outpoints.
use crate::{bootstrap::BootstrapBinding, handoff::Digest, hash, lineage::IssuanceBinding};
use anyhow::{Result, ensure};

pub struct DepositBinding {
    pub authorization: IssuanceBinding,
    pub bootstrap: BootstrapBinding,
}

impl DepositBinding {
    pub const ENCODED_LEN: usize = IssuanceBinding::ENCODED_LEN + BootstrapBinding::ENCODED_LEN;

    pub fn encode(&self) -> Result<Vec<u8>> {
        let s = &self.authorization.signing;
        let b = &self.bootstrap;
        crate::bootstrap::validate_context(&s.context)?;
        ensure!(s.context == b.context, "deposit signing contexts differ");
        ensure!(
            s.funding == b.active_funding,
            "deposit active funding differs"
        );
        ensure!(
            s.next_capability == b.initial_capability,
            "deposit capability differs"
        );
        ensure!(
            s.draft_server == b.active_server && b.parent_server == b.active_server,
            "deposit authority differs"
        );
        ensure!(s.server_nonce != b.parent_nonce, "deposit nonce reuse");
        ensure!(
            s.nonce_commitment != b.nonce_commitment,
            "deposit blinding reuse"
        );
        let mut out = self.authorization.encode()?;
        out.extend_from_slice(&b.encode()?);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == Self::ENCODED_LEN,
            "deposit authorization length"
        );
        let value = Self {
            authorization: IssuanceBinding::decode(&bytes[..IssuanceBinding::ENCODED_LEN])?,
            bootstrap: BootstrapBinding::decode(&bytes[IssuanceBinding::ENCODED_LEN..])?,
        };
        ensure!(
            value.encode()? == bytes,
            "noncanonical deposit authorization"
        );
        Ok(value)
    }

    pub fn public_inputs(&self) -> Result<Vec<u8>> {
        self.encode()
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/private-handoff/deposit-authorization/v1",
            &self.encode()?,
        ]))
    }
}
