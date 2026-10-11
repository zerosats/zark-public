//! Independent owner-key authorization before releasing masks or exit nonces.
//! Signatures authorize a frozen operation; they do not replace its ZK relation.
use crate::{
    handoff::{Digest, OperationScope, PROTOCOL_VERSION, TransferContext},
    hash, random32,
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Reject the negated scalar even when it has the same x-only public key.
pub fn normalized_key(secret: &Digest) -> Result<SigningKey> {
    let key = SigningKey::from_bytes(secret)?;
    ensure!(
        &key.to_bytes()[..] == secret,
        "owner secret is not normalized"
    );
    Ok(key)
}

pub fn generate_secret() -> Digest {
    SigningKey::from_bytes(&crate::random_scalar().to_bytes())
        .expect("nonzero scalar")
        .to_bytes()
        .into()
}

pub fn public_capability_commitment(
    deployment: &Digest,
    coin: &Digest,
    public_key: &Digest,
) -> Result<Digest> {
    ensure!(
        *deployment != [0; 32] && *coin != [0; 32],
        "owner capability domain"
    );
    VerifyingKey::from_bytes(public_key)?;
    Ok(crate::application_hash::hash(&[
        b"ZARK/private-handoff/owner-capability/v1",
        &PROTOCOL_VERSION.to_le_bytes(),
        deployment,
        coin,
        public_key,
    ]))
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OwnerPurpose {
    Reserve = 1,
    BatchReserve = 2,
    ExitPrepare = 3,
}

/// Unsigned preimage. Construction chooses the purpose, never the remote caller.
pub struct OwnerAuthorizationPayload {
    purpose: OwnerPurpose,
    context: TransferContext,
    command_data: Vec<u8>,
}
impl OwnerAuthorizationPayload {
    pub fn reservation(context: &TransferContext) -> Result<Self> {
        context.encode()?;
        ensure!(
            context.start_revision > 0,
            "owner authorization requires accepted revision"
        );
        ensure!(
            context.recipient_claim
                != crate::exit::intent(&context.deployment, &context.coin, &context.operation)?,
            "exit requires exit owner purpose"
        );
        Ok(Self {
            purpose: match context.scope {
                OperationScope::Single => OwnerPurpose::Reserve,
                OperationScope::Batch { .. } => OwnerPurpose::BatchReserve,
            },
            context: context.clone(),
            command_data: vec![],
        })
    }
    pub fn exit(
        context: &TransferContext,
        funding: &Digest,
        server_share: &Digest,
        exit: &Digest,
        blinding: &Digest,
    ) -> Result<Self> {
        crate::exit::validate_context(context)?;
        let mut command_data = Vec::with_capacity(128);
        for value in [funding, server_share, exit, blinding] {
            ensure!(*value != [0; 32], "empty owner exit field");
            command_data.extend_from_slice(value);
        }
        Ok(Self {
            purpose: OwnerPurpose::ExitPrepare,
            context: context.clone(),
            command_data,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![self.purpose as u8];
        bytes.extend_from_slice(&self.context.encode()?);
        bytes.extend_from_slice(&self.command_data);
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/private-handoff/owner-authorization/v1",
            &self.encode()?,
        ]))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAuthorization {
    pub public_key: Digest,
    pub signature: Vec<u8>,
}
impl OwnerAuthorization {
    fn sign(payload: &OwnerAuthorizationPayload, secret: &Digest) -> Result<Self> {
        let key = normalized_key(secret)?;
        ensure!(
            key.verifying_key().to_bytes()[..] != payload.context.session_auth,
            "owner and session keys must differ"
        );
        Ok(Self {
            public_key: key.verifying_key().to_bytes().into(),
            signature: key
                .sign_raw(&payload.digest()?, &random32())?
                .to_bytes()
                .to_vec(),
        })
    }
    fn verify(
        &self,
        payload: &OwnerAuthorizationPayload,
        current_capability: &Digest,
    ) -> Result<()> {
        ensure!(
            self.public_key != payload.context.session_auth,
            "owner and session keys must differ"
        );
        ensure!(
            public_capability_commitment(
                &payload.context.deployment,
                &payload.context.coin,
                &self.public_key
            )? == *current_capability,
            "wrong current owner key"
        );
        VerifyingKey::from_bytes(&self.public_key)?.verify_raw(
            &payload.digest()?,
            &Signature::try_from(self.signature.as_slice())?,
        )?;
        Ok(())
    }
    pub fn sign_reservation(context: &TransferContext, secret: &Digest) -> Result<Self> {
        Self::sign(&OwnerAuthorizationPayload::reservation(context)?, secret)
    }
    pub fn verify_reservation(
        &self,
        context: &TransferContext,
        current_capability: &Digest,
    ) -> Result<()> {
        self.verify(
            &OwnerAuthorizationPayload::reservation(context)?,
            current_capability,
        )
    }
    pub fn sign_exit(
        context: &TransferContext,
        funding: &Digest,
        server_share: &Digest,
        exit: &Digest,
        blinding: &Digest,
        secret: &Digest,
    ) -> Result<Self> {
        Self::sign(
            &OwnerAuthorizationPayload::exit(context, funding, server_share, exit, blinding)?,
            secret,
        )
    }
    pub fn verify_exit(
        &self,
        context: &TransferContext,
        current_capability: &Digest,
        funding: &Digest,
        server_share: &Digest,
        exit: &Digest,
        blinding: &Digest,
    ) -> Result<()> {
        self.verify(
            &OwnerAuthorizationPayload::exit(context, funding, server_share, exit, blinding)?,
            current_capability,
        )
    }
}
