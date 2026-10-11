//! Canonical shared v10 wallet/signer requests. No Bitcoin or receiving-address
//! data belongs in these commands. Claim delta is confidential recipient-only.
use crate::{
    batch::Manifest as BatchManifest,
    certificate::PredecessorKind,
    handoff::{Digest, TransferContext},
    hash,
    head::HeadQuery,
    owner_auth::OwnerAuthorization,
    proof::PROOF_BYTES,
    session::{Purpose, sign_request, verify_request},
};
use anyhow::{Result, ensure};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAX_BODY: usize = 128 * 1024;
pub const MAX_WIRE: usize = MAX_BODY + 4096;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    BootstrapAllocate {},
    BootstrapPrepare {
        parent_funding: Digest,
        active_funding: Digest,
        capability: Digest,
        blinding: Digest,
    },
    BootstrapFreeze {
        statement: Vec<u8>,
    },
    RetrieveBootstrap {
        binding_digest: Digest,
    },
    Reserve {
        owner_authorization: OwnerAuthorization,
    },
    CancelTransfer {},
    BatchReserve {
        manifest: BatchManifest,
        owner_authorization: OwnerAuthorization,
    },
    BatchReady {
        manifest: BatchManifest,
        observed_tip: Digest,
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    BatchAbort {
        manifest: BatchManifest,
    },
    Handover {
        predecessor: PredecessorKind,
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    ProposeRecipient {
        statement: Vec<u8>,
        token: Digest,
        delta: Digest,
        delta_salt: Digest,
    },
    Prepare {
        recovery: Digest,
        blinding: Digest,
    },
    Issue {
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    IssueDeposit {
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    AcceptOrigin {
        state: Digest,
        issuance_identity: Digest,
    },
    AcknowledgeTransfer {
        state: Digest,
        issuance_identity: Digest,
    },
    RetrieveIssued {
        binding_digest: Digest,
    },
    ExitPrepare {
        funding: Digest,
        server_share: Digest,
        capability: Digest,
        exit: Digest,
        blinding: Digest,
        owner_authorization: OwnerAuthorization,
    },
    ExitIssue {
        predecessor: PredecessorKind,
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    RetrieveExit {
        binding_digest: Digest,
    },
    CompleteSender {},
    Head {
        query: HeadQuery,
    },
}
impl Command {
    pub fn purpose(&self) -> Purpose {
        match self {
            Self::BootstrapAllocate {} => Purpose::BootstrapAllocation,
            Self::BootstrapPrepare { .. } => Purpose::BootstrapPreparation,
            Self::BootstrapFreeze { .. } => Purpose::BootstrapFreeze,
            Self::RetrieveBootstrap { .. } => Purpose::BootstrapResponseRecovery,
            Self::Reserve { .. } => Purpose::SenderReservation,
            Self::CancelTransfer {} => Purpose::TransferCancellation,
            Self::BatchReserve { .. } => Purpose::BatchReservation,
            Self::BatchReady { .. } => Purpose::BatchReadiness,
            Self::BatchAbort { .. } => Purpose::BatchAbort,
            Self::Handover { .. } => Purpose::SenderHandover,
            Self::ProposeRecipient { .. } => Purpose::RecipientProposal,
            Self::Prepare { .. } => Purpose::RecoveryPreparation,
            Self::Issue { .. } => Purpose::RecoveryIssuance,
            Self::IssueDeposit { .. } => Purpose::DepositIssuance,
            Self::AcceptOrigin { .. } => Purpose::OriginAcceptance,
            Self::AcknowledgeTransfer { .. } => Purpose::TransferAcknowledgement,
            Self::RetrieveIssued { .. } => Purpose::IssuedResponseRecovery,
            Self::CompleteSender {} => Purpose::SenderCompletion,
            Self::Head { .. } => Purpose::SignerHead,
            Self::ExitPrepare { .. } => Purpose::ExitPreparation,
            Self::ExitIssue { .. } => Purpose::ExitIssuance,
            Self::RetrieveExit { .. } => Purpose::ExitResponseRecovery,
        }
    }
    pub fn proof(&self) -> Option<&[u8]> {
        match self {
            Self::BatchReady { proof, .. }
            | Self::Handover { proof, .. }
            | Self::Issue { proof, .. }
            | Self::IssueDeposit { proof, .. }
            | Self::ExitIssue { proof, .. } => Some(proof),
            _ => None,
        }
    }
    pub fn body(&self) -> Result<Zeroizing<Vec<u8>>> {
        if let Self::BatchReady { observed_tip, .. } = self {
            ensure!(*observed_tip != [0; 32], "empty batch Bitcoin tip");
        }
        if let Some(proof) = self.proof() {
            ensure!(proof.len() == PROOF_BYTES, "private proof length");
        }
        let body = Zeroizing::new(serde_json::to_vec(self)?);
        ensure!(body.len() <= MAX_BODY, "private request too large");
        Ok(body)
    }
    pub fn decode(body: &[u8]) -> Result<Self> {
        ensure!(
            !body.is_empty() && body.len() <= MAX_BODY,
            "private request size"
        );
        let command: Self =
            serde_json::from_slice(body).map_err(|_| anyhow::anyhow!("invalid private command"))?;
        ensure!(*command.body()? == body, "noncanonical private command");
        Ok(command)
    }
    pub fn digest(&self, context: &TransferContext) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/private-engine/request/v1",
            &context.encode()?,
            &self.body()?,
        ]))
    }
}

#[derive(Clone)]
pub struct Request {
    pub context: TransferContext,
    pub command: Command,
    pub signature: [u8; 64],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    context: String,
    command: Command,
    signature: String,
}
impl Request {
    pub fn sign(context: TransferContext, command: Command, key: &SigningKey) -> Result<Self> {
        let signature = sign_request(key, &context, command.purpose(), &command.digest(&context)?)?;
        Ok(Self {
            context,
            command,
            signature,
        })
    }
    pub fn digest(&self) -> Result<Digest> {
        self.command.digest(&self.context)
    }
    pub fn authenticate(&self) -> Result<Digest> {
        let digest = self.digest()?;
        verify_request(
            &self.context,
            self.command.purpose(),
            &digest,
            &self.signature,
        )?;
        Ok(digest)
    }
    pub fn from_body(context: TransferContext, body: &[u8], signature: [u8; 64]) -> Result<Self> {
        let value = Self {
            context,
            command: Command::decode(body)?,
            signature,
        };
        value.authenticate()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.authenticate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(&Envelope {
            version: crate::handoff::PROTOCOL_VERSION,
            context: hex::encode(self.context.encode()?),
            command: self.command.clone(),
            signature: hex::encode(self.signature),
        })?);
        ensure!(bytes.len() <= MAX_WIRE, "private envelope size");
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_WIRE,
            "private envelope size"
        );
        let envelope: Envelope = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid private envelope"))?;
        ensure!(
            envelope.version == crate::handoff::PROTOCOL_VERSION,
            "private envelope version"
        );
        let ctx = hex::decode(&envelope.context)?;
        ensure!(
            hex::encode(&ctx) == envelope.context,
            "noncanonical context"
        );
        let signature = hex::decode(&envelope.signature)?;
        ensure!(
            hex::encode(&signature) == envelope.signature,
            "noncanonical signature"
        );
        let request = Self {
            context: TransferContext::decode(&ctx)?,
            command: envelope.command,
            signature: signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("private signature length"))?,
        };
        request.authenticate()?;
        ensure!(*request.encode()? == bytes, "noncanonical private envelope");
        Ok(request)
    }
}
