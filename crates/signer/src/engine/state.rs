//! Persisted coin lifecycle and secret retirement; field order and serde formats are stable.
use super::{
    Deserialize, Digest, IssuedOriginRecord, IssuedTransferRecord, PredecessorKind, Serialize,
    TransferContext, Zeroize, bootstrap,
};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    BootstrapAllocated,
    BootstrapPrepared,
    Origin,
    OriginPrepared,
    OriginIssued,
    Accepted,
    Reserved,
    Handover,
    RecipientProposed,
    Prepared,
    Issued,
    ExitPrepared,
    Terminal,
}

/// Frozen terminal-signing request. After release this contains only the public
/// signer point, commitments and exact signature response, never either scalar.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Exit {
    pub(super) context: TransferContext,
    pub(super) funding: Digest,
    pub(super) capability: Digest,
    pub(super) server_share: Digest,
    pub(super) server_point: Vec<u8>,
    pub(super) exit: Digest,
    pub(super) blinding: Digest,
    pub(super) nonce_secret: Option<Digest>,
    pub(super) nonce_point: Vec<u8>,
    pub(super) signing: Option<Vec<u8>>,
    pub(super) partial: Option<Digest>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub(super) origin: bool,
    pub(super) batch: Option<Digest>,
    pub(super) sender: Option<TransferContext>,
    pub(super) recipient: Option<TransferContext>,
    pub(super) mask: Option<Digest>,
    pub(super) mask_salt: Option<Digest>,
    pub(super) cm: Option<Digest>,
    pub(super) handover: Option<Vec<u8>>,
    pub(super) claim: Option<Vec<u8>>,
    pub(super) draft_secret: Option<Digest>,
    pub(super) draft_salt: Option<Digest>,
    pub(super) recovery: Option<Digest>,
    pub(super) blinding: Option<Digest>,
    pub(super) nonce_secret: Option<Digest>,
    pub(super) nonce_point: Option<Vec<u8>>,
    pub(super) signing: Option<Vec<u8>>,
    pub(super) partial: Option<Digest>,
    pub(super) issued_transfer: Option<IssuedTransferRecord>,
    pub(super) issued_origin: Option<IssuedOriginRecord>,
}
impl Pending {
    pub(super) fn new(origin: bool) -> Self {
        Self {
            origin,
            batch: None,
            sender: None,
            recipient: None,
            mask: None,
            mask_salt: None,
            cm: None,
            handover: None,
            claim: None,
            draft_secret: None,
            draft_salt: None,
            recovery: None,
            blinding: None,
            nonce_secret: None,
            nonce_point: None,
            signing: None,
            partial: None,
            issued_transfer: None,
            issued_origin: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Coin {
    pub(super) deployment: Digest,
    pub(super) coin: Digest,
    pub(super) funding: Digest,
    pub(super) state: Digest,
    pub(super) capability: Digest,
    pub(super) owner_kind: PredecessorKind,
    pub(super) server_secret: Digest,
    pub(super) server_salt: Digest,
    pub(super) current_session: TransferContext,
    pub(super) phase: Phase,
    pub(super) pending: Option<Pending>,
    pub(super) exit: Option<Exit>,
    pub(super) bootstrap: Option<bootstrap::Bootstrap>,
}
impl Drop for Coin {
    fn drop(&mut self) {
        self.server_secret.zeroize();
        if let Some(exit) = &mut self.exit
            && let Some(nonce) = &mut exit.nonce_secret
        {
            nonce.zeroize();
        }
        if let Some(p) = &mut self.pending {
            if let Some(v) = &mut p.mask {
                v.zeroize();
            }
            if let Some(v) = &mut p.mask_salt {
                v.zeroize();
            }
            if let Some(v) = &mut p.draft_secret {
                v.zeroize();
            }
            if let Some(v) = &mut p.nonce_secret {
                v.zeroize();
            }
        }
    }
}
