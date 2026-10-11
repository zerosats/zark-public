//! Private peer offer, isolated from accepted ownership and live wallet flows.
//! Native bindings and an actual pinned outer proof precede invitation reservation.
//! Fresh signer-head and Bitcoin observations are separate orchestration gates.
//! No predecessor recovery, payout, server point, mask opening or history is carried.
use crate::{bitcoin::attach_signature, envelope::OfferContext, types::Input};
use anyhow::{Result, ensure};
use bitcoin::{
    OutPoint, Transaction, Txid,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    certificate::PredecessorKind,
    handoff::{
        Digest, FundingOpening, RecoveryDelay, bridge_commitment, draft_access_commitment,
        masked_share_commitment, recipient_claim_commitment,
    },
    hex32,
    lineage::{LineageHandoverBinding, LineagePolicy},
    proof::{PROOF_BYTES, PinnedVerifier},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_OFFER_PLAINTEXT_BYTES: usize = 40_000;
const MAX_ACTIVATION_BYTES: usize = 1_024;
const SCHEMA: &str = "zark-private-handover-offer";

/// Sender-local material for an encrypted peer message. Deliberately has no
/// Debug or serialization implementation. A supplied proof is not yet verified.
pub struct OfferParameters {
    pub predecessor: PredecessorKind,
    pub handover: LineageHandoverBinding,
    pub proof: Vec<u8>,
    pub backing: Input,
    pub activation_input: Input,
    pub activation: Transaction,
    pub masked_share: Digest,
    pub masked_share_salt: Digest,
    pub bridge_salt: Digest,
    pub old_delay: RecoveryDelay,
    pub claim_salt: Digest,
    pub token: Digest,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    #[zeroize(skip)]
    predecessor: PredecessorKind,
    handover: String,
    proof: String,
    // These are common Bitcoin data, not a predecessor private opening.
    #[zeroize(skip)]
    backing: Input,
    #[zeroize(skip)]
    activation_input: Input,
    activation: String,
    masked_share: Digest,
    masked_share_salt: Digest,
    bridge_salt: Digest,
    old_delay: u32,
    claim_salt: Digest,
    token: Digest,
}

/// Native checks succeeded, but historical authorization has NOT been verified.
/// This cannot be used as a verified offer or receipt-acceptance token.
pub struct UnverifiedOffer {
    record: Record,
    handover: LineageHandoverBinding,
    proof: Zeroizing<Vec<u8>>,
    activation: Transaction,
}

/// Actual outer handover proof verified under local pins. This is not current
/// signer entitlement, live backing, completed recovery, or accepted ownership.
/// Private material remains contained for a future narrow recipient journal API.
pub struct VerifiedOffer {
    offer: UnverifiedOffer,
}

/// Actor-local openings consumed only by the recipient journal and witness
/// builders. This is not a public secret-export interface or signer message.
pub(crate) struct RecipientMaterial {
    pub masked_share: Digest,
    pub masked_share_salt: Digest,
    pub bridge_salt: Digest,
    pub old_delay: u32,
    pub claim_salt: Digest,
    pub token: Digest,
}

impl Drop for RecipientMaterial {
    fn drop(&mut self) {
        self.masked_share.zeroize();
        self.masked_share_salt.zeroize();
        self.bridge_salt.zeroize();
        self.claim_salt.zeroize();
        self.token.zeroize();
    }
}

impl UnverifiedOffer {
    pub fn from_parts(
        parameters: OfferParameters,
        recipient: &ReceivingAddress,
        expected: &OfferContext,
        policy: &LineagePolicy,
    ) -> Result<Self> {
        ensure!(parameters.proof.len() == PROOF_BYTES, "offer proof length");
        let activation = serialize(&parameters.activation);
        ensure!(
            activation.len() <= MAX_ACTIVATION_BYTES,
            "offer activation size"
        );
        let record = Record {
            schema: SCHEMA.into(),
            version: 2,
            predecessor: parameters.predecessor,
            handover: hex::encode(parameters.handover.encode()?),
            proof: hex::encode(&parameters.proof),
            backing: parameters.backing,
            activation_input: parameters.activation_input,
            activation: hex::encode(activation),
            masked_share: parameters.masked_share,
            masked_share_salt: parameters.masked_share_salt,
            bridge_salt: parameters.bridge_salt,
            old_delay: parameters.old_delay.blocks(),
            claim_salt: parameters.claim_salt,
            token: parameters.token,
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&record)?);
        Self::decode(&bytes, recipient, expected, policy)
    }

    /// Strictly bounded private plaintext parsing and local recipient binding.
    /// No invitation is reserved and no proof validity is inferred from parsing.
    pub fn decode(
        bytes: &[u8],
        recipient: &ReceivingAddress,
        expected: &OfferContext,
        policy: &LineagePolicy,
    ) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_OFFER_PLAINTEXT_BYTES,
            "offer plaintext size"
        );
        let record: Record = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid private offer record"))?;
        ensure!(
            record.schema == SCHEMA && record.version == 2,
            "unsupported private offer record"
        );
        ensure!(
            recipient.network() == AddressNetwork::Test
                && *recipient.deployment() == expected.deployment,
            "offer recipient deployment"
        );
        let handover = LineageHandoverBinding::decode(&canonical_hex(
            &record.handover,
            LineageHandoverBinding::ENCODED_LEN,
        )?)?;
        let binding = &handover.handover;
        ensure!(
            binding.intent.deployment == expected.deployment
                && binding.intent.coin == expected.coin
                && binding.intent.operation == expected.operation,
            "offer context mismatch"
        );
        policy.require(
            &expected.deployment,
            &binding.policy,
            &handover.origin_key,
            &handover.role_hashes,
        )?;
        let claim_key: Digest = recipient.claim_key()[1..].try_into()?;
        ensure!(
            recipient_claim_commitment(
                &expected.deployment,
                &expected.coin,
                &expected.operation,
                &claim_key,
                &record.claim_salt
            )? == binding.intent.recipient_claim,
            "offer is for another recipient claim"
        );
        let funding = checked_input(&record.backing, &expected.deployment)?;
        ensure!(
            funding.coin == expected.coin && funding.commitment()? == binding.funding,
            "offer backing commitment mismatch"
        );
        let parent = checked_input(&record.activation_input, &expected.deployment)?;
        let raw = canonical_hex_bounded(&record.activation, MAX_ACTIVATION_BYTES)?;
        let activation: Transaction = deserialize(&raw)?;
        ensure!(
            serialize(&activation) == raw,
            "noncanonical activation encoding"
        );
        ensure!(
            record.backing.vout == 0
                && activation.compute_txid() == Txid::from_str(&record.backing.txid)?,
            "activation does not create offer backing"
        );
        let mut exact_activation = crate::bitcoin::activation(
            OutPoint::new(
                Txid::from_str(&record.activation_input.txid)?,
                record.activation_input.vout,
            ),
            record.activation_input.amount,
            &[(record.backing.amount, funding.output_key()?)],
            0,
        )?;
        ensure!(
            activation.input.len() == 1 && activation.input[0].witness.len() == 1,
            "offer activation witness shape"
        );
        let signature: [u8; 64] = activation.input[0]
            .witness
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing activation signature"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("activation signature length"))?;
        attach_signature(
            &mut exact_activation,
            record.activation_input.amount,
            parent.output_key()?,
            &signature,
        )?;
        ensure!(
            serialize(&exact_activation) == raw,
            "offer activation transaction mismatch"
        );
        let delay = RecoveryDelay::from_sequence(record.old_delay)?;
        ensure!(
            draft_access_commitment(&binding.intent, &record.token)? == binding.draft_access,
            "offer draft token mismatch"
        );
        ensure!(
            (record.predecessor == PredecessorKind::Origin
                && delay == policy.schedule.delay_after(0)?)
                || (record.predecessor == PredecessorKind::Transfer
                    && delay.blocks() < policy.schedule.initial),
            "offer predecessor role and delay differ"
        );
        let next = delay
            .blocks()
            .checked_sub(policy.schedule.gap)
            .ok_or_else(|| anyhow::anyhow!("offer recovery budget exhausted"))?;
        policy
            .schedule
            .check_transition(delay, RecoveryDelay::from_sequence(next)?)?;
        ensure!(
            bridge_commitment(
                &binding.intent,
                &binding.funding,
                delay,
                &binding.policy,
                &record.bridge_salt
            )? == binding.bridge,
            "offer bridge commitment mismatch"
        );
        ensure!(
            masked_share_commitment(
                &binding.intent,
                &record.masked_share,
                &record.masked_share_salt
            )? == binding.masked_share,
            "offer masked-share commitment mismatch"
        );
        let proof = Zeroizing::new(canonical_hex(&record.proof, PROOF_BYTES)?);
        Ok(Self {
            record,
            handover,
            proof,
            activation,
        })
    }

    /// Explicit private peer encoding. Encrypt before transport; do not log it.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(
            bytes.len() <= MAX_OFFER_PLAINTEXT_BYTES,
            "offer plaintext size"
        );
        Ok(bytes)
    }

    pub fn handover(&self) -> &LineageHandoverBinding {
        &self.handover
    }
    pub(crate) fn predecessor(&self) -> PredecessorKind {
        self.record.predecessor
    }

    pub(crate) fn recipient_material(&self) -> RecipientMaterial {
        RecipientMaterial {
            masked_share: self.record.masked_share,
            masked_share_salt: self.record.masked_share_salt,
            bridge_salt: self.record.bridge_salt,
            old_delay: self.record.old_delay,
            claim_salt: self.record.claim_salt,
            token: self.record.token,
        }
    }

    pub(crate) fn common_backing(&self) -> &Input {
        &self.record.backing
    }
    pub(crate) fn common_activation_input(&self) -> &Input {
        &self.record.activation_input
    }
    pub(crate) fn common_activation(&self) -> &Transaction {
        &self.activation
    }
    pub(crate) fn outer_proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn verify(self, verifier: &PinnedVerifier, scratch: &Path) -> Result<VerifiedOffer> {
        verifier.sender_handover(
            self.record.predecessor,
            &self.handover,
            &self.proof,
            scratch,
        )?;
        Ok(VerifiedOffer { offer: self })
    }
}

impl VerifiedOffer {
    pub fn handover(&self) -> &LineageHandoverBinding {
        &self.offer.handover
    }
    pub fn backing(&self) -> &Input {
        &self.offer.record.backing
    }
    pub fn activation_input(&self) -> &Input {
        &self.offer.record.activation_input
    }
    pub fn activation(&self) -> &Transaction {
        &self.offer.activation
    }
    pub fn old_delay(&self) -> Result<RecoveryDelay> {
        RecoveryDelay::from_sequence(self.offer.record.old_delay)
    }
}

fn canonical_hex(value: &str, bytes: usize) -> Result<Vec<u8>> {
    ensure!(value.len() == bytes * 2, "offer field length");
    canonical_hex_bounded(value, bytes)
}

fn canonical_hex_bounded(value: &str, max_bytes: usize) -> Result<Vec<u8>> {
    ensure!(
        !value.is_empty()
            && value.len() <= max_bytes * 2
            && value.len().is_multiple_of(2)
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "noncanonical offer hex"
    );
    Ok(hex::decode(value)?)
}

fn checked_input(input: &Input, deployment: &Digest) -> Result<FundingOpening> {
    ensure!(
        input.deployment == hex::encode(deployment),
        "offer input deployment"
    );
    canonical_hex(&input.id, 32)?;
    canonical_hex(&input.funding_salt, 32)?;
    let txid = Txid::from_str(&input.txid)?;
    ensure!(
        txid.to_string() == input.txid,
        "noncanonical offer outpoint"
    );
    let funding = FundingOpening {
        deployment: *deployment,
        coin: hex32(&input.id)?,
        salt: hex32(&input.funding_salt)?,
        txid: txid.to_byte_array(),
        vout: input.vout,
        amount: input.amount,
        internal_point: canonical_hex(&input.internal_point, 64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("offer input point length"))?,
    };
    funding.commitment()?;
    Ok(funding)
}
