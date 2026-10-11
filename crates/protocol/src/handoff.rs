//! Canonical handoff, funding, recovery and ownership-state contracts.
//!
//! Encoding, commitments and delay checks do not verify ownership or a proof.
//! Signing also requires the composed proof and current signer state.
mod bindings;
mod commitments;
mod context;
mod funding;
mod schedule;
mod state;

use anyhow::{Result, ensure};
pub use bindings::{ClaimBinding, HandoverBinding, SigningBinding};
pub use commitments::{
    blinding_commitment, bridge_commitment, capability_commitment, delta_commitment,
    draft_access_commitment, issuance_commitment, mask_commitment, masked_share_commitment,
    origin_previous_capability, origin_previous_state, origin_refresh_commitment,
    policy_commitment, recipient_claim_commitment, refresh_commitment,
};
pub use context::{OperationScope, TransferContext, TransferIntent};
pub use funding::{FundingOpening, RecoveryOpening};
pub use schedule::{RecoveryDelay, RecoverySchedule, TransferWindow};
pub use state::{ServerShareOpening, StateOpening};

pub const PROTOCOL_VERSION: u32 = 10;
pub const INITIAL_OWNER_LIMIT: u32 = 8;
pub type Digest = [u8; 32];

fn nonzero(value: &Digest) -> Result<()> {
    ensure!(*value != [0; 32], "zero context or commitment");
    Ok(())
}

// Decoder callers first enforce the exact fixed statement length.
fn part<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&bytes[offset..offset + N]);
    value
}

pub(crate) fn validate_recursive_vk_hash(value: &Digest) -> Result<()> {
    // Noir Field is BN254's scalar field, distinct from secp256k1 scalars.
    let field_modulus: Digest = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];
    nonzero(value)?;
    ensure!(
        *value < field_modulus,
        "noncanonical recursive VK field hash"
    );
    Ok(())
}
