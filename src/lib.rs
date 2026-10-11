//! Whole-coin private handoffs with receiver-owned Bitcoin recovery.
//! This research implementation is not an audited signing protocol.
pub mod bitcoin;
pub mod bootstrap;
pub mod chain;
pub mod cli;
mod common;
pub mod envelope;
pub mod exit;
pub mod exit_operation;
pub mod fast_helper;
pub mod freshness;
pub mod invitation;
pub mod offer;
pub mod origin;
pub(crate) mod outgoing;
pub mod prover;
pub mod receiver;
pub mod recovery;
pub mod recovery_export;
pub mod sender;
pub mod signing;
pub mod types;

#[cfg(test)]
mod test_support;
