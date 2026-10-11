//! Opt-in fixed-label diagnostics. No identifiers, payloads or error text.
use std::{
    io::Write,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub enum Phase {
    AppLoad,
    CrsAuthentication,
    VerifierInitialization,
    ProverInitialization,
    ExternalVerification,
    VerificationCacheHit,
    VerifierAssetAuthentication,
    WorkerAssetCheck,
    SignerConnect,
    SignerConnectWait,
    SignerExchange,
    ChainObservation,
    ChainRpc,
    ChainPrepare,
    RecoveryOpen,
    RecoveryValidation,
    LocalDurableWrite,
    ProofInputFreeze,
    ProverProcessPrepare,
    ProverProcessSpawn,
    ProverProcessWait,
    HelperProcessSpawn,
    HelperReadiness,
    VerifierProcessSpawn,
    VerifierProcessWait,
    SignerIngress,
    SignerQueue,
    SignerProcessing,
    SignerPlan,
    SignerVerification,
    SignerCommit,
    SignerReply,
}
impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::AppLoad => "app_load",
            Self::CrsAuthentication => "crs_authentication",
            Self::VerifierInitialization => "verifier_initialization",
            Self::ProverInitialization => "prover_initialization",
            Self::ExternalVerification => "external_verification",
            Self::VerificationCacheHit => "verification_cache_hit",
            Self::VerifierAssetAuthentication => "verifier_asset_authentication",
            Self::WorkerAssetCheck => "worker_asset_check",
            Self::SignerConnect => "signer_connect",
            Self::SignerConnectWait => "signer_connect_wait",
            Self::SignerExchange => "signer_exchange",
            Self::ChainObservation => "chain_observation",
            Self::ChainRpc => "chain_rpc",
            Self::ChainPrepare => "chain_prepare",
            Self::RecoveryOpen => "recovery_open",
            Self::RecoveryValidation => "recovery_validation",
            Self::LocalDurableWrite => "local_durable_write",
            Self::ProofInputFreeze => "proof_input_freeze",
            Self::ProverProcessPrepare => "prover_process_prepare",
            Self::ProverProcessSpawn => "prover_process_spawn",
            Self::ProverProcessWait => "prover_process_wait",
            Self::HelperProcessSpawn => "helper_process_spawn",
            Self::HelperReadiness => "helper_readiness",
            Self::VerifierProcessSpawn => "verifier_process_spawn",
            Self::VerifierProcessWait => "verifier_process_wait",
            Self::SignerIngress => "signer_ingress",
            Self::SignerQueue => "signer_queue",
            Self::SignerProcessing => "signer_processing",
            Self::SignerPlan => "signer_plan",
            Self::SignerVerification => "signer_verification",
            Self::SignerCommit => "signer_commit",
            Self::SignerReply => "signer_reply",
        }
    }
}
pub struct Span(Phase, Option<Instant>);
impl Span {
    pub fn new(phase: Phase) -> Self {
        Self(phase, enabled().then(Instant::now))
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if let Some(start) = self.1 {
            record(self.0, start.elapsed());
        }
    }
}
fn enabled() -> bool {
    std::env::var_os("ZARK_TIMINGS").is_some_and(|v| v == "1")
}
pub fn record(phase: Phase, elapsed: Duration) {
    if enabled() {
        // Diagnostics cannot fail a durable wallet operation, even with a closed pipe.
        let _ = writeln!(
            std::io::stderr().lock(),
            "ZARK_STAGE_TIMING {{\"phase\":\"{}\",\"milliseconds\":{}}}",
            phase.label(),
            elapsed.as_millis()
        );
    }
}
