//! Private local witness-hint helper for the fast prover (`zark-fast-helper`).
//!
//! It answers noir-execute's JSON-RPC `resolve_foreign_call` for the donor
//! Brillig oracles `zark_glv_hint_v1`, `zark_glv_batch_hint_v1` and
//! `zark_fixed_generator_hint_v1` on a loopback-only HTTP/1.0 server. Each
//! answer is an untrusted hint recomputed for that request; the unchanged
//! constrained replay validates every value.
//! No request, answer, witness value or error detail is logged, cached or
//! persisted. Framing, rejections and answers stay byte-compatible with the
//! earlier Python helper so witnesses for admitted circuits are unchanged.
mod field;
mod fixed;
mod glv;
mod glv_batch;
mod http;
mod json;
mod rpc;
mod server;
mod tables;

pub use rpc::respond;
pub use server::run;
pub use tables::Tables;

/// Serve honest hints until the parent wallet exits or a stop signal arrives.
pub fn main() -> ! {
    run(respond)
}
