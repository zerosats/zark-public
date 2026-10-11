//! Synthetic byte-equivalence corpus and opt-in, in-process RPC benchmark.
//! Run the ignored test in release mode on both revisions, alternating runs.
//! This includes parsing/arithmetic/encoding, but not HTTP, witness execution
//! or proving. Inputs are constructed before timing; no wallet files are read.
use super::{Case, hexes, tables};
use crate::fast_helper::rpc::{BATCH_ORACLE, FIXED_ORACLE, GLV_ORACLE, respond};
use ring::digest::{Context, SHA256};
use serde_json::{Value, json};
use std::hint::black_box;
use std::time::Instant;

// Recorded from the unmodified 4d57c06 helper, not from optimized kernels.
const BASELINE_DIGEST: &str = "dc72b1f9ea7aacce79f88c32d83d53b9f6295949e5937c8c0030cdb1be1a8741";

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut requests = Vec::new();
    for seed in 0..12 {
        let mut case = Case::new(seed);
        if seed == 0 {
            case.digits = [[0; 32]; 6];
            case.skews = [false; 6];
        } else if seed == 1 {
            case.digits = [[15; 32]; 6];
            case.skews = [true; 6];
        }
        let batch = case.request(seed);
        let mut glv = batch.clone();
        glv["params"][0]["function"] = json!(GLV_ORACLE);
        let points = batch["params"][0]["inputs"][0].as_array().unwrap();
        glv["params"][0]["inputs"] = json!([
            points[..12],
            hexes(case.digits[..2].iter().flatten().copied().map(u128::from)),
            hexes(case.skews[..2].iter().copied().map(u128::from)),
            format!("{:x}", u8::from(case.negate[0])),
            "0",
            "0"
        ]);
        let fixed = json!({"jsonrpc":"2.0", "id":seed, "method":"resolve_foreign_call",
        "params":[{"session_id":8, "function":FIXED_ORACLE, "inputs":[
            hexes((0..42).map(|i| u128::from((seed * 7 + i * 3) % 32))),
            hexes((0..42).map(|i| u128::from((seed + i) % 2)))
        ]}]});
        for (label, request) in [("batch", batch), ("glv", glv), ("fixed", fixed)] {
            requests.push((label, serde_json::to_vec(&request).unwrap()));
        }
    }
    for index in [255, 256, 511] {
        let mut case = Case::new(5);
        case.forced = true;
        case.index = index;
        requests.push((
            "batch",
            serde_json::to_vec(&case.request(u64::MAX)).unwrap(),
        ));
    }
    // Force an equal-x first addition, then check normal selection skips it.
    // Preserve the complete table prefix and the exact zero suffix on failure.
    let offset = tables().wide_bank[0][0];
    let mut case = Case::new(7);
    case.digits[0][0] = 8;
    let mut request = case.request(99);
    let image = super::Point {
        x: offset.x * super::Fp::beta(),
        y: if case.negate[0] { -offset.y } else { offset.y },
    };
    let coordinates = [offset.x, offset.y, image.x, image.y]
        .into_iter()
        .flat_map(super::Fp::limbs);
    for (i, value) in coordinates.enumerate() {
        request["params"][0]["inputs"][0][i] = json!(format!("{value:064x}"));
    }
    requests.push(("batch", serde_json::to_vec(&request).unwrap()));
    request["params"][0]["inputs"][4] = json!("1");
    requests.push(("forced_failure", serde_json::to_vec(&request).unwrap()));
    requests
}

fn checked_corpus_digest(requests: &[(&str, Vec<u8>)]) -> String {
    let mut digest = Context::new(&SHA256);
    for (label, request) in requests {
        let response = respond(tables(), request);
        let parsed: Value = serde_json::from_slice(&response).unwrap();
        assert!(parsed.get("result").is_some(), "{label}: {parsed}");
        for bytes in [request.as_slice(), response.as_slice()] {
            digest.update(&(bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
        }
    }
    let identity = hex::encode(digest.finish());
    assert_eq!(
        identity, BASELINE_DIGEST,
        "native helper corpus differs from 4d57c06"
    );
    identity
}

#[test]
fn full_rpc_transcripts_match_native_batch_baseline() {
    let requests = corpus();
    let digest = checked_corpus_digest(&requests);
    println!(
        "native baseline corpus: {digest} ({} requests)",
        requests.len()
    );
}

#[test]
#[should_panic(expected = "native helper corpus differs from 4d57c06")]
fn corpus_guard_rejects_changed_successful_responses() {
    let mut requests = corpus();
    let mut request: Value = serde_json::from_slice(&requests[0].1).unwrap();
    // A valid new ID still produces a successful RPC result, but changes the
    // frozen request/response bytes. It must fail the same guard used by timing.
    request["id"] = json!(777);
    requests[0].1 = serde_json::to_vec(&request).unwrap();
    checked_corpus_digest(&requests);
}

#[test]
#[ignore = "release-mode helper benchmark; not a proof-action benchmark"]
fn benchmark_native_rpc() {
    let requests = corpus();
    let iterations: usize = std::env::var("ZARK_HELPER_BENCH_ITERATIONS")
        .map_or(Ok(64), |v| v.parse())
        .unwrap();
    assert!((1..=10000).contains(&iterations));
    let identity = checked_corpus_digest(&requests);
    for function in [BATCH_ORACLE, GLV_ORACLE, FIXED_ORACLE] {
        let label = match function {
            BATCH_ORACLE => "batch",
            GLV_ORACLE => "glv",
            _ => "fixed",
        };
        let inputs: Vec<_> = requests.iter().filter(|(kind, _)| *kind == label).collect();
        // Warm the same varied corpus that will be timed.
        for (_, input) in &inputs {
            black_box(respond(tables(), black_box(input)));
        }
        let started = Instant::now();
        for _ in 0..iterations {
            for (_, input) in &inputs {
                black_box(respond(tables(), black_box(input)));
            }
        }
        println!(
            "{}",
            json!({"oracle":label, "requests":iterations * inputs.len(),
            "ns_per_request":started.elapsed().as_nanos() / (iterations * inputs.len()) as u128,
            "corpus_sha256":identity})
        );
    }
}
