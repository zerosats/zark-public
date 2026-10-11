//! Test-only dishonest witness-hint helper for the explicit real-prover
//! qualification (tests/zark_fast_prover_real.rs). It answers exactly like
//! zark-fast-helper except that the low bit of the first transcript limb of
//! one oracle is flipped. The oracle is chosen by this executable's file name,
//! containing `batch`, `glv` or `fixed`, because the runtime passes its helper no
//! configuration. The circuits must reject every proof attempted with it.
use serde_json::Value;
use std::path::Path;
use zark_wallet::fast_helper::{respond, run};

const GLV_ORACLE: &str = "zark_glv_hint_v1";
const BATCH_GLV_ORACLE: &str = "zark_glv_batch_hint_v1";
const FIXED_ORACLE: &str = "zark_fixed_generator_hint_v1";

fn main() {
    let name = std::env::args_os()
        .next()
        .and_then(|path| Some(Path::new(&path).file_name()?.to_str()?.to_owned()))
        .unwrap_or_default();
    let oracle = if name.contains("batch") {
        BATCH_GLV_ORACLE
    } else if name.contains("fixed") {
        FIXED_ORACLE
    } else if name.contains("glv") {
        GLV_ORACLE
    } else {
        std::process::exit(2)
    };
    run(move |tables, raw| {
        let honest = respond(tables, raw);
        corrupt(oracle, raw, &honest).unwrap_or(honest)
    })
}

/// The honest response with one limb changed, for successful calls to `oracle`.
fn corrupt(oracle: &str, raw: &[u8], honest: &[u8]) -> Option<Vec<u8>> {
    let request: Value = serde_json::from_slice(raw).ok()?;
    if request["params"][0]["function"] != oracle {
        return None;
    }
    let mut response: Value = serde_json::from_slice(honest).ok()?;
    let values = response.get_mut("result")?.get_mut("values")?;
    // Both GLV oracles return [selected, transcript]; the fixed-base oracle
    // returns only [transcript]. Mutate the proof-bound transcript in either
    // shape instead of accidentally changing the batch oracle's selected row.
    let transcript = values.get_mut(usize::from(oracle != FIXED_ORACLE))?;
    let limb = transcript.get_mut(0)?;
    let flipped = u128::from_str_radix(limb.as_str()?, 16).ok()? ^ 1;
    *limb = Value::String(format!("{flipped:064x}"));
    serde_json::to_vec(&response).ok()
}
