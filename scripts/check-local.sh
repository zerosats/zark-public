#!/bin/sh
# Local verification only; no CI service or network access is required by default.
set -eu
audit_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$audit_root"
if command -v cargo >/dev/null 2>&1; then
    audit_cargo=$(command -v cargo)
else
    audit_cargo=
    for audit_candidate in "$HOME"/.rustup/toolchains/1.95.0-*/bin/cargo; do
        if test -x "$audit_candidate"; then audit_cargo=$audit_candidate; break; fi
    done
    if test -z "$audit_cargo"; then
        echo 'Rust 1.95.0 must be installed and cargo available on PATH.' >&2
        exit 1
    fi
fi
audit_bin=$(dirname "$audit_cargo")
PATH="$audit_bin:$PATH"
export PATH
if test -d "$audit_root/work/cargo/registry"; then
    CARGO_HOME="$audit_root/work/cargo"
    export CARGO_HOME
fi
if test -d /Library/Developer/CommandLineTools; then
    DEVELOPER_DIR=/Library/Developer/CommandLineTools
    export DEVELOPER_DIR
fi
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$audit_root/work/implementation-target}"
export CARGO_TARGET_DIR
audit_action=${1:-check}
case "$audit_action" in
    noir) cd "$audit_root/circuits/relations"; exec "$audit_root/work/tools/nargo" test ;;
    circuit-rows)
        audit_nargo=${2:?circuit-rows requires the absolute pinned nargo executable}
        audit_bb=${3:?circuit-rows requires the absolute pinned original BB executable}
        exec python3 "$audit_root/scripts/check-circuit-rows.py" --nargo "$audit_nargo" --bb "$audit_bb" ;;
    check|test|build) exec "$audit_cargo" "$audit_action" --workspace --all-targets --locked --offline ;;
    check-wallet) exec "$audit_cargo" check -p zark-wallet --lib --locked --offline ;;
    test-protocol) exec "$audit_cargo" test -p zark-protocol --all-targets --locked --offline ;;
    test-public-corpus) exec "$audit_cargo" test -p zark-protocol --release --test linux_corpus --locked --offline public_corpus_has_authenticated_exact_artifacts -- --ignored --exact --nocapture ;;
    test-real-lineage) exec "$audit_cargo" test -p zark-protocol --release --test lineage_real --locked --offline native_verifier_accepts_full_private_lineage_and_rejects_substitution -- --ignored --exact --nocapture ;;
    test-real-deposit) exec "$audit_cargo" test -p zark-protocol --release --test proof --locked --offline real_native_deposit_verification_pins_roles_and_canonical_statements -- --ignored --exact --nocapture ;;
    test-signer) exec "$audit_cargo" test -p zark-signer --all-targets --locked --offline ;;
    test-host)
        # Cargo runs this integration test from crates/signer, not the repository root.
        ZARK_TEST_SUITE=${2:?test-host requires the absolute qualified suite directory}
        ZARK_TEST_BB=${3:?test-host requires the absolute pinned BB executable}
        ZARK_TEST_CRS=${4:?test-host requires the absolute CRS directory}
        export ZARK_TEST_SUITE ZARK_TEST_BB ZARK_TEST_CRS
        exec "$audit_cargo" test -p zark-signer --test host --locked --offline listener_pins_tls_scopes_replays_and_rejects_unsupported_protocol -- --ignored --exact --nocapture --test-threads=1 ;;
    capacity-benchmark) exec "$audit_cargo" test -p zark-signer --release --lib --locked --offline engine::tests::capacity::near_limit_storage_measurements -- --ignored --exact --nocapture --test-threads=1 ;;
    test-wallet) exec "$audit_cargo" test -p zark-wallet --all-targets --locked --offline ;;
    benchmark-helper) exec "$audit_cargo" test -p zark-wallet --release --lib --locked --offline fast_helper:: -- --ignored --nocapture --test-threads=1 ;;
    test-clients) exec "$audit_cargo" test --workspace --exclude zark-signer --all-targets --locked --offline ;;
    test-real-flow) shift; exec "$audit_cargo" test -p zark-wallet --release --locked --offline --test zark_flow_real "$@" -- --ignored --exact --nocapture --test-threads=1 ;;
    test-real-prover) exec "$audit_cargo" test -p zark-wallet --release --locked --offline --test zark_prover_real actual_proof_stays_owner_local_and_resumes_only_exact_verified_output -- --ignored --exact --nocapture --test-threads=1 ;;
    test-fast-prover) "$audit_cargo" build -p zark-wallet --release --locked --offline --example malicious-fast-helper && exec "$audit_cargo" test -p zark-wallet --release --locked --offline --test zark_fast_prover_real application_prover_qualifies_six_roles_and_measures_fresh_linked_transfers -- --ignored --exact --nocapture --test-threads=1 ;;
    build-release) exec "$audit_cargo" build --workspace --release --locked --offline ;;
    clippy) exec "$audit_cargo" clippy --workspace --all-targets --locked --offline -- -D warnings ;;
    fmt) exec "$audit_cargo" fmt --all --check ;;
    format) exec "$audit_cargo" fmt --all ;;
    fetch) exec "$audit_cargo" fetch ;;
    lock) exec "$audit_cargo" generate-lockfile --offline ;;
    *) echo 'usage: check-local.sh check|check-wallet|test|test-clients|test-protocol|test-public-corpus|test-real-lineage|test-real-deposit|test-signer|test-host ABS_SUITE ABS_BB ABS_CRS|test-wallet|benchmark-helper|test-real-flow [name]|test-real-prover|test-fast-prover|capacity-benchmark|build|build-release|clippy|fmt|format|noir|circuit-rows ABS_NARGO ABS_BB|fetch|lock' >&2; exit 2 ;;
esac
