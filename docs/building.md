# Building and qualification

Supported native targets are Apple Silicon macOS 13.3+ and Linux x86-64/arm64.
The qualified Linux BB binary requires a sufficiently recent CPU (Intel Broadwell
or AMD Zen onwards on x86-64). No Windows or Intel Mac package is qualified.

## Prerequisites

Use Rust 1.95.0 (`rust-toolchain.toml`), Node.js 20+, Python 3.11+, OpenSSL and
Git. macOS needs Xcode Command Line Tools. Debian/Ubuntu desktop builds need:

```sh
sudo apt install build-essential pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libfuse2
cargo +1.95.0 install tauri-cli --version 2.12.0 --locked
```

Build the wallet with locked dependencies and neutral source paths:

```sh
python3 scripts/native_build.py -- build --release --locked --workspace --bins
cargo build --release --locked --manifest-path apps/desktop-tauri/Cargo.toml
```

`sh apps/desktop/run.sh --preview` opens a UI preview with synthetic data. For a
real wallet, first obtain a qualified tool bundle and matching deployment trust:

```sh
export ZARK_TRUSTED_RUNTIME=/absolute/deployment/trust
export ZARK_ASSET_SOURCE=/absolute/bundle/prebuilt
export ZARK_DESKTOP_BASE=/absolute/new-wallet-directory
./run-wallet.sh alice
```

Trust settings contain public certificates and pins, never signer keys or RPC
credentials. Missing settings fail before building; there is no old-server fallback.
Normal profile locations are `~/Library/Application Support/Zark` on macOS and
`$XDG_DATA_HOME/zark` (default `~/.local/share/zark`) on Linux. Use a separate base
for local tests and for each new deployment. Packaged apps select a
`deployments/<deployment identity>` subdirectory automatically, preserving wallets
from earlier deployments. An explicit `ZARK_DESKTOP_BASE` still takes precedence.

## Proving tools and suite

Use Noir 1.0.0-beta.25 at `75061fab15986eedee4e7d9104ff87dd9fa4ca10`
from https://github.com/noir-lang/noir and Barretenberg 5.2.0 at
`49a592109ec4f18d79212b43d621891aaf36f7b6` from
https://github.com/AztecProtocol/aztec-packages. Accepted native compiler/verifier
hashes are in `runtime/toolchains.json`; official Linux archive and executable
hashes are also in `apps/desktop/runtime/platform.mjs`.

Build the native witness executor from a clean pinned Noir checkout, applying
`runtime/fast-prover/witness-fast-gzip.patch`, then:

```sh
python3 /absolute/zark/scripts/native_build.py --source /absolute/noir \
  --toolchain 1.89.0 -- build --release --locked -p noir_artifact_cli --bin noir-execute
```

Linux qualification uses stock BB for proving and verification. Mac qualification
uses stock BB for verification and the separately built cap15 prover. Apply
`runtime/fast-prover/barretenberg-cap15.patch` to the pinned Aztec checkout;
configure `barretenberg/cpp` with CMake/Ninja Release, Apple Clang and the macOS
SDK, `ENABLE_PIC=ON`, `AVM=OFF`, `BB_LITE=OFF`, `MULTITHREADING=ON`,
`OMP_MULTITHREADING=OFF`, `ENABLE_PARALLEL_ALGORITHMS=OFF`, then build `bb`
with two jobs. See `runtime/fast-prover/README.md` for the pinned dependencies.
The deposit-specialization patch is retained to check its embedded key against
the suite; it is not selected by this qualification profile.

Supply the authenticated CRS (`bn254_g1.dat` and `bn254_g1_compressed.dat`), whose
hashes are enforced by the scripts, and rebuild all six roles:

```sh
python3 scripts/build-fast-prover-suite.py \
  --nargo /absolute/tools/nargo --bb /absolute/tools/bb \
  --crs /absolute/crs --output work/suite-build
```

This compiles the maintained circuit sources, derives native hints while checking
that constrained bytecode is preserved, and verifies every artifact and key
against `runtime/fast-prover/source-lock.json`. Compiler source-map labels use
`/zark`; they are serialization metadata, not filesystem dependencies.

Prepare a native tools directory containing `nargo`, `bb`, `prover`, `executor`,
`bitcoind`, `bitcoin-cli`, and the locally built `zark-wallet`, `zark-signer` and
`zark-fast-helper`. Use Bitcoin Core 30.2 for the packaged CLI. Record the exact
inputs for qualification:

```sh
python3 scripts/prepare-flow.py --suite work/suite-build/suite \
  --tools /absolute/native-tools --crs /absolute/crs --output work/qualification
```

This records binary hashes; it does not by itself qualify newly compiled tools.
Keep the resulting flow file and test wallets outside Git.

## Real tests

Ordinary Rust/JS tests do not execute real proofs or contact Bitcoin. For that:

```sh
export ZARK_REAL_FLOW_CONFIG="$PWD/work/qualification/flow.json"
cargo test --release --locked --test zark_flow_real \
  fresh_eight_owner_chain_rejects_eighth_transfer_and_exits -- --ignored --exact --nocapture
cargo test --release --locked --test zark_flow_real \
  fresh_public_native_worker_tls_alice_bob_carol_and_cooperative_exit -- --ignored --exact --nocapture
```

These use isolated regtest nodes and fresh keys, test real proofs and transitions,
and retain recovery data. Also run the origin-exit and concurrent batch cases
when changing those paths. Never substitute a participant's wallet for a fixture.

## Desktop packages

Use the same suite and fresh deployment trust on all platforms. The trust
directory must contain `deployment.json`, `deployment-receipt.json`,
`public-deployment-pins.json`, `public-services.json`, `certificate.pem` and
`public-chain-certificate.pem`. The packager verifies their agreement and the
eight-owner recovery budget. Create a separate asset inventory per platform:

```sh
python3 scripts/build-desktop.py --flow work/qualification/flow.json \
  --trust /absolute/deployment/trust --node /absolute/pinned/node \
  --node-sha256 NODE_BINARY_SHA256 --output work/desktop --admit-assets
```

The output is `Zark.app` on Mac or an AppImage on Linux. For repeat builds, omit
`--admit-assets`; the inventory must match. Build on the target OS/architecture.
The app carries Node, the native wallet, proving tools, CRS and precompiled
circuits. Signing and AppImage bundling are followed by asset hash verification.
The initial Mac bundle is ad-hoc signed. Use the distribution step below to add
Developer ID signing.

The Mac packager builds the shell in a neutral temporary directory and remaps
Rust source paths. Build the wallet, helper and witness executor through
`scripts/native_build.py` as above; the signing step rejects binaries that still
contain the builder's home path. Public Developer ID identity is retained.

For Mac distribution, sign a qualified bundle using a Developer ID Application
identity in the login Keychain:

```sh
python3 scripts/sign-macos.py --input work/desktop/Zark.app \
  --receipt work/desktop/build-receipt.json --output work/desktop-signed \
  --identity DEVELOPER_ID_CERTIFICATE_FINGERPRINT
```

This preserves Core's existing Developer ID signature, signs the other binaries
with the hardened runtime and secure timestamps, and checks executable bytes
after stripping signatures and normalizing the signature-dependent `__LINKEDIT`
memory reservation. Node receives only the JIT
entitlement. Tool hashes are admitted into a separate cache revision; earlier
wallets keep their original admitted tools and immutable configuration. Retain
the previous manifest history when producing subsequent signed releases.

Signing is not notarization. Submit the signed app to Apple's notary service,
inspect its result, staple the accepted ticket, and verify the downloaded app
with Gatekeeper before publishing. Store notarization credentials in Keychain,
never in the repository. Re-run the packaged flow and reopen an existing wallet
to check both the signed tools and compatibility.

After provisioning an isolated signer and faucet, test the finished bundle:

```sh
node scripts/check-desktop.mjs /absolute/Zark.app /absolute/new-smoke-directory
```

On Linux first extract the AppImage with `--appimage-extract` and pass its
`squashfs-root` directory. This exercises the packaged backend's claim, send and
accept with its bundled Node. Inspect the actual GUI separately, including
Receive, clipboard, file selection and graceful shutdown. A virtual X11 display
is useful coverage, but is not a physical desktop or Wayland qualification.
