# Zark

A research Bitcoin wallet for private off-chain transfers and coinswaps.
Zark combines a two-party statechain with zero-knowledge proofs and signed
Bitcoin recovery transactions. The desktop app uses Tauri on Apple Silicon
macOS and Linux x86-64/arm64.

**MutinyNet test coins only. Unaudited; mainnet is disabled.**

- Claim a sponsored deposit, then send and receive coins off-chain.
- Exchange coins through atomic swaps coordinated by the signer.
- Keep recovery material locally and withdraw to Bitcoin.
- Each coin supports **eight owners: the depositor and seven transfers**.

Download the app from [Releases](https://github.com/zerosats/zark-public/releases/tag/desktop-v0.1.0-mutinynet):
the signed and notarized Mac DMG is for Apple Silicon; Linux AppImages are
available for x86-64 and arm64. The packages include their tools and connect to
the MutinyNet demo automatically. Use **Get free test sats** to start.

Linux x86-64 needs AVX2 (Intel Broadwell or AMD Zen onward). Windows and Intel
Macs are not supported. Existing wallets must stay with their original deployment.

## Build and test

Install the pinned Rust toolchain, Node.js 20+ and Python 3.11+.

```sh
cargo build --release --locked --workspace --bins
cargo test --locked --workspace --all-targets
sh apps/desktop/test.sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```

The GUI also needs platform libraries. See [building and qualification](docs/building.md)
for Tauri, the pinned proving tools, real Bitcoin tests and desktop packages.

## Read more

- [How the protocol works and what users trust](docs/protocol.md)
- [Contributing](CONTRIBUTING.md)

The wallet lives in `src/`, shared protocol code in `crates/protocol/`, the
signer in `crates/signer/`, and proof programs in `circuits/`. The Tauri UI is
in `apps/desktop-tauri/`; `apps/desktop/` contains its shared Node runtime.
`services/` contains the Bitcoin gateway and sponsored-deposit faucet.

Zark source is distributed under the [MIT license](LICENSE). Third-party
components retain their own notices and terms.
