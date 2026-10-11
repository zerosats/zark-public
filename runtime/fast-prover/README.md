# Maintained proving runtime

The six-role v10 suite supports eight owners. `source-lock.json` authenticates
circuit source, native-hint donors, artifacts, verification keys and helper
tables. Build and qualification commands are in [the build guide](../../docs/building.md).

The witness executor uses `witness-fast-gzip.patch` at Noir commit
`75061fab15986eedee4e7d9104ff87dd9fa4ca10`. The Mac cap15 prover uses
`barretenberg-cap15.patch` at Aztec commit
`49a592109ec4f18d79212b43d621891aaf36f7b6`. Linux uses the official stock BB
prover/verifier. Both platforms use the native Rust hint helper. No IFMA or
historical comparison profile is selected here.

Pinned BB dependency revisions used by the qualified Mac build:

| Dependency | Commit |
| --- | --- |
| gtest | `b796f7d44681514f58a683a3a71ff17c94edb0c1` |
| benchmark | `7638387d2727853d970fc9420dcf95cf3e9bd112` |
| libdeflate | `96836d7d9d10e3e0d53e6edb54eb908514e336c4` |
| httplib | `5c00bbf36ba8ff47b4fb97712fc38cb2884e5b98` |
| nlohmann_json | `9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03` |
| tracy | `5d542dc09f3d9378d005092a4ad446bd405f819a` |
| msgpack-c | `c0334576ed657fb3b3c49e8e61402989fb84146d` |
| lmdb | `ddd0a773e2f44d38e4e31ec9ed81af81f4e4ccbb` |

Tool hashes are build-specific: recompiling a helper or executor can change its
binary hash. A new qualified flow must record that exact binary. Source and
circuit verification must never be bypassed to accept a mismatching build.
