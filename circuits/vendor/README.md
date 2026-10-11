# Vendored Noir libraries

Noir package manifests and source trees are retained without source pruning.

- `poseidon`: https://github.com/noir-lang/poseidon, commit `bde183cb593145dbc297a2491057983756a0e043`; nearest ancestor tag `v0.3.0`.
- `noir-bignum`: https://github.com/noir-lang/noir-bignum, commit `afbe71a5fcbdddeaf02208d75c74beb4db56450a`; nearest ancestor tag `v0.10.0`.
- `noir_bigcurve`: https://github.com/noir-lang/noir_bigcurve, commit `a1ac8dbe3f513def855c64cdd0dbf43e2c3f2e79`; nearest ancestor tag `v0.14.0`.

Upstream licenses are retained where available. Upstream CI and development tooling are excluded.
Among included files, only `Nargo.toml` dependency paths and the local `noir_bigcurve` GLV patch differ from upstream.
The GLV patch adds seven `src/glv*.nr` files and edits `src/lib.nr` and both point-table modules.
