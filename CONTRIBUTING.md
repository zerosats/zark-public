# Contributing

Start with the [README](README.md) for the protocol overview and local checks.
Contributions use the [MIT license](LICENSE).

Keep changes focused on a named responsibility or behavior. Follow the source
organization rules in [AGENTS.md](AGENTS.md). Describe the problem, resulting
behavior, relevant invariants, and checks performed in the change description.
Do not mix a mechanical module extraction with a protocol or storage migration.

Use the pinned toolchain and locked dependencies. Test with synthetic keys and
fresh isolated homes under ignored `work/`; never use participant wallets as test
fixtures. Do not commit keys, credentials, private witnesses, databases, recovery
exports, generated proof artifacts, or local configuration.

Preserve exact request retries, one-use nonces, signed domain separation,
commit/checkpoint before response, and durable recovery before acknowledgement.
Changes to a circuit, canonical encoding, signed artifact, transaction shape,
deployment domain, or signer transition require the corresponding adversarial
and native/circuit parity checks. Do not silently migrate old protocol state.

Separate native tests, actual proof verification, Bitcoin integration, platform
qualification, and independent review in reports. Passing one does not imply
the others. Keep historical measurements labeled with their original suite and
source; update README when public guidance changes.
