# Signer messaging

`signer-client.mjs` is the desktop transport. It connects to the selected signer's
pinned TLS endpoint using `zark-mail/1`. The local Rust wallet encrypts peer
messages; the UI receives display fields only. Deployment settings come from the
explicit trust directory described in [the build guide](../../../docs/building.md).

The loopback `server.mjs`, HTTP client and retirement helpers are retained for
compatibility and regression tests. The current desktop does not launch that
legacy server. Its mailbox, replay and recovery tests remain part of
`sh apps/desktop/test.sh`.
