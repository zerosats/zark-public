# Browser wallet transport

The signer can expose ordinary HTTPS alongside its existing native TLS socket.
Both listeners use the same Engine, durable database/checkpoint, admission
counters, and signing/continuation/recovery/mail queues. Browser traffic does not
require a local gateway, native helper, extension or installed certificate.
The chain facade in `services/public_gateway.py` also supports opt-in browser
origins. Keys, witnesses, encrypted wallet storage and proving stay in the wallet.

This is an additive transport for the existing deployment. Do not regenerate
deployment keys, circuits, admissions, wallet files or pending operations to
enable it. For the current MutinyNet wallet, retain the authenticated deployment
`d9b52c43931931f79a97992ab40ed3b259afc724716a5d8df06dae5210e9ac02`, suite
`7073e09320aca6c8f1d10afe3e9618317b7d2be4fcadf25d80acdc3fba056391`, and eight-owner
schedule. The authenticated deployment files remain authoritative.

## Signer configuration and TLS

Add the following member to the existing trusted v10 hosted configuration.
These domains and paths are examples; provision operator-owned domains first.

```json
{
  "browser": {
    "listen": "0.0.0.0:7449",
    "certificate": "/srv/zark/browser-tls/fullchain.pem",
    "private_key": "/srv/zark/browser-tls/private.key",
    "allowed_origins": ["https://wallet.example.org"],
    "allowed_hosts": ["signer.example.org"]
  }
}
```

Keep the existing native `listen`, `certificate` and `private_key`. The new
listener requires its own browser-trusted certificate covering the public
hostname, including intermediate certificates. The key must be a private regular
file with mode 0600, in the signer's owned mode-0700 directory; copy renewed
certificate/key material into that directory rather than pointing at ACME
symlinks. Run the existing `zark-signer --config /absolute/signer.json
--check-config` before restarting the service. TLS material and listener addresses
are loaded at startup; changing them requires restart. Origin/host policy and
admission settings are reread on requests. Setting `browser` to `null` immediately
denies new HTTPS requests; existing queued operations can still complete.

Map public TCP port 443 to this HTTPS listener, or listen on 443 with the
appropriate service permissions. An alternate public port must appear in both
the wallet endpoint URL and `allowed_hosts`, e.g. `signer.example.org:7449`.
DNS or Cloudflare pointing at the native custom-ALPN socket does not translate
its protocol. Publish the new HTTPS listener explicitly. It negotiates TLS 1.3
and HTTP/1.1; an HTTP/2-capable edge must use HTTP/1.1 upstream.

Browser `fetch` authenticates the public domain through browser PKI. JavaScript
cannot enforce the desktop's custom TLS leaf pin. The browser endpoint is an
explicit additional trust binding in the wallet's operator-authenticated endpoint
configuration; do not claim that its certificate is the existing native pin.
Desktop clients continue to authenticate the original certificate and ALPN.
Protocol session/owner signatures, deployment identity and circuit checks still
apply to both transports. CORS is a browser access policy, not proof of ownership
or authentication against non-browser clients.

A TLS-terminating reverse proxy (including a CDN) can see protocol requests,
proofs and mailbox bearer tokens. It becomes part of the transport trust boundary.
Use a controlled proxy, no body/access logging or caching, no automatic upstream
retries, and verified TLS to the HTTPS listener. Do not expose a plaintext signer
upstream. Preserve `Host` and `Origin`, buffer bodies with a fixed Content-Length,
and do not compress request bodies. Forwarded IP headers are deliberately ignored:
without TCP source preservation all proxy users share one existing per-peer
budget, which is stricter, not a way to bypass admission. A TCP forwarding setup
can preserve end-to-end browser TLS; source addresses still depend on its network
configuration.

`allowed_origins` contains exact serialized origins: scheme, lowercase hostname
and optional nondefault port, without a path or trailing slash. HTTPS origins are
accepted; explicitly listed `http://localhost:PORT` and `http://127.0.0.1:PORT`
are allowed for development only. Wildcards, `null`, embedded credentials,
nonlocal HTTP, and default-port spellings such as `:443` are rejected. IPv6
HTTP authorities are currently unsupported; the listen socket may still be IPv6.

## HTTPS API

Every request to the signer HTTPS listener requires a configured `Host` and
`Origin`, including monitoring requests. Same-origin browser GET `/health` may
omit Origin when `Sec-Fetch-Site: same-origin` is present and the derived HTTPS
origin is explicitly allowed. Use `credentials: "omit"` and JSON POST
bodies. Tokens are carried in the existing JSON envelope, never cookies, URLs or
the HTTP Authorization header. Responses include `Cache-Control: no-store` and
the exact allowed `Access-Control-Allow-Origin`; no credentialed CORS is enabled.
OPTIONS is supported on these same paths, with the route's GET or POST method
and only `Content-Type` as an explicitly requested header. Preflight cache age is
60 seconds. Unknown origins/hosts receive HTTP 403 without an allow-origin header.
See the [browser CORS documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
for how fetch preflight and response access work.

| HTTP path | Method | Request | Response |
| --- | --- | --- | --- |
| `/health` | GET | No body | `{"service":"zark-browser","version":1,"protocol_version":10}` |
| `/v1/signer` | POST | Existing native outer envelope | Existing native signer response |
| `/v1/mail` | POST | Existing native mail envelope | Existing native mail response |

Signer request, without any extra newline:

```json
{"method":"zark_request","request":"<exact saved canonical v10 Request JSON>"}
```

The `request` value is the original string emitted by the core. Do not parse and
reserialize it. The host uses the same canonical decoder and signature checks as
native transport. The optional existing `credential` string is supported for
privately admitted clients; a hosted wallet must not embed a shared operator
credential in its public JS. Self-service starts require the existing
`public_access` hosting policy. Continuations/recovery retain their existing
frozen-session authorization even after hosting credential expiry/revocation.

Successful signer response:

```json
{"ok":true,"result":{"version":10,"response":{}}}
```

`response` is the unchanged Engine response for that command. Rejections use the
existing envelope, e.g.:

```json
{"ok":false,"error":{"code":"overloaded","retryable":true,"message":"Private request was not completed; retain the exact request."}}
```

Signer/mail protocol successes and failures both use HTTP 200, so the wallet's
existing protocol decoder sees the same result. HTTP boundary failures use
400 (malformed headers/body, missing length or size violation), 403 (origin/host),
404 (path), 405 (method) or 415 (non-JSON). They use a safe `ok:false` envelope and
never echo internal errors, credentials or submitted bodies. Header/framing
failures before origin validation cannot include CORS headers.

Limits are byte counts, not character counts:

| Boundary | Limit/deadline |
| --- | --- |
| HTTPS headers | 16,384 bytes total, at most 64 distinct headers |
| Signer outer POST body | 271,360 bytes |
| Canonical inner signed request | 135,168 bytes |
| Signer response JSON | Less than 135,168 bytes |
| Mail POST body | 3,000,000 bytes |
| Mail response JSON | Less than 3,000,000 bytes |
| TLS + headers + upload + ingress queue | 8 seconds from accept |
| Signing queue + execution | 90 seconds from accept |
| Mail queue + start of execution | 8 seconds from accept |
| Response write | 5 seconds |

HTTPS uses one request per connection and `Connection: close`. Chunked/compressed
bodies, duplicate headers, `Expect`, cookies and HTTP authorization are rejected.
Browser fetch with a finite string body supplies Content-Length automatically;
do not use streaming uploads. HTTPS has a bounded ingress pool using the configured
`network_workers` and `queue_capacity`; it cannot occupy the native ingress pool.
Its work then shares the original queues and admission counters. Ordinary proof
traffic cannot use the dedicated continuation/recovery queues or mail worker.

## Mail authentication and recovery

POST `/v1/mail` wraps the original mailbox operation, e.g.:

```json
{"version":1,"method":"POST","path":"/v1/mailboxes","body":{"receiveAddress":"<address>","readTokenHash":"<sha256 of token UTF-8>","ttlMs":604800000,"signature":"<claim-key registration signature>"}}
```

The browser must save its invitation/address and random 32-byte token (lowercase
hex) before registration. The claim-key signature covers the existing
domain-separated address/token-hash/TTL registration digest. Repeating identical
registration returns the saved registration; it does not replace its token.
Successful response is `{"ok":true,"result":{"addressHash":"...",
"createdAt":0,"expiresAt":0}}` with actual stored timestamps.

All remaining operations also use HTTP POST `/v1/mail`; `method` and `path` below
are fields in that JSON envelope:

| Operation | Envelope method/path | Body / authentication |
| --- | --- | --- |
| Health | `GET /health` | `body:null` |
| Deliver | `POST /v1/mailboxes/<addressHash>/messages` | `body:{id,ciphertext,ttlMs?}`; no bearer |
| Poll | `GET /v1/mailboxes/<addressHash>/messages` | `body:null`, `bearer:<saved read token>` |
| Acknowledge | `DELETE /v1/mailboxes/<addressHash>/messages/<id>` | `body:null`, same bearer |

Delivery only accepts the existing bounded ciphertext format, opaque delivery
ID and optional TTL. Plaintext message kinds, witnesses and local file paths
are not part of this API. IDs and address hashes are lowercase 32-byte hex.
Poll returns `{"ok":true,"result":{"messages":[...]}}` with up to 32 existing
encrypted frames, bounded by the response limit. Ack returns
`{"ok":true,"result":{"acknowledged":true}}` and is idempotent. The original
offer-board operations also remain available through the same mail envelope;
their existing token checks and validation are unchanged.

Persist the exact encrypted ID/ciphertext before delivery. An identical delivery
retry reports `message_replayed`; changed content under the same ID reports
`message_conflict`. The browser's existing mailbox adapter must retain its
replay/confirmation checks. Save received frames and recovery state durably in
the browser before acknowledging; the service cannot establish whether client
storage succeeded. Never acknowledge merely because fetch returned a frame.
Mailbox mutations still commit through the original atomic durable write before
any transport response. Storage faults retain the existing fail-closed behavior.

Timeouts, disconnects, aborted fetches, CORS errors or proxy errors can leave an
unknown outcome. Preserve the wallet and retry/recover using the exact saved
request, operation, nonce and encrypted frame. Do not regenerate them or infer
noncommit from a missing HTTP response. `overloaded` and `timeout` are retryable
signer codes; `retryable` only permits the existing exact retry/recovery flow.
`invalid_request`, `unauthorized`, storage faults and mailbox-specific failures
must remain actionable; do not turn them into apparent success.

## Chain HTTPS and wallet wiring

The chain service already implements POST `/rpc`. Start it with repeated
`--allowed-origin https://wallet.example.org --allowed-host chain.example.org`
options to enable browser access. With no origins configured, native clients
continue to work and browser-origin requests are denied. GET `/health` exposes
`X-Zark-Observation: 1` through CORS; GET `/assets/<listed public file>` also
supports the configured origins. No browser faucet access is enabled.

Keep the desktop's chain certificate/pin intact. A separate public HTTPS reverse
proxy can reach the original HTTPS chain service with verified upstream TLS,
using its existing `chain.internal` server name and authenticated certificate as
the trust anchor. For nginx, the relevant upstream settings are
`proxy_ssl_verify on`, `proxy_ssl_server_name on`,
`proxy_ssl_name chain.internal`, and `proxy_ssl_trusted_certificate` pointing to
the authenticated current chain certificate; these directives are described in
the [nginx proxy documentation](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify).
Preserve the public Host and
Origin headers. Set `proxy_next_upstream off`; disable caching/logging and use
a request limit no greater than 16 MiB. Do not replace the native chain certificate
with the public certificate. The existing trusted-loopback-proxy mode is also an
operator-only option on the same host; it is not an end-user wallet gateway.
The public proxy's TLS termination has the same explicit trust implications
described above. Provision a public domain/certificate for it as well.

The chain RPC body uses the existing facade format:

```json
{"jsonrpc":"2.0","id":"browser-wallet","method":"gettxout","params":["<txid>",0,true]}
```

Responses remain `{"result":...,"error":null,"id":...}`; preserve RPC failures
as failures, including HTTP errors. The facade forwards only its existing limited
method set: `getblockchaininfo`, `getblockhash`, `getrawtransaction`, `gettxout`,
`getmempoolentry`, `testmempoolaccept`, `sendrawtransaction`,
`decoderawtransaction`, and the bounded read-only `zark_observe`. The wallet only
needs its existing read/check subset for receiving/transferring. Requests are
bounded to 16 MiB, responses to 32 MiB, observation evidence to 4,000,000 bytes;
body reads have an 8-second absolute deadline, Core calls 10-second timeouts,
and observation collection an 8-second total budget. Existing connection and
observation concurrency bounds remain. Cookies, HTTP authorization, compression
and chunking are rejected for browser requests. Core credentials stay server-side.

In `zark-web-wallet/src/demo/transport.ts` replace `/api/preview/signer` and
`/api/preview/mail` with configured absolute HTTPS `/v1/signer` and `/v1/mail`
URLs. Send the core's string payload unchanged with `Content-Type:
application/json`, `credentials:"omit"`, `cache:"no-store"`, and a client timeout
longer than the service deadline (the current 190-second timeout is sufficient).
Keep the existing mailbox reply validator and persisted exact-request retry flow.

Replace `/api/preview/chain` with direct POST to the chain `/rpc` endpoint. Convert
the core's `{method,args}` using the current `server/preview-gateway.ts`
`chainParams` rules in the browser: numeric heights/output indexes, boolean
verbosity/mempool flags, the JSON transaction array for `testmempoolaccept`, and
the unchanged five string parameters for `zark_observe`. Check HTTP status and
RPC `error`, then return JSON for `result` to the core. Discover observation
support through GET `/health`; only advertise `zark_observation_version:1` on
`getblockchaininfo` when the exposed header is exactly `1`. Preserve the core's
tip fences, fresh mempool-inclusive reads and complete evidence checks.

Replace `/api/preview/status` with browser-side authenticated asset checks and
signer/mail health checks. Host the already authenticated public assets with
the web app or use the chain's listed `/assets/` route, retaining every digest
check. The wallet app still needs COOP `same-origin` and COEP `require-corp`
headers for its existing SharedArrayBuffer/WASM proving workers, and CSP
`connect-src` must allow the new HTTPS origins. Publish endpoint URLs as
authenticated configuration for the existing deployment, rather than changing
deployment identity or copying a native leaf-pin claim onto browser TLS.

## Validation and activation

Run `sh scripts/check-local.sh test-signer`, `sh scripts/check-local.sh clippy`,
`sh scripts/check-local.sh fmt`, `sh apps/desktop/test.sh`, and
`python3 -m unittest discover -s services -p 'test_*.py'`.
The normal HTTPS regressions use ephemeral TLS trust roots and synthetic stores;
the durable Engine test uses the repository's explicit test-only relation oracle.
They test canonical authentication, exact replay/restart, origin/host policy,
malformed HTTP, admission/lane isolation, mailbox possession/replay/ack and chain
evidence. They do not qualify live proofs, Bitcoin spends or production TLS.

An optional real Chromium fetch check uses an installed Playwright and Chrome:

```sh
export ZARK_TEST_NODE=/absolute/node
export ZARK_TEST_PLAYWRIGHT=/absolute/node_modules/playwright/index.mjs
# Optional: export ZARK_TEST_CHROME=/absolute/chrome
sh scripts/check-local.sh test-browser
```

It trusts only the ephemeral test certificate's SPKI in an isolated browser
process and exercises actual HTTPS fetch/preflight, mailbox health and origin
denial. Production wallet fetch must use normal browser PKI with no TLS bypass.

Activation still requires operator-owned domains, browser-trusted certificates,
the updated service binary/configuration, the chain origin policy/public endpoint,
and the wallet's transport wiring above. Deploy/restart under the operator's
normal controls, preserve the database/checkpoint/mail store and pending wallets,
then check the configured wallet origin in a real browser. Qualify live transfers
and new-suite proving timings separately with authorized fixtures; ordinary
transport tests do not spend live coins or perform that qualification.
