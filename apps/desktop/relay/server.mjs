/**
 * Local-development mailbox relay and public swap board. This server verifies
 * transport credentials only. Payloads must contain existing encrypted offers
 * or public coordination metadata; recipient wallets verify every offer.
 */
import http from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, lstat, chmod, open, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const DEFAULT_LIMITS = Object.freeze({
  // Rust envelopes are <=2,000,000 bytes; base64 plus public JSON fits in 3 MB.
  maxMessageBytes: 3_000_000,
  maxStateBytes: 32 * 1024 * 1024,
  maxMailboxes: 1024,
  maxMessagesPerMailbox: 32,
  maxAcceptedMessagesPerMailbox: 256,
  maxOffers: 1024,
  mailboxTtlMs: 7 * 24 * 60 * 60 * 1000,
  messageTtlMs: 24 * 60 * 60 * 1000,
  offerTtlMs: 24 * 60 * 60 * 1000,
});

const HASH = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const TOKEN = /^[a-f0-9]{64}$/;
const ADDRESS = /^tzark1[023456789acdefghjklmnpqrstuvwxyz]{164}$/;
const MAX_AMOUNT = 2_100_000_000_000_000;

class HttpError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
const fail = (status, code, message) => { throw new HttpError(status, code, message); };
const assert = (ok, message) => { if (!ok) fail(400, 'invalid_request', message); };
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function object(value, allowed, required = allowed) {
  assert(value !== null && typeof value === 'object' && !Array.isArray(value), 'Expected a JSON object');
  assert(Object.keys(value).every((key) => allowed.includes(key)), 'Unknown field');
  assert(required.every((key) => Object.hasOwn(value, key)), 'Missing required field');
}
function hash(value) { assert(typeof value === 'string' && HASH.test(value), 'Invalid SHA-256 digest'); return value; }
function address(value) {
  assert(typeof value === 'string' && ADDRESS.test(value), 'Expected a canonical test-network receiving address');
  return value;
}
function lifetime(value, max) {
  value ??= max;
  assert(Number.isSafeInteger(value) && value > 0 && value <= max, 'Invalid lifetime');
  return value;
}
function authorized(req, expectedHash) {
  const value = req.headers.authorization;
  if (typeof value !== 'string' || !value.startsWith('Bearer ')) return false;
  const token = value.slice(7);
  if (!TOKEN.test(token) || !HASH.test(expectedHash ?? '')) return false;
  return timingSafeEqual(Buffer.from(sha256(token), 'hex'), Buffer.from(expectedHash, 'hex'));
}
function requireAuthorization(req, expectedHash) {
  if (!authorized(req, expectedHash)) fail(401, 'unauthorized', 'A valid bearer token is required');
}
function mailboxAt(state, key, now) {
  const mailbox = state.mailboxes[key];
  if (!mailbox) fail(404, 'mailbox_not_found', 'Mailbox not found');
  if (mailbox.expiresAt <= now) fail(410, 'mailbox_expired', 'Mailbox expired; create a fresh receiving address');
  return mailbox;
}
function offerAt(state, id, now) {
  const offer = Object.hasOwn(state.offers, id) ? state.offers[id] : undefined;
  if (!offer) fail(404, 'offer_not_found', 'Offer not found');
  if (offer.expiresAt <= now) fail(410, 'offer_expired', 'Offer expired');
  return offer;
}
function publicOffer(offer, privateDetails = false) {
  const result = {
    id: offer.id, amountSat: offer.amountSat, receiveAddress: offer.receiveAddress, swapVersion: offer.swapVersion ?? 1,
    addressHash: offer.addressHash, createdAt: offer.createdAt, expiresAt: offer.expiresAt,
    status: offer.status,
  };
  if (privateDetails && offer.claim) {
    result.claim = { receiveAddress: offer.claim.receiveAddress, addressHash: offer.claim.addressHash, claimedAt: offer.claim.claimedAt };
  }
  return result;
}
function prune(state, now) {
  let changed = false;
  // Retain bounded mailbox registrations and seen IDs for the full mailbox life.
  // Expired registrations become tombstones: their read token cannot be replaced.
  for (const mailbox of Object.values(state.mailboxes)) {
    for (const [id, message] of Object.entries(mailbox.messages)) {
      if (message.expiresAt <= now || mailbox.expiresAt <= now) { delete mailbox.messages[id]; changed = true; }
    }
    if (mailbox.expiresAt <= now && mailbox.seen.length) { mailbox.seen = []; changed = true; }
  }
  for (const [id, offer] of Object.entries(state.offers)) {
    if (offer.expiresAt <= now) { delete state.offers[id]; changed = true; }
  }
  return changed;
}
function validateState(state, limits) {
  object(state, ['version', 'mailboxes', 'offers']);
  assert(state.version === 1, 'Unsupported relay state');
  assert(state.mailboxes && typeof state.mailboxes === 'object' && !Array.isArray(state.mailboxes), 'Invalid mailboxes');
  assert(state.offers && typeof state.offers === 'object' && !Array.isArray(state.offers), 'Invalid offers');
  assert(Object.keys(state.mailboxes).length <= limits.maxMailboxes, 'Too many persisted mailboxes');
  assert(Object.keys(state.offers).length <= limits.maxOffers, 'Too many persisted offers');
  for (const [key, box] of Object.entries(state.mailboxes)) {
    hash(key); object(box, ['readTokenHash', 'createdAt', 'expiresAt', 'messages', 'seen']); hash(box.readTokenHash);
    assert(Number.isSafeInteger(box.createdAt) && Number.isSafeInteger(box.expiresAt) && box.expiresAt > box.createdAt, 'Invalid mailbox timestamps');
    assert(box.messages && typeof box.messages === 'object' && !Array.isArray(box.messages), 'Invalid persisted messages');
    assert(Array.isArray(box.seen) && box.seen.length <= limits.maxAcceptedMessagesPerMailbox && box.seen.every((record) => record && typeof record.id === 'string' && ID.test(record.id) && typeof record.digest === 'string' && HASH.test(record.digest)), 'Invalid replay records');
    assert(new Set(box.seen.map(record => record.id)).size === box.seen.length, 'Duplicate replay records');
    assert(Object.keys(box.messages).length <= limits.maxMessagesPerMailbox, 'Too many persisted messages');
    for (const [id, message] of Object.entries(box.messages)) {
      object(message, ['id', 'kind', 'payload', 'createdAt', 'expiresAt']);
      assert(message.id === id && box.seen.some(record => record.id === id && record.digest === sha256(JSON.stringify({ kind: message.kind, payload: message.payload }))), 'Invalid message identity');
      assert(typeof message.kind === 'string' && /^[a-z][a-z0-9_-]{0,63}$/.test(message.kind), 'Invalid message kind');
      assert(Number.isSafeInteger(message.createdAt) && Number.isSafeInteger(message.expiresAt) && message.expiresAt > message.createdAt && message.expiresAt <= box.expiresAt, 'Invalid message timestamps');
      assert(Buffer.byteLength(JSON.stringify(message.payload)) <= limits.maxMessageBytes, 'Persisted message too large');
    }
  }
  for (const [id, offer] of Object.entries(state.offers)) {
    object(offer, ['id', 'amountSat', 'receiveAddress', 'addressHash', 'createdAt', 'expiresAt', 'ownerTokenHash', 'status', 'claim', 'swapVersion'], ['id', 'amountSat', 'receiveAddress', 'addressHash', 'createdAt', 'expiresAt', 'ownerTokenHash', 'status']);
    assert(ID.test(id) && id === offer.id, 'Invalid offer identity');
    address(offer.receiveAddress); hash(offer.addressHash); hash(offer.ownerTokenHash);
    assert(sha256(offer.receiveAddress) === offer.addressHash && Object.hasOwn(state.mailboxes, offer.addressHash), 'Invalid offer mailbox');
    assert([1, 2].includes(offer.swapVersion ?? 1), 'Invalid swap version');
    assert(Number.isSafeInteger(offer.amountSat) && offer.amountSat > 0 && offer.amountSat <= MAX_AMOUNT, 'Invalid amount');
    assert(Number.isSafeInteger(offer.createdAt) && Number.isSafeInteger(offer.expiresAt) && offer.expiresAt > offer.createdAt, 'Invalid offer timestamps');
    assert(['open', 'claimed', 'cancelled'].includes(offer.status), 'Invalid offer status');
    assert((offer.status === 'claimed') === Object.hasOwn(offer, 'claim'), 'Invalid offer claim state');
    if (offer.claim) {
      object(offer.claim, ['receiveAddress', 'addressHash', 'claimTokenHash', 'claimedAt']);
      address(offer.claim.receiveAddress); hash(offer.claim.addressHash); hash(offer.claim.claimTokenHash);
      assert(sha256(offer.claim.receiveAddress) === offer.claim.addressHash && Object.hasOwn(state.mailboxes, offer.claim.addressHash), 'Invalid claim mailbox');
      assert(Number.isSafeInteger(offer.claim.claimedAt) && offer.claim.claimedAt >= offer.createdAt && offer.claim.claimedAt < offer.expiresAt, 'Invalid claim timestamp');
    }
  }
}

async function readJson(req, maxBytes) {
  if (!/^application\/json(?:\s*;.*)?$/i.test(req.headers['content-type'] ?? '')) fail(415, 'unsupported_media_type', 'Use application/json');
  const length = req.headers['content-length'];
  if (length && (!/^\d+$/.test(length) || Number(length) > maxBytes)) fail(413, 'body_too_large', 'Request exceeds byte limit');
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) fail(413, 'body_too_large', 'Request exceeds byte limit');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { fail(400, 'invalid_json', 'Invalid JSON'); }
}
function sendJson(res, status, result) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'", 'Connection': 'close' });
  res.end(JSON.stringify(result));
}

export async function createRelayServer({ stateDir, limits: overrides = {}, clock = Date.now } = {}) {
  if (!stateDir) throw new Error('A relay stateDir is required');
  const limits = { ...DEFAULT_LIMITS, ...overrides };
  if (Object.keys(overrides).some((key) => !Object.hasOwn(DEFAULT_LIMITS, key)) || Object.values(limits).some((n) => !Number.isSafeInteger(n) || n <= 0)) throw new Error('Invalid relay limits');
  stateDir = path.resolve(stateDir);
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const directory = await lstat(stateDir);
  if (!directory.isDirectory() || directory.isSymbolicLink()) throw new Error('Relay state must be a real directory');
  await chmod(stateDir, 0o700);
  const lockPath = path.join(stateDir, 'relay.lock');
  let lock;
  try { lock = await open(lockPath, 'wx', 0o600); }
  catch (error) {
    if (error.code === 'EEXIST') throw new Error('Relay state is locked. Stop the other relay; after a crash, verify it is stopped before removing relay.lock.');
    throw error;
  }
  await lock.writeFile(`${process.pid}\n`);
  const statePath = path.join(stateDir, 'relay-state.json');
  let state = { version: 1, mailboxes: {}, offers: {} };
  async function persist(next) {
    const encoded = JSON.stringify(next);
    if (Buffer.byteLength(encoded) > limits.maxStateBytes) fail(507, 'storage_quota', 'Relay storage quota reached');
    const temporary = path.join(stateDir, `.relay-${randomBytes(16).toString('hex')}.tmp`);
    let handle;
    try {
      handle = await open(temporary, 'wx', 0o600);
      await handle.writeFile(encoded); await handle.sync(); await handle.close(); handle = undefined;
      await rename(temporary, statePath);
      const dir = await open(stateDir, constants.O_RDONLY);
      try { await dir.sync(); } finally { await dir.close(); }
    } finally { if (handle) await handle.close(); await unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; }); }
  }
  try {
    let handle;
    try {
      handle = await open(statePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > limits.maxStateBytes || (stat.mode & 0o077) !== 0 || (process.getuid && stat.uid !== process.getuid())) throw new Error('Invalid relay state file or permissions');
      state = JSON.parse(await handle.readFile('utf8')); validateState(state, limits);
    } catch (error) { if (error.code !== 'ENOENT') throw error; await persist(state); }
    finally { await handle?.close(); }
  } catch (error) { await lock.close(); await unlink(lockPath); throw error; }

  let queue = Promise.resolve();
  let storageFault = false;
  function transaction(operation) {
    const result = queue.then(async () => {
      if (storageFault) fail(503, 'storage_fault', 'Restart the relay after checking its private state directory');
      const next = structuredClone(state); const now = clock();
      const pruned = prune(next, now);
      const response = operation(next, now);
      if (response.changed || pruned) {
        try { await persist(next); state = next; }
        catch (error) {
          // A rename can succeed before fsync fails. Do not continue serving an
          // in-memory history that might differ from the durable state.
          if (!(error instanceof HttpError)) storageFault = true;
          throw error;
        }
      }
      return response;
    });
    queue = result.catch(() => {});
    return result;
  }

  const server = http.createServer({ maxHeaderSize: 8192 }, async (req, res) => {
    try {
      // A native desktop backend talks to this service. Browser requests are
      // deliberately unsupported, including same-origin JSON writes.
      if (req.headers.origin || (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'none')) fail(403, 'browser_request_denied', 'Use the native desktop relay client');
      const host = req.headers.host ?? '';
      if (!/^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?$/.test(host)) fail(403, 'invalid_host', 'A loopback Host header is required');
      if (!req.url || !req.url.startsWith('/') || req.url.includes('?') || req.url.includes('%')) fail(404, 'not_found', 'Route not found');
      const parts = req.url.split('/').filter(Boolean);
      if (req.method === 'GET' && req.url === '/health') { sendJson(res, 200, { ok: true, service: 'zark-local-relay', version: 1 }); return; }
      const needsBody = req.method === 'POST';
      const body = needsBody ? await readJson(req, limits.maxMessageBytes + 8192) : undefined;
      const response = await transaction((next, now) => {
        if (req.method === 'POST' && req.url === '/v1/mailboxes') {
          object(body, ['addressHash', 'readTokenHash', 'ttlMs'], ['addressHash', 'readTokenHash']);
          const key = hash(body.addressHash); hash(body.readTokenHash);
          if (Object.hasOwn(next.mailboxes, key)) {
            const existing = next.mailboxes[key];
            if (existing.readTokenHash !== body.readTokenHash) fail(409, 'mailbox_exists', 'Mailbox registration cannot be replaced');
            mailboxAt(next, key, now);
            if (body.ttlMs !== undefined) lifetime(body.ttlMs, limits.mailboxTtlMs);
            return { status: 200, body: { addressHash: key, createdAt: existing.createdAt, expiresAt: existing.expiresAt } };
          }
          if (Object.keys(next.mailboxes).length >= limits.maxMailboxes) fail(429, 'mailbox_quota', 'Mailbox registration quota reached');
          const expiresAt = now + lifetime(body.ttlMs, limits.mailboxTtlMs);
          next.mailboxes[key] = { readTokenHash: body.readTokenHash, createdAt: now, expiresAt, messages: {}, seen: [] };
          return { status: 201, body: { addressHash: key, createdAt: now, expiresAt }, changed: true };
        }
        if (parts.length >= 4 && parts[0] === 'v1' && parts[1] === 'mailboxes' && parts[3] === 'messages') {
          const key = hash(parts[2]); const box = mailboxAt(next, key, now);
          if (parts.length === 4 && req.method === 'POST') {
            object(body, ['id', 'kind', 'payload', 'ttlMs'], ['id', 'kind', 'payload']);
            assert(typeof body.id === 'string' && ID.test(body.id), 'Invalid message ID');
            assert(typeof body.kind === 'string' && /^[a-z][a-z0-9_-]{0,63}$/.test(body.kind), 'Invalid message kind');
            assert(body.payload !== null && typeof body.payload === 'object' && !Array.isArray(body.payload), 'Message payload must be a JSON object');
            if (Buffer.byteLength(JSON.stringify(body.payload)) > limits.maxMessageBytes) fail(413, 'payload_too_large', 'Message payload exceeds byte limit');
            const messageDigest = sha256(JSON.stringify({ kind: body.kind, payload: body.payload }));
            const previous = box.seen.find(record => record.id === body.id);
            if (previous) {
              if (previous.digest !== messageDigest) fail(409, 'message_conflict', 'Message ID already belongs to different content');
              fail(409, 'message_replayed', 'Identical message has already been accepted');
            }
            if (Object.keys(box.messages).length >= limits.maxMessagesPerMailbox || box.seen.length >= limits.maxAcceptedMessagesPerMailbox) fail(429, 'message_quota', 'Mailbox message quota reached');
            const expiresAt = Math.min(box.expiresAt, now + lifetime(body.ttlMs, limits.messageTtlMs));
            Object.defineProperty(box.messages, body.id, { value: { id: body.id, kind: body.kind, payload: body.payload, createdAt: now, expiresAt }, enumerable: true, configurable: true, writable: true }); box.seen.push({ id: body.id, digest: messageDigest });
            return { status: 201, body: { id: body.id, createdAt: now, expiresAt }, changed: true };
          }
          if (parts.length === 4 && req.method === 'GET') {
            requireAuthorization(req, box.readTokenHash);
            return { status: 200, body: { messages: Object.values(box.messages).sort((a, b) => a.createdAt - b.createdAt) } };
          }
          if (parts.length === 5 && req.method === 'DELETE') {
            requireAuthorization(req, box.readTokenHash); assert(ID.test(parts[4]), 'Invalid message ID');
            const deleted = Object.hasOwn(box.messages, parts[4]); delete box.messages[parts[4]];
            return { status: 200, body: { acknowledged: true }, changed: deleted };
          }
        }
        if (req.url === '/v1/offers' && req.method === 'GET') {
          return { status: 200, body: { offers: Object.values(next.offers).filter((offer) => offer.status === 'open').map((offer) => publicOffer(offer)).sort((a, b) => b.createdAt - a.createdAt) } };
        }
        if (req.url === '/v1/offers' && req.method === 'POST') {
          object(body, ['amountSat', 'receiveAddress', 'addressHash', 'ownerTokenHash', 'ttlMs', 'swapVersion'], ['amountSat', 'receiveAddress', 'addressHash', 'ownerTokenHash']);
          address(body.receiveAddress); hash(body.addressHash); hash(body.ownerTokenHash);
          assert(sha256(body.receiveAddress) === body.addressHash, 'Receiving address does not match mailbox');
          assert([1, 2].includes(body.swapVersion ?? 1), 'Invalid swap version');
          assert(Number.isSafeInteger(body.amountSat) && body.amountSat > 0 && body.amountSat <= MAX_AMOUNT, 'Amount must be a positive integer number of satoshis');
          const box = mailboxAt(next, body.addressHash, now); requireAuthorization(req, box.readTokenHash);
          const prior = Object.values(next.offers).find((offer) => offer.ownerTokenHash === body.ownerTokenHash);
          if (prior) {
            if (prior.addressHash !== body.addressHash || prior.amountSat !== body.amountSat || (prior.swapVersion ?? 1) !== (body.swapVersion ?? 1) || (body.ttlMs !== undefined && prior.expiresAt !== Math.min(box.expiresAt, prior.createdAt + lifetime(body.ttlMs, limits.offerTtlMs)))) fail(409, 'offer_terms_conflict', 'Offer token already belongs to different terms');
            return { status: 200, body: publicOffer(prior) };
          }
          if (Object.keys(next.offers).length >= limits.maxOffers) fail(429, 'offer_quota', 'Offer quota reached');
          if (Object.values(next.offers).some((offer) => offer.status !== 'cancelled' && (offer.addressHash === body.addressHash || offer.claim?.addressHash === body.addressHash))) fail(409, 'address_in_use', 'Receiving address already belongs to an offer');
          const id = randomBytes(16).toString('hex');
          const offer = { id, swapVersion: body.swapVersion ?? 1, amountSat: body.amountSat, receiveAddress: body.receiveAddress, addressHash: body.addressHash, ownerTokenHash: body.ownerTokenHash, createdAt: now, expiresAt: Math.min(box.expiresAt, now + lifetime(body.ttlMs, limits.offerTtlMs)), status: 'open' };
          next.offers[id] = offer; return { status: 201, body: publicOffer(offer), changed: true };
        }
        if (parts[0] === 'v1' && parts[1] === 'offers' && parts.length >= 3) {
          assert(ID.test(parts[2]), 'Invalid offer ID'); const offer = offerAt(next, parts[2], now);
          if (parts.length === 3 && req.method === 'GET') {
            if (!authorized(req, offer.ownerTokenHash) && !authorized(req, offer.claim?.claimTokenHash)) fail(401, 'unauthorized', 'An owner or claim bearer token is required');
            return { status: 200, body: publicOffer(offer, true) };
          }
          if (parts.length === 3 && req.method === 'DELETE') {
            requireAuthorization(req, offer.ownerTokenHash);
            if (offer.status === 'claimed') fail(409, 'offer_claimed', 'A claimed offer cannot be cancelled on the board');
            offer.status = 'cancelled'; return { status: 200, body: publicOffer(offer), changed: true };
          }
          if (parts.length === 4 && parts[3] === 'claim' && req.method === 'POST') {
            object(body, ['receiveAddress', 'addressHash', 'claimTokenHash', 'swapVersion'], ['receiveAddress', 'addressHash', 'claimTokenHash']); address(body.receiveAddress); hash(body.addressHash); hash(body.claimTokenHash);
            assert((body.swapVersion ?? 1) === (offer.swapVersion ?? 1), 'Unsupported swap version');
            assert(sha256(body.receiveAddress) === body.addressHash, 'Receiving address does not match mailbox');
            assert(body.addressHash !== offer.addressHash, 'Use a separate receiving address');
            const box = mailboxAt(next, body.addressHash, now); requireAuthorization(req, box.readTokenHash);
            if (offer.status === 'claimed' && offer.claim.addressHash === body.addressHash && offer.claim.claimTokenHash === body.claimTokenHash) return { status: 200, body: publicOffer(offer, true) };
            if (offer.status !== 'open') fail(409, 'offer_unavailable', 'Offer is no longer open');
            if (Object.values(next.offers).some((other) => other.status !== 'cancelled' && (other.addressHash === body.addressHash || other.claim?.addressHash === body.addressHash))) fail(409, 'address_in_use', 'Receiving address already belongs to an offer');
            offer.status = 'claimed'; offer.claim = { receiveAddress: body.receiveAddress, addressHash: body.addressHash, claimTokenHash: body.claimTokenHash, claimedAt: now };
            return { status: 200, body: publicOffer(offer, true), changed: true };
          }
        }
        fail(404, 'not_found', 'Route not found');
      });
      sendJson(res, response.status, response.body);
    } catch (error) {
      // Never log request bodies, credentials, addresses, or encrypted envelopes.
      const known = error instanceof HttpError;
      if (!res.headersSent && !res.destroyed) sendJson(res, known ? error.status : 500, { error: { code: known ? error.code : 'internal_error', message: known ? error.message : 'Relay operation failed' } });
    }
  });
  server.requestTimeout = 15_000; server.headersTimeout = 10_000; server.keepAliveTimeout = 1000;
  server.maxConnections = 64; server.maxRequestsPerSocket = 32;
  let released;
  server.release = () => {
    released ??= queue.then(async () => { await lock.close(); await unlink(lockPath); });
    return released;
  };
  server.on('close', () => { server.release().catch(() => {}); });
  return server;
}

export async function startRelay({ host = '127.0.0.1', port = 7449, ...options } = {}) {
  if (!['127.0.0.1', '::1', 'localhost'].includes(host)) throw new Error('This development relay binds only to loopback');
  const server = await createRelayServer(options);
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  } catch (error) { await server.release(); throw error; }
  const bound = server.address();
  return {
    server, url: `http://${host === '::1' ? '[::1]' : host}:${bound.port}`,
    async close() { await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); await server.release(); },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const stateDir = process.env.ZARK_RELAY_STATE_DIR;
  if (!stateDir) { console.error('Set ZARK_RELAY_STATE_DIR to a private local state directory.'); process.exitCode = 1; }
  else {
    const relay = await startRelay({ stateDir, port: Number(process.env.ZARK_RELAY_PORT ?? 7449) });
    console.log(`Zark development relay listening at ${relay.url}`);
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => relay.close().catch(() => { process.exitCode = 1; }));
  }
}
