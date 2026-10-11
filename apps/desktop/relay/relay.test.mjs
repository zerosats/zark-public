import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { startRelay, sha256 } from './server.mjs';
import { RelayClient, RelayError, addressHash } from './client.mjs';

// Relay syntax validation is deliberately separate from the Rust address codec.
const address = (letter) => `tzark1${letter.repeat(164)}`;
const A = address('q'); const B = address('p'); const C = address('r');
const TOKEN = '11'.repeat(32);
function errorCode(code) { return (error) => error instanceof RelayError && error.code === code; }
async function fixture(t, options = {}) {
  const stateDir = await mkdtemp(path.join(os.tmpdir(), 'zark-relay-test-'));
  let relay = await startRelay({ stateDir, port: 0, ...options });
  const f = { stateDir, relay, client: new RelayClient(relay.url), async restart() {
    await relay.close(); relay = await startRelay({ stateDir, port: 0, ...options });
    f.relay = relay; f.client = new RelayClient(relay.url);
  } };
  t.after(async () => { await relay.close(); await rm(stateDir, { recursive: true, force: true }); });
  return f;
}

test('mailbox access is isolated; acknowledgments and replay records survive restart', async (t) => {
  const f = await fixture(t); const client = f.client;
  const alice = await client.createMailbox(A); const bob = await client.createMailbox(B);
  await client.send(A, { id: 'opaque-1', kind: 'offer', payload: { envelope: 'encrypted-data', publicContext: 'context' } });
  assert.equal((await client.poll(alice))[0].payload.envelope, 'encrypted-data');
  assert.deepEqual(await client.poll(bob), []);
  await assert.rejects(client.poll({ ...alice, token: bob.token }), errorCode('unauthorized'));
  await assert.rejects(client.ack({ ...alice, token: bob.token }, 'opaque-1'), errorCode('unauthorized'));
  await assert.rejects(client.createMailbox(A), errorCode('mailbox_exists'));
  await assert.rejects(client.send(A, { id: 'opaque-1', payload: { envelope: 'different' } }), errorCode('message_conflict'));
  await f.restart();
  assert.equal((await f.client.poll(alice)).length, 1);
  await f.client.ack(alice, 'opaque-1');
  await f.client.ack(alice, 'opaque-1');
  await f.restart();
  assert.deepEqual(await f.client.poll(alice), []);
  await assert.rejects(f.client.send(A, { id: 'opaque-1', kind: 'offer', payload: { envelope: 'encrypted-data', publicContext: 'context' } }), errorCode('message_replayed'));
  await assert.rejects(f.client.send(A, { id: 'opaque-1', payload: {} }), errorCode('message_conflict'));
  const state = await readFile(path.join(f.stateDir, 'relay-state.json'), 'utf8');
  assert.equal(state.includes(alice.token), false);
  assert.equal(state.includes(bob.token), false);
  assert.equal((await stat(path.join(f.stateDir, 'relay-state.json'))).mode & 0o777, 0o600);
  assert.equal((await stat(f.stateDir)).mode & 0o777, 0o700);
});

test('offer claim is compare-and-set, with private routing and persistent ownership', async (t) => {
  const f = await fixture(t); const client = f.client;
  const alice = await client.createMailbox(A); const bob = await client.createMailbox(B); const carol = await client.createMailbox(C);
  const offer = await client.createOffer({ amountSat: 20_000, receiveAddress: A });
  assert.equal((await client.listOffers()).length, 1);
  const publicJson = JSON.stringify(await client.listOffers());
  assert.equal(publicJson.includes(offer.ownerToken), false);
  assert.equal(publicJson.includes(sha256(offer.ownerToken)), false);
  assert.equal(publicJson.includes(alice.token), false);
  await assert.rejects(client.getOffer(offer.id, TOKEN), errorCode('unauthorized'));
  const claims = await Promise.allSettled([
    client.claimOffer(offer.id, { receiveAddress: B }),
    client.claimOffer(offer.id, { receiveAddress: C }),
  ]);
  assert.equal(claims.filter((result) => result.status === 'fulfilled').length, 1);
  const loser = claims.find((result) => result.status === 'rejected');
  assert.equal(loser.reason.code, 'offer_unavailable');
  const winner = claims.find((result) => result.status === 'fulfilled').value;
  assert.equal(winner.status, 'claimed');
  assert.deepEqual(await client.listOffers(), []);
  const ownerView = await client.getOffer(offer.id, offer.ownerToken);
  assert.equal(ownerView.claim.receiveAddress, winner.claim.receiveAddress);
  assert.equal(JSON.stringify(ownerView).includes(winner.claimToken), false);
  assert.equal(JSON.stringify(ownerView).includes('TokenHash'), false);
  await assert.rejects(client.cancelOffer(offer.id, offer.ownerToken), errorCode('offer_claimed'));
  await f.restart();
  assert.equal((await f.client.getOffer(offer.id, winner.claimToken)).claim.receiveAddress, winner.claim.receiveAddress);
  const state = await readFile(path.join(f.stateDir, 'relay-state.json'), 'utf8');
  for (const secret of [alice.token, bob.token, carol.token, offer.ownerToken, winner.claimToken]) assert.equal(state.includes(secret), false);
});

test('offer ownership and mailbox proof cannot be forged; open offers can be cancelled', async (t) => {
  const { client } = await fixture(t);
  const alice = await client.createMailbox(A); const bob = await client.createMailbox(B);
  await assert.rejects(client.request('POST', '/v1/offers', { bearer: bob.token, body: { amountSat: 100, receiveAddress: A, addressHash: alice.addressHash, ownerTokenHash: sha256(TOKEN) } }), errorCode('unauthorized'));
  const offer = await client.createOffer({ amountSat: 100, receiveAddress: A });
  await assert.rejects(client.claimOffer(offer.id, { receiveAddress: A }), errorCode('invalid_request'));
  await assert.rejects(client.request('POST', `/v1/offers/${offer.id}/claim`, { bearer: alice.token, body: { receiveAddress: B, addressHash: bob.addressHash, claimTokenHash: sha256(TOKEN) } }), errorCode('unauthorized'));
  await assert.rejects(client.cancelOffer(offer.id, TOKEN), errorCode('unauthorized'));
  assert.equal((await client.cancelOffer(offer.id, offer.ownerToken)).status, 'cancelled');
  assert.deepEqual(await client.listOffers(), []);
  await assert.rejects(client.claimOffer(offer.id, { receiveAddress: B }), errorCode('offer_unavailable'));
});

test('multi-coin offer version is public and must match before claim', async t => {
  const { client } = await fixture(t);
  await client.createMailbox(A); await client.createMailbox(B);
  const offer = await client.createOffer({ amountSat: 50000, receiveAddress: A, swapVersion: 2 });
  assert.equal((await client.listOffers())[0].swapVersion, 2);
  await assert.rejects(client.claimOffer(offer.id, { receiveAddress: B }), errorCode('invalid_request'));
  assert.equal((await client.listOffers())[0].id, offer.id);
  const claimed = await client.claimOffer(offer.id, { receiveAddress: B, swapVersion: 2 });
  assert.equal(claimed.swapVersion, 2);
});

test('messages and offers expire; expired one-use mailbox ownership cannot be replaced', async (t) => {
  let now = 10_000;
  const f = await fixture(t, { clock: () => now, limits: { mailboxTtlMs: 1000, messageTtlMs: 100, offerTtlMs: 200 } });
  const box = await f.client.createMailbox(A);
  await f.client.send(A, { id: 'expires', payload: {} });
  const offer = await f.client.createOffer({ amountSat: 100, receiveAddress: A });
  now += 101;
  assert.deepEqual(await f.client.poll(box), []);
  await assert.rejects(f.client.send(A, { id: 'expires', payload: {} }), errorCode('message_replayed'));
  now += 100;
  assert.deepEqual(await f.client.listOffers(), []);
  await assert.rejects(f.client.getOffer(offer.id, offer.ownerToken), errorCode('offer_not_found'));
  now += 800;
  await assert.rejects(f.client.poll(box), errorCode('mailbox_expired'));
  await assert.rejects(f.client.send(A, { payload: {} }), errorCode('mailbox_expired'));
  await f.restart();
  await assert.rejects(f.client.createMailbox(A), errorCode('mailbox_exists'));
});

test('message byte, count, lifetime, replay and mailbox quotas are enforced', async (t) => {
  const { client } = await fixture(t, { limits: { maxMessageBytes: 64, maxMessagesPerMailbox: 1, maxAcceptedMessagesPerMailbox: 2, maxMailboxes: 1, messageTtlMs: 1000 } });
  const box = await client.createMailbox(A);
  await assert.rejects(client.createMailbox(B), errorCode('mailbox_quota'));
  await assert.rejects(client.send(A, { payload: { data: 'a'.repeat(65) } }), errorCode('payload_too_large'));
  await assert.rejects(client.send(A, { payload: { data: 'a'.repeat(9000) } }), errorCode('body_too_large'));
  await assert.rejects(client.send(A, { payload: {}, ttlMs: 1001 }), errorCode('invalid_request'));
  await client.send(A, { id: 'one', payload: {} });
  await assert.rejects(client.send(A, { id: 'two', payload: {} }), errorCode('message_quota'));
  await client.ack(box, 'one');
  await client.send(A, { id: 'two', payload: {} });
  await client.ack(box, 'two');
  await assert.rejects(client.send(A, { id: 'three', payload: {} }), errorCode('message_quota'));
  await assert.rejects(client.send(A, { id: 'one', payload: {} }), errorCode('message_replayed'));
});

test('offer quotas, amount validation and response bounds fail safely', async (t) => {
  const { client, relay } = await fixture(t, { limits: { maxOffers: 1 } });
  await client.createMailbox(A); await client.createMailbox(B);
  for (const amountSat of [0, -1, 1.5, '100', 2_100_000_000_000_001]) {
    await assert.rejects(client.createOffer({ amountSat, receiveAddress: A }), errorCode('invalid_request'));
  }
  await client.createOffer({ amountSat: 100, receiveAddress: A });
  await assert.rejects(client.createOffer({ amountSat: 100, receiveAddress: B }), errorCode('offer_quota'));
  const smallClient = new RelayClient(relay.url, { maxResponseBytes: 8 });
  await assert.rejects(smallClient.listOffers(), /response exceeds byte limit/);
});

test('storage quota rejection does not mutate in-memory or persisted state', async (t) => {
  const f = await fixture(t, { limits: { maxStateBytes: 1000 } });
  const box = await f.client.createMailbox(A);
  await assert.rejects(f.client.send(A, { id: 'large', payload: { data: 'a'.repeat(1500) } }), errorCode('storage_quota'));
  assert.deepEqual(await f.client.poll(box), []);
  await f.restart();
  await f.client.send(A, { id: 'large', payload: { data: 'small' } });
  assert.equal((await f.client.poll(box)).length, 1);
});

test('JSON prototype-named message IDs are handled as opaque own keys', async (t) => {
  const f = await fixture(t); const box = await f.client.createMailbox(A);
  await f.client.send(A, { id: '__proto__', payload: { ciphertext: 'safe' } });
  await f.restart();
  assert.equal((await f.client.poll(box))[0].id, '__proto__');
  await f.client.ack(box, '__proto__');
  assert.deepEqual(await f.client.poll(box), []);
  await assert.rejects(f.client.send(A, { id: '__proto__', payload: { ciphertext: 'safe' } }), errorCode('message_replayed'));
});

test('development relay rejects browser origins, rebinding hosts, unexpected fields and traversal', async (t) => {
  const { relay, client } = await fixture(t);
  assert.equal((await client.health()).ok, true);
  const browser = await fetch(`${relay.url}/health`, { headers: { Origin: 'http://evil.example' } });
  assert.equal(browser.status, 403);
  assert.equal(browser.headers.has('access-control-allow-origin'), false);
  const rebinding = await new Promise((resolve, reject) => {
    http.get(`${relay.url}/health`, { headers: { Host: 'evil.example' } }, (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject);
  });
  assert.equal(rebinding, 403);
  await assert.rejects(client.request('POST', '/v1/mailboxes', { body: { addressHash: addressHash(A), readTokenHash: sha256(TOKEN), unexpected: 'ignored?' } }), errorCode('invalid_request'));
  await assert.rejects(client.send('../other', { payload: {} }), /receiving address/);
  await assert.rejects(client.getOffer('../other', TOKEN), /identifier/);
  const malformed = await fetch(`${relay.url}/v1/mailboxes`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{' });
  assert.equal(malformed.status, 400);
  for (const url of ['http://example.com', 'https://user:pass@example.com', 'https://example.com/path', 'https://example.com/?token=abc']) {
    assert.throws(() => new RelayClient(url), /Relay URL/);
  }
});

test('relay state lock rejects a second process and is released on graceful close', async (t) => {
  const f = await fixture(t);
  await assert.rejects(startRelay({ stateDir: f.stateDir, port: 0 }), /state is locked/);
  await f.restart();
  assert.equal((await f.client.health()).ok, true);
});

test('pre-saved mailbox, offer and claim tokens support exact retries after restart', async (t) => {
  const f = await fixture(t);
  const alice = await f.client.createMailbox(A, { token: TOKEN });
  const bob = await f.client.createMailbox(B);
  const offerToken = '22'.repeat(32); const claimToken = '33'.repeat(32);
  const offer = await f.client.createOffer({ amountSat: 500, receiveAddress: A, ownerToken: offerToken });
  const claimed = await f.client.claimOffer(offer.id, { receiveAddress: B, token: claimToken });
  await f.restart();
  const restored = await f.client.createMailbox(A, { token: TOKEN });
  assert.deepEqual(restored, alice);
  f.client.useMailbox(bob);
  assert.equal((await f.client.createOffer({ amountSat: 500, receiveAddress: A, ownerToken: offerToken })).id, offer.id);
  assert.deepEqual(await f.client.claimOffer(offer.id, { receiveAddress: B, token: claimToken }), claimed);
  await assert.rejects(f.client.createOffer({ amountSat: 501, receiveAddress: A, ownerToken: offerToken }), errorCode('offer_terms_conflict'));
  await assert.rejects(f.client.claimOffer(offer.id, { receiveAddress: B, token: '44'.repeat(32) }), errorCode('offer_unavailable'));
});
