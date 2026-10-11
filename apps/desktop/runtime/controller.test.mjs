import { seedLegacySwap } from './test-support/legacy-swap.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Controller, safeError } from './controller.mjs';
import { readPrivate, writePrivateImmutable, lockProfile } from './storage.mjs';
import { startRelay } from '../relay/server.mjs';
import { RelayClient } from '../relay/client.mjs';

const hex = value => value.repeat(64);
const A = hex('1'), B = hex('2'), DEPLOYMENT = hex('a');
const addr = letter => `tzark1${letter.repeat(164)}`;
const makeContext = (coin, operation) => `0a000000${DEPLOYMENT}${coin}${hex('3')}${operation}${hex('4')}${hex('5')}0100000000000000${"00".repeat(33)}`;
const member = intent => ({
  ...Object.fromEntries([['coin', 36], ['previous_state', 68], ['operation', 100], ['recipient_claim', 132], ['sender_session', 164]].map(([field, offset]) => [field, [...Buffer.from(intent.context.slice(offset * 2, offset * 2 + 64), 'hex')]])),
  revision: intent.revision,
});
function manifest(own, peer, expiresAt) {
  return { id: [...Buffer.from(hex('9'), 'hex')], deployment: [...Buffer.from(DEPLOYMENT, 'hex')], expires_at: expiresAt, members: [own, peer].sort((a, b) => a.coin.localeCompare(b.coin)).map(member) };
}

class FakeWallet {
  constructor(home, coin, letter, shared) { this.home = home; this.coin = coin; this.address = addr(letter); this.shared = shared; this.drafts = new Map(); this.received = new Map(); this.nativeAccepts = 0; }
  async snapshot() { return { coins: [{ id: this.coin, amountSat: 50_000, status: 'available' }] }; }
  async validateAddress(address) { return { valid: true, kind: address.startsWith('tzark') ? 'zark' : 'bitcoin' }; }
  async newAddress() {
    const invitationPath = path.join(this.home, 'invitation'); await mkdir(invitationPath, { mode: 0o700, recursive: true });
    return { address: this.address, invitationPath };
  }
  async batchDraft({ coin }) {
    if (!this.drafts.has(coin)) {
      const operationPath = path.join(this.home, 'draft'); await mkdir(operationPath, { mode: 0o700 });
      const operation = coin === A ? hex('6') : hex('7');
      this.drafts.set(coin, { operationPath, coin, transferOperation: operation, context: makeContext(coin, operation), revision: 1 });
    }
    return this.drafts.get(coin);
  }
  async batchManifest({ first, peer, expiresAt, output }) {
    const own = [...this.drafts.values()].find(d => d.operationPath === first);
    const other = JSON.parse(await readPrivate(peer));
    await writePrivateImmutable(output, JSON.stringify(manifest(own, other, expiresAt)));
    return { manifest: output };
  }
  async batchSend({ operationPath }) {
    const draft = [...this.drafts.values()].find(d => d.operationPath === operationPath);
    const offerPath = path.join(this.home, 'encrypted-offer');
    const envelope = JSON.stringify({ valid: true, coin: draft.coin, operation: draft.transferOperation });
    await writePrivateImmutable(offerPath, envelope);
    return { ...draft, offerPath };
  }
  async send({ coin }) { const d = await this.batchDraft({ coin }); return this.batchSend({ operationPath: d.operationPath }); }
  async complete(operationPath) {
    const draft = [...this.drafts.values()].find(d => d.operationPath === operationPath);
    return { operationPath, completed: this.shared.accepted.has(draft.transferOperation) };
  }
  async accept(parameters) {
    this.nativeAccepts++;
    const bytes = await readPrivate(parameters.offerPath);
    let envelope;
    try { envelope = JSON.parse(bytes); } catch { throw new Error('Native encrypted-offer validation failed'); }
    if (!envelope.valid || envelope.coin !== parameters.coin || envelope.operation !== parameters.transferOperation) throw new Error('Native encrypted-offer validation failed');
    this.shared.accepted.add(parameters.transferOperation);
    const result = { operationPath: parameters.operationPath, accepted: true, coin: parameters.coin };
    this.received.set(parameters.operationPath, result);
    return result;
  }
  async advance(operationPath) {
    if (this.received.has(operationPath)) return this.received.get(operationPath);
    return this.batchSend({ operationPath });
  }
}

async function setup(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'zark-controller-test-'));
  const relay = await startRelay({ stateDir: path.join(root, 'relay'), port: 0 });
  const shared = { accepted: new Set() };
  async function make(name, coin, letter) {
    const home = path.join(root, name); await mkdir(home, { mode: 0o700 });
    const wallet = new FakeWallet(home, coin, letter, shared); const client = new RelayClient(relay.url);
    const controller = new Controller({ wallet, relay: client, home }); await controller.initialize();
    return controller;
  }
  const alice = await make('alice', A, 'q'); const bob = await make('bob', B, 'p');
  t.after(async () => { await relay.close(); await rm(root, { recursive: true, force: true }); });
  return { root, relay, alice, bob, shared };
}
async function tick(controller) {
  for (const entry of [...controller.state.tasks, ...controller.state.swaps]) entry.due = 0;
  await controller.tick();
}

test('two controllers complete a swap using only public intents and encrypted offer transport', async (t) => {
  const { alice, bob, shared } = await setup(t);
  await seedLegacySwap(alice, 'swapPublish', { coin: A });
  const offer = (await bob.relay.listOffers())[0];
  await seedLegacySwap(bob, 'swapJoin', { coin: B, offer: offer.id });
  for (let i = 0; i < 8; i++) { await tick(alice); await tick(bob); }
  assert.equal(alice.state.swaps[0].phase, 'complete');
  assert.equal(bob.state.swaps[0].phase, 'complete');
  assert.equal(shared.accepted.size, 2);
  assert.equal(alice.wallet.nativeAccepts, 1);
  assert.equal(bob.wallet.nativeAccepts, 1);
  assert.equal(alice.state.tasks.filter(t => t.kind === 'receive').length, 1);
  assert.equal(bob.state.tasks.filter(t => t.kind === 'receive').length, 1);
  assert.deepEqual(await alice.relay.poll(alice.state.invitations[0].mailbox), []);
});

test('manual receive freezes ciphertext before ack and pins address only after native validation', async (t) => {
  const { alice, bob } = await setup(t);
  await bob.action('receive'); const box = bob.state.invitations[0];
  await alice.relay.send(box.address, { id: 'untrusted', kind: 'coin', payload: { coin: A, transferOperation: hex('8'), amountSat: 50_000, envelope: Buffer.from('garbage').toString('base64') } });
  await tick(bob);
  const bad = bob.state.tasks[0];
  assert.equal(box.used, undefined);
  assert.equal((await readPrivate(bad.parameters.offerPath)).toString(), 'garbage');
  assert.deepEqual(await bob.relay.poll(box.mailbox), []);
  await assert.rejects(bob.action('accept', { operation: bad.id }), /validation failed/);
  assert.equal(box.used, undefined);
  await alice.action('send', { coin: A, address: box.address });
  await tick(bob);
  const good = bob.state.tasks.find(task => task.id !== bad.id);
  assert.equal(good.phase, 'offer');
  await bob.action('accept', { operation: good.id });
  assert.equal(good.phase, 'complete');
  assert.equal(box.used, good.messageKey);
  await assert.rejects(writePrivateImmutable(good.parameters.offerPath, 'replacement'), /Frozen wallet input differs/);
  await tick(alice);
  assert.equal(alice.state.tasks[0].phase, 'complete');
});

test('malformed metadata is acknowledged without creating a receive task or pinning address', async (t) => {
  const { alice, bob } = await setup(t);
  await bob.action('receive'); const box = bob.state.invitations[0];
  await alice.relay.send(box.address, { id: 'invalid', kind: 'coin', payload: { coin: '../bad', transferOperation: hex('8'), amountSat: 5, envelope: 'QQ==' } });
  await tick(bob);
  assert.deepEqual(bob.state.tasks, []); assert.equal(box.used, undefined);
  assert.deepEqual(await bob.relay.poll(box.mailbox), []);
});

test('crash after successful send recovers stable replay without publishing or accepting twice', async (t) => {
  const { alice, bob, relay } = await setup(t);
  await bob.action('receive'); const box = bob.state.invitations[0];
  const original = alice.relay.send.bind(alice.relay); let dropped = false;
  alice.relay.send = async (...args) => {
    const result = await original(...args);
    if (!dropped) { dropped = true; throw new Error('Simulated lost send response'); }
    return result;
  };
  await assert.rejects(alice.action('send', { coin: A, address: box.address }), /lost send response/);
  const restarted = new Controller({ wallet: alice.wallet, relay: new RelayClient(relay.url), home: alice.home }); await restarted.initialize();
  await tick(restarted); await tick(bob);
  assert.equal(restarted.state.tasks[0].phase, 'pending');
  assert.equal(restarted.state.tasks[0].error, null);
  assert.equal(bob.state.tasks.length, 1);
  await bob.action('accept', { operation: bob.state.tasks[0].id });
  await tick(restarted);
  assert.equal(restarted.state.tasks[0].phase, 'complete');
});

test('interactive send durably delivers before background completion polling', async t => {
  const { alice, bob } = await setup(t);
  await bob.action('receive');
  const complete = alice.wallet.complete.bind(alice.wallet);
  let completions = 0;
  alice.wallet.complete = async (...args) => { completions++; return complete(...args); };
  const listOffers = alice.relay.listOffers.bind(alice.relay);
  let boardReads = 0;
  alice.relay.listOffers = async () => { boardReads++; return listOffers(); };
  await alice.action('send', { coin: A, address: bob.state.invitations[0].address });
  assert.equal(completions, 0);
  assert.equal(boardReads, 0, 'send rendering does not wait for the swap board');
  assert.equal(alice.state.tasks[0].phase, 'pending');
  await tick(bob);
  assert.equal(bob.state.tasks.length, 1);
  await bob.action('accept', { operation: bob.state.tasks[0].id });
  await tick(alice);
  assert.equal(completions, 1);
  assert.equal(alice.state.tasks[0].phase, 'complete');
});

test('a queued user action stops background polling at its next durable step', async t => {
  const { alice } = await setup(t);
  const polled = []; let release, released = 0;
  const gate = new Promise(resolve => { release = resolve; });
  alice.state.invitations = ['a', 'b', 'c'].map(id => ({ id, mailbox: { addressHash: id } }));
  alice.relay = {
    health: async () => ({}), listOffers: async () => [], releaseIdle: () => { released++; },
    poll: async mailbox => { polled.push(mailbox.addressHash); if (polled.length === 1) await gate; return []; },
  };
  const background = alice.tick();
  await new Promise(resolve => setImmediate(resolve));
  const queued = alice.action('retry', { operation: 'missing' });
  release();
  await background;
  await assert.rejects(queued, /Offer unavailable/);
  assert.deepEqual(polled, ['a']);
  assert.equal(released, 1);
  assert.equal(alice.waiting, 0);
  await alice.tick();
  assert.deepEqual(polled, ['a', 'a', 'b', 'c']);
});

test('delivery preparation overlaps native send and is closed on completion or failure', async t => {
  const { alice, bob } = await setup(t);
  const box = await bob.invitation();
  let prepared = false, closed = 0, delivered = 0;
  alice.relay.prepareDelivery = () => { prepared = true; return { close() { prepared = false; closed++; } }; };
  const nativeSend = alice.wallet.send.bind(alice.wallet);
  alice.wallet.send = async args => {
    assert.ok(prepared); assert.equal(delivered, 0);
    return nativeSend(args);
  };
  const send = alice.relay.send.bind(alice.relay);
  alice.relay.send = async (...args) => { assert.ok(prepared); delivered++; return send(...args); };
  await alice.action('send', { coin: A, address: box.address });
  assert.equal(delivered, 1); assert.equal(closed, 1);
  const task = alice.state.tasks[0];
  task.result = null; task.phase = 'draft';
  alice.wallet.send = async () => { assert.ok(prepared); throw new Error('native failure'); };
  await assert.rejects(alice.runTask(task), /native failure/);
  assert.equal(delivered, 1); assert.equal(closed, 2);
});

test('joiner rejects a manifest with altered own session or peer operation before pinning it', async (t) => {
  const { alice, bob } = await setup(t);
  await seedLegacySwap(alice, 'swapPublish', { coin: A });
  await seedLegacySwap(bob, 'swapJoin', { coin: B, offer: alice.state.swaps[0].offerId });
  const swap = bob.state.swaps[0]; const box = bob.state.invitations[0];
  const peer = { coin: A, context: makeContext(A, hex('6')), revision: 1 };
  const bad = manifest(swap.draft, peer, Math.floor(Date.now() / 1000) + 1000);
  bad.members.find(m => Buffer.from(m.coin).toString('hex') === B).sender_session[0] ^= 1;
  await alice.relay.send(box.address, { kind: 'swap-manifest', payload: { swapId: swap.offerId, intent: peer, manifest: bad } });
  await tick(bob);
  assert.equal(swap.phase, 'waiting_manifest'); assert.equal(swap.manifestPath, undefined);
  assert.deepEqual(await bob.relay.poll(box.mailbox), []);
  for (let i = 0; i < 8; i++) { await tick(alice); await tick(bob); }
  assert.equal(swap.phase, 'complete');
});

test('profile locks fail closed without stale-lock takeover races; safe errors never disclose peer text', async (t) => {
  const { root } = await setup(t); const directory = path.join(root, 'locked');
  const release = await lockProfile(directory);
  await assert.rejects(lockProfile(directory), /profile is locked/);
  await release(); const again = await lockProfile(directory); await again();
  assert.equal(safeError({ code: 'signer_unauthorized' }), 'Signer authorization required');
  assert.equal(safeError({ code: 'amount_mismatch' }), 'Coin amount does not match');
  assert.equal(safeError({ code: 'awaiting_confirmation', message: 'private detail' }), 'Waiting for a Bitcoin confirmation. Your saved action will retry.');
  assert.equal(safeError({ code: 'worker_unavailable', message: 'private detail' }), 'Restart the wallet, then retry the saved operation.');
  assert.equal(safeError(new Error('peer secret in error body')), 'Action failed. Retry the saved operation.');
});

test('outbound retries require the exact locally frozen content, even after receiver acknowledgment', async (t) => {
  const { alice, bob, relay } = await setup(t);
  await bob.action('receive'); const box = bob.state.invitations[0];
  await alice.sendOnce(box.address, { id: 'frozen', kind: 'offer', payload: { ciphertext: 'original' } });
  await bob.relay.ack(box.mailbox, 'frozen');
  const restarted = new Controller({ wallet: alice.wallet, relay: new RelayClient(relay.url), home: alice.home }); await restarted.initialize();
  await restarted.sendOnce(box.address, { id: 'frozen', kind: 'offer', payload: { ciphertext: 'original' } });
  await assert.rejects(restarted.sendOnce(box.address, { id: 'frozen', kind: 'offer', payload: { ciphertext: 'replacement' } }), /Frozen outbound message differs/);
});

test('expired swaps release a coin only after native abort confirms; committed batches keep recovering', async (t) => {
  const { alice, bob } = await setup(t);
  await seedLegacySwap(alice, 'swapPublish', { coin: A });
  await seedLegacySwap(bob, 'swapJoin', { coin: B, offer: alice.state.swaps[0].offerId });
  await tick(alice); // maker creates and delivers a manifest
  await tick(bob); // joiner reserves and sends an offer
  const swap = bob.state.swaps[0];
  swap.expiresAt = Math.floor(Date.now() / 1000) - 1;
  let attempts = 0;
  bob.wallet.batchAbort = async () => { attempts++; throw new Error('Batch already committed'); };
  await tick(bob);
  assert.equal(attempts, 1); assert.notEqual(swap.phase, 'cancelled');
  bob.wallet.batchAbort = async () => ({ aborted: true });
  await tick(bob);
  assert.equal(swap.phase, 'cancelled');
});

test('Bitcoin deposit readiness and restored amount reflect native recovery confirmation', async (t) => {
  const { bob } = await setup(t); const events = []; bob.emit = event => events.push(event);
  bob.state.deposit = { amountSat: 42_000, address: 'tb1qfunding', operationPath: '/fake/deposit', phase: 'awaiting_funding' };
  bob.decodeTransaction = async () => ({ txid: hex('d'), vin: [{ txinwitness: ['signed'] }], vout: [{ n: 0, value: 0.00042, scriptPubKey: { address: 'tb1qfunding' } }] });
  bob.wallet.bindDeposit = async () => ({});
  bob.wallet.advance = async () => ({ phase: 'awaiting_external_funding' });
  await bob.action('depositImport', { transactionPath: '/fake/transaction' });
  assert.equal(bob.state.deposit.phase, 'awaiting_funding');
  bob.wallet.advance = async () => ({ recovery_and_activation_saved: true });
  await bob.action('depositImport', { transactionPath: '/fake/transaction' });
  assert.equal(bob.state.deposit.phase, 'ready');
  await bob.action('receive', { kind: 'bitcoin' });
  assert.equal(events.findLast(event => event.receiveKind === 'bitcoin').receiveAmountSat, 42_000);
});

test('reopening Bitcoin receive after broadcast offers a fresh deposit with a new amount', async (t) => {
  const { bob } = await setup(t); const events = []; bob.emit = event => events.push(event);
  const previous = { amountSat: 25_000, address: 'tb1qprevious', operationPath: '/fake/previous', phase: 'broadcast' };
  bob.state.deposit = previous;
  await bob.save();
  await bob.initialize();
  let preparations = 0;
  bob.wallet.createDeposit = async ({ amountSat }) => {
    preparations++;
    assert.equal(amountSat, 50_000);
    return { operationPath: '/fake/next', funding_address: 'tb1qnext' };
  };

  await bob.action('receive', { kind: 'bitcoin' });
  assert.deepEqual(events.findLast(event => event.receiveKind === 'bitcoin'), {
    receiveKind: 'bitcoin', receiveAddress: '', receivePhase: 'address',
  });
  assert.equal(preparations, 0);
  assert.deepEqual(bob.state.deposit, previous);

  await bob.action('deposit', { amountSat: 50_000 });
  assert.equal(preparations, 1);
  assert.equal(bob.state.deposit.address, 'tb1qnext');
  assert.equal(bob.state.deposit.amountSat, 50_000);
  await bob.action('receive', { kind: 'bitcoin' });
  assert.equal(events.findLast(event => event.receiveKind === 'bitcoin').receiveAddress, 'tb1qnext');
  assert.equal(preparations, 1);
});

test('test sats claim saves recovery before broadcast and resumes without a second grant', async (t) => {
  const { bob } = await setup(t); const events = []; bob.emit = event => events.push(event);
  const steps = [];
  let grants = 0;
  bob.faucet = {
    info: async () => ({ amountSat: 25_000, available: true }),
    fund: async address => { grants++; steps.push(`fund:${address}`); return '02abcd'; },
  };
  bob.wallet.createDeposit = async ({ amountSat }) => {
    steps.push(`create:${amountSat}`);
    return { operationPath: '/fake/origin-1', funding_address: 'tb1pdeposit' };
  };
  bob.decodeTransaction = async file => {
    assert.equal((await readPrivate(file)).toString(), '02abcd\n');
    return { txid: hex('d'), vin: [{ txinwitness: ['signed'] }], vout: [{ n: 1, value: 0.00025, scriptPubKey: { address: 'tb1pdeposit' } }] };
  };
  bob.wallet.bindDeposit = async ({ vout }) => { steps.push(`bind:${vout}`); return {}; };
  let proving = 0;
  bob.wallet.advance = async (_, options) => {
    if (options?.broadcast) { steps.push('broadcast'); return { transaction_id: 'f'.repeat(64) }; }
    steps.push('recovery');
    if (++proving === 1) throw new Error('prover interrupted');
    return { recovery_and_activation_saved: true };
  };

  await assert.rejects(bob.action('testSats'), /prover interrupted/);
  assert.equal(bob.state.deposit.phase, 'awaiting_funding');
  await bob.initialize();
  assert.deepEqual(bob.state.deposit.boundFunding, { txid: hex('d'), vout: 1 });
  const decode = bob.decodeTransaction;
  bob.decodeTransaction = async file => ({ ...await decode(file), txid: hex('e') });
  await assert.rejects(bob.action('testSats'), /Transaction does not fund this deposit/);
  bob.decodeTransaction = decode;
  await bob.action('testSats');
  assert.equal(grants, 1);
  assert.deepEqual(steps, ['create:25000', 'fund:tb1pdeposit', 'bind:1', 'recovery', 'recovery', 'broadcast']);
  assert.equal(bob.state.deposit.phase, 'broadcast');
  assert.deepEqual(bob.state.deposits, [{ id: 'origin-1', amountSat: 25_000, source: 'faucet' }]);
  const activity = events.findLast(event => event.snapshot).snapshot.activity;
  assert.ok(activity.some(item => item.label === 'Test sats' && item.amountSat === 25_000));
});

test('test sats never take over a manual deposit and surface faucet refusals', async (t) => {
  const { bob } = await setup(t);
  bob.faucet = { info: async () => ({ amountSat: 25_000, available: false }), fund: async () => assert.fail('unexpected grant') };
  await assert.rejects(bob.action('testSats'), error => safeError(error) === 'The test sats faucet is empty or at its daily limit.');
  assert.equal(bob.state.deposit, undefined);
  bob.state.deposit = { amountSat: 42_000, address: 'tb1qmanual', operationPath: '/fake/manual', phase: 'awaiting_funding' };
  await assert.rejects(bob.action('testSats'), /Finish the pending deposit first/);
});

test('relay downtime does not block native withdrawal or received-offer recovery', async (t) => {
  const { bob } = await setup(t);
  bob.relay.health = async () => { throw new Error('Relay offline'); };
  bob.state.tasks.push({ id: 'withdrawal', kind: 'withdraw', coin: B, phase: 'pending', result: { operationPath: '/fake/withdrawal' } });
  let advances = 0;
  bob.wallet.advance = async () => { advances++; return { waiting: false }; };
  await tick(bob);
  assert.equal(bob.online, false);
  assert.equal(advances, 1);
  assert.equal(bob.state.tasks[0].phase, 'complete');
});

test('invalid or wrong-network destinations do not freeze a coin or create outgoing tasks', async (t) => {
  const { alice } = await setup(t);
  alice.wallet.validateAddress = async () => { throw new Error('Invalid checksum'); };
  await assert.rejects(alice.action('send', { coin: A, address: 'broken-address' }), error => /checksum/.test(error.message) && safeError(error) === 'Check the receiving address');
  assert.equal(alice.state.tasks.length, 0);
  assert.equal((await alice.coin(A)).id, A);
  alice.wallet.validateAddress = async () => ({ valid: true, kind: 'bitcoin' });
  await assert.rejects(alice.action('send', { coin: A, address: 'tb1pwrong-kind' }), /receiving address/);
  assert.equal(alice.state.tasks.length, 0);
});
