import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once, EventEmitter } from 'node:events';
import { PassThrough, Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
const DEPLOYMENT = '22'.repeat(32);
import { parseRequest, requestLines, runBackend } from './main.mjs';

const request = (id, action = 'refresh', args = {}) => JSON.stringify({ id, action, args });

test('swap actions accept only a bounded distinct coin ID list', () => {
  const ids = Array.from({ length: 5 }, (_, i) => String(i + 1).repeat(64));
  assert.deepEqual(parseRequest(request('five', 'swapPublish', { coins: ids })).args.coins, ids);
  for (const coins of [[], [...ids, '6'.repeat(64)], [ids[0], ids[0]], 'coin', ['bad'], [null]]) {
    assert.throws(() => parseRequest(request('bad', 'swapPublish', { coins })), /Invalid wallet request/);
  }
  assert.throws(() => parseRequest(request('old', 'swapPublish', { coin: ids[0] })), /Invalid wallet request/);
});

test('preview subprocess consumes Swift-shaped JSON stdin without accessing any wallet', async () => {
  const child = spawn(process.execPath, [fileURLToPath(new URL('./main.mjs', import.meta.url))], {
    env: { ...process.env, ZARK_PREVIEW: '1', ZARK_PROFILE: 'not-a-real-wallet', ZARK_WALLET_BINARY: '/does-not-exist' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', data => { stdout += data; });
  child.stderr.on('data', data => { stderr += data; });
  child.stdin.end(`${request('native-uuid')}\n${request('write-request', 'receive', { kind: 'zark' })}\n`);
  const [code] = await once(child, 'close');
  assert.equal(code, 0);
  assert.equal(stderr, '');
  const events = stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(events.length, 2);
  assert.equal(events[0].id, 'native-uuid');
  assert.equal(events[0].snapshot.totalSat, 50000);
  assert.equal(events[0].snapshot.connected, true);
  assert.ok(events[0].snapshot.coins.every(coin => typeof coin.id === 'string' && Number.isInteger(coin.amountSat) && typeof coin.ownerOperation === 'string' && typeof coin.status === 'string'));
  assert.ok(events[0].snapshot.offers.every(offer => typeof offer.own === 'boolean'));
  assert.ok(events[0].snapshot.activity.every(activity => typeof activity.state === 'string'));
  assert.equal(events[1].id, 'write-request');
  assert.equal(events[1].error, 'Preview only');
});

test('IPC rejects oversized streaming lines before parse and recovers the next request', async () => {
  const lines = [];
  const input = Readable.from([Buffer.alloc(9000, 'x'), Buffer.alloc(9000, 'x'), Buffer.from(`\n${request('after-limit')}\n`)]);
  for await (const line of requestLines(input)) lines.push(line);
  assert.equal(lines[0], null);
  assert.equal(parseRequest(lines[1]).id, 'after-limit');
  for (const value of [
    { id: 'x', action: 'refresh', args: [] },
    { id: 'x', action: 'receive', args: { kind: 'mainnet' } },
    { id: 'x', action: ['refresh'], args: {} },
    { id: 'x', action: 'constructor', args: {} },
    { id: 'x', action: 'send', args: { coin: 'coin', address: 'address', broadcast: true } },
    { id: 'x\nsecret', action: 'refresh', args: {} },
    { id: 'x', action: 'withdraw', args: { coin: 'coin', address: 'address', feeSat: {} } },
  ]) assert.throws(() => parseRequest(JSON.stringify(value)), /Invalid wallet request/);
});

test('preview never runs injected configuration, lock, or wallet dependencies', async () => {
  const input = Readable.from([`${request('read')}\n`]);
  const output = new PassThrough();
  let raw = ''; output.on('data', bytes => { raw += bytes; });
  const forbidden = () => { throw new Error('Preview accessed a live dependency'); };
  const code = await runBackend({ input, output, signals: new EventEmitter(), env: { ZARK_PREVIEW: '1' }, dependencies: { configuration: forbidden, lockProfile: forbidden, wallet: { verifyAssets: forbidden } } });
  assert.equal(code, 0);
  assert.equal(JSON.parse(raw).id, 'read');
});

test('invalid user arguments retain a safe request id so native UI can finish its pending action', async () => {
  const input = Readable.from([`${request('native-action', 'receive', { kind: 'wrong' })}\n`]);
  const output = new PassThrough();
  let raw = ''; output.on('data', bytes => { raw += bytes; });
  await runBackend({ input, output, signals: new EventEmitter(), env: { ZARK_PREVIEW: '1' } });
  assert.deepEqual(JSON.parse(raw), { id: 'native-action', error: 'Invalid wallet request' });
});

test('SIGTERM stops new admission and drains in-flight work before releasing profile lock', async () => {
  const input = new PassThrough(), output = new PassThrough(), signals = new EventEmitter();
  output.resume();
  let finish, started;
  const work = new Promise(resolve => { finish = resolve; });
  const actionStarted = new Promise(resolve => { started = resolve; });
  const order = [];
  const controller = {
    tail: Promise.resolve(),
    async initialize() { order.push('initialized'); },
    action() { order.push('action'); started(); this.tail = work.then(() => order.push('finished')); return this.tail; },
    async tick() { throw new Error('No timer should run in this test'); },
  };
  const done = runBackend({ input, output, signals, env: {}, dependencies: {
    configuration: async () => ({ home: '/test/profile', deployment: DEPLOYMENT }),
    lockProfile: async () => { order.push('locked'); return async () => { order.push('released'); }; },
    wallet: { verifyAssets: async () => ({ verified: true, version: 10, proof_roles: 6, deployment: DEPLOYMENT }),
      close: async () => { order.push('worker-closed'); } }, controller,
  } });
  input.write(`${request('first')}\n${request('never-admitted')}\n`);
  await actionStarted;
  signals.emit('SIGTERM');
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(!order.includes('released'));
  finish();
  assert.equal(await done, 0);
  assert.deepEqual(order, ['locked', 'initialized', 'action', 'finished', 'worker-closed', 'released']);
  assert.equal(signals.listenerCount('SIGTERM'), 0);
});

test('startup fails closed on unsupported verification result and releases lock', async () => {
  const output = new PassThrough(); let raw = ''; output.on('data', bytes => { raw += bytes; });
  let released = false, initialized = false;
  const code = await runBackend({ input: Readable.from([`${request('refresh')}\n`]), output, signals: new EventEmitter(), env: {}, dependencies: {
    configuration: async () => ({ home: '/test/profile', deployment: DEPLOYMENT }),
    lockProfile: async () => async () => { released = true; },
    wallet: { verifyAssets: async () => ({ verified: true, version: 7, proof_roles: 6, deployment: DEPLOYMENT }) },
    controller: { async initialize() { initialized = true; } },
  } });
  assert.equal(code, 1); assert.equal(released, true); assert.equal(initialized, false);
  assert.ok(raw.split('\n').filter(Boolean).every(line => JSON.parse(line).error));
});
