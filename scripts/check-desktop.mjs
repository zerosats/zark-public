// Operator-invoked public smoke check. Uses new profiles, real testnet claims,
// the packaged entry point and its bundled Node; never reads another wallet.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { mkdir, open, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const [bundleArg, outputArg] = process.argv.slice(2);
if (!bundleArg || !outputArg) throw new Error('Usage: node scripts/check-desktop.mjs /absolute/Zark.app-or-extracted-AppDir /absolute/new-test-directory');
const bundle = path.resolve(bundleArg);
const app = ['Contents/Resources/app', 'usr/lib/Zark/app']
  .map(relative => path.join(bundle, relative))
  .find(candidate => existsSync(path.join(candidate, 'apps/desktop/runtime/app.mjs')));
assert.ok(app, 'Expected a Mac app or an extracted Linux AppImage');
const services = JSON.parse(await readFile(path.join(app, 'apps/desktop/runtime/public-services.json')));
const endpoint = process.env.ZARK_SIGNER_ADDRESS || services.signer_address;
const loopback = /^(127\.|\[::1\]:|localhost:)/.test(endpoint);
const output = path.resolve(outputArg);
await mkdir(output, { mode: 0o700 });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
class Client {
  constructor(profile, fd) {
    this.events = {}; this.pending = new Map(); this.sequence = 0;
    this.child = spawn(path.join(app, 'node/bin/node'), [path.join(app, 'apps/desktop/runtime/app.mjs')], {
      env: { HOME: process.env.HOME, PATH: '/usr/bin:/bin', ZARK_PROFILE: profile,
        ZARK_DESKTOP_BASE: path.join(output, 'profiles'), ZARK_WALLET_BINARY: path.join(app, 'bin/zark-wallet'),
        ...(process.env.ZARK_SIGNER_ADDRESS ? { ZARK_SIGNER_ADDRESS: process.env.ZARK_SIGNER_ADDRESS } : {}) },
      stdio: ['pipe', 'pipe', fd],
    });
    this.closed = new Promise(resolve => this.child.once('close', resolve));
    createInterface({ input: this.child.stdout }).on('line', line => {
      const event = JSON.parse(line); Object.assign(this.events, event);
      if (event.error) console.error(`${profile}: ${event.error}`);
      const item = this.pending.get(event.id);
      if (item) {
        this.pending.delete(event.id); clearTimeout(item.timer);
        event.error ? item.reject(new Error(event.error)) : item.resolve();
      }
    });
    this.child.on('exit', () => {
      this.exited = true;
      for (const item of this.pending.values()) { clearTimeout(item.timer); item.reject(new Error('Packaged backend exited')); }
      this.pending.clear();
    });
  }
  async action(action, args = {}) {
    if (this.exited) throw new Error('Packaged backend exited; retain the profile and inspect its log');
    const begin = performance.now(), id = 'public-check-' + ++this.sequence;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Wallet action timed out; retain the profile for recovery')), 15 * 60 * 1000);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(JSON.stringify({ id, action, args }) + '\n');
    });
    return (performance.now() - begin) / 1000;
  }
  async close() { this.child.stdin.end(); await this.closed; }
}
const logs = [], clients = [];
try {
  for (const profile of ['check-alice', 'check-bob']) {
    const log = await open(path.join(output, profile + '.log'), 'wx', 0o600);
    const client = new Client(profile, log.fd);
    logs.push(log); clients.push(client);
    // Model normal first launch before opening the second wallet. Concurrent
    // provisioning of a shared asset directory is a separate stress test.
    await client.action('refresh');
  }
  const [a, b] = clients;
  console.log('Both fresh packaged wallets initialized without system Node or developer tools.');
  assert.equal(a.events.faucetAmountSat, 25000);
  const claim = await a.action('testSats');
  console.log(`Public claim completed in ${claim.toFixed(2)} s.`);
  let coin;
  for (let attempt = 0; attempt < 90; attempt++) {
    await a.action('refresh'); coin = a.events.snapshot.coins.find(c => c.status === 'available');
    if (coin) break;
    await pause(2000);
  }
  assert.equal(coin?.amountSat, 25000);
  await b.action('receive', { kind: 'zark' });
  const sendBegin = performance.now();
  let confirmationWaitObserved = false;
  try { await a.action('send', { coin: coin.id, address: b.events.receiveAddress }); }
  catch (error) {
    if (!error.message.startsWith('Waiting for a Bitcoin confirmation.')) throw error;
    confirmationWaitObserved = true;
    const saved = JSON.parse(await readFile(path.join(output, 'profiles/check-alice/.desktop-gui/state.json')));
    const task = saved.tasks.find(t => t.kind === 'send' && t.coin === coin.id);
    assert.ok(task, 'Unconfirmed send has a durable retry');
    let sent = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      await pause(5000);
      try { await a.action('retry', { operation: task.id }); sent = true; break; }
      catch (retryError) { if (!retryError.message.startsWith('Waiting for a Bitcoin confirmation.')) throw retryError; }
    }
    assert.ok(sent, 'Deposit confirmed and the same saved transfer resumed');
  }
  const send = (performance.now() - sendBegin) / 1000;
  await b.action('refresh');
  const offer = b.events.snapshot.activity.find(o => o.state === 'offer');
  assert.ok(offer, 'Public signer mailbox delivered the offer');
  const accept = await b.action('accept', { operation: offer.id });
  await a.action('refresh'); await b.action('refresh');
  assert.equal(b.events.snapshot.totalSat, 25000);
  const report = { network: 'MutinyNet', platform: `${process.platform}-${process.arch}`, bundledRuntime: true,
    signerTransport: loopback ? 'isolated loopback test endpoint' : process.env.ZARK_SIGNER_ADDRESS ? 'operator override; not direct public reachability' : 'configured public endpoint',
    claimThroughBroadcastSeconds: claim, sendIncludingConfirmationWaitSeconds: send,
    confirmationWaitObserved, acceptSeconds: accept, receivedSat: 25000 };
  await writeFile(path.join(output, 'result.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify(report));
} finally {
  for (const client of clients) await client.close();
  for (const log of logs) await log.close();
}
