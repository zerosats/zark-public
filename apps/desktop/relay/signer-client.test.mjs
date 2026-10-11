import test from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import { X509Certificate, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SignerRelayClient } from './signer-client.mjs';
import { DeliveryPreparation } from './mailbox-connection.mjs';

async function fixture(t, respond, { session = false } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'zark-mail-tls-'));
  const cert = path.join(root, 'cert.pem'), key = path.join(root, 'key.pem'), config = path.join(root, 'openssl.cnf');
  await writeFile(config, '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n');
  execFileSync('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', config, '-keyout', key, '-out', cert], { stdio: 'ignore' });
  const pem = await readFile(cert);
  const seen = [], sockets = new Set(); let connections = 0;
  const server = tls.createServer({ key: await readFile(key), cert: pem, minVersion: 'TLSv1.3',
    ALPNProtocols: session ? ['zark-mail/1-session', 'zark-mail/1'] : ['zark-mail/1'] }, socket => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
    let bytes = '';
    socket.on('data', chunk => {
      bytes += chunk;
      while (bytes.includes('\n')) {
        const end = bytes.indexOf('\n');
        const request = JSON.parse(bytes.slice(0, end)); bytes = bytes.slice(end + 1); seen.push(request);
        const response = respond(request, socket);
        if (response === undefined) continue;
        const wire = `${JSON.stringify(response)}\n`;
        if (socket.alpnProtocol === 'zark-mail/1-session') socket.write(wire);
        else socket.end(wire);
      }
    });
  });
  server.on('connection', () => { connections++; });
  server.on('tlsClientError', () => {});
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); });
  return { seen, sockets, connections: () => connections, endpoint: { address: `127.0.0.1:${server.address().port}`, server_name: 'localhost', ca_certificate: cert, certificate_sha256: createHash('sha256').update(new X509Certificate(pem).raw).digest('hex') } };
}

test('hosted client pins TLS before sending tokens and isolates its transport protocol', async t => {
  const f = await fixture(t, () => ({ ok: true, result: { service: 'zark-mail', version: 1 } }));
  const client = new SignerRelayClient(f.endpoint, {});
  assert.equal((await client.health()).service, 'zark-mail');
  assert.deepEqual(f.seen[0], { version: 1, method: 'GET', path: '/health', body: null });
  const wrongPin = new SignerRelayClient({ ...f.endpoint, certificate_sha256: 'ab'.repeat(32) }, {});
  await assert.rejects(wrongPin.request('GET', '/v1/offers/id', { bearer: 'cd'.repeat(32) }), /authentication/);
  const wrongName = new SignerRelayClient({ ...f.endpoint, server_name: 'wrong.example' }, {});
  await assert.rejects(wrongName.health(), /connection failed/);
  assert.equal(f.seen.length, 1);
});

test('private payloads never appear on the hosted wire; tokens and remote errors are not echoed', async t => {
  const f = await fixture(t, r => r.path === '/health'
    ? ({ ok: false, error: { code: 'arbitrary-secret-canary', message: 'do-not-display-me' } })
    : ({ ok: true, result: { id: r.body.id } }));
  let plain;
  const wallet = { async sealDelivery(address, message) { plain = { address, message }; return { id: '12'.repeat(32), ciphertext: 'ab'.repeat(100) }; } };
  const client = new SignerRelayClient(f.endpoint, wallet);
  const message = { id: 'logical-private-id', kind: 'swap-manifest', payload: { coin: 'private-coin', amountSat: 123456, manifest: 'private-manifest' } };
  await client.send(`tzark1${'q'.repeat(164)}`, message);
  assert.deepEqual(plain.message, message);
  const wire = JSON.stringify(f.seen);
  for (const value of ['logical-private-id', 'swap-manifest', 'private-coin', '123456', 'private-manifest', 'amountSat']) assert.ok(!wire.includes(value));
  await assert.rejects(client.health(), e => e.code === 'remote_rejected' && !e.message.includes('canary') && !e.message.includes('display'));
});

test('malformed encrypted mail is discarded but transient wallet failures retain it', async () => {
  const endpoint = { address: '127.0.0.1:1', server_name: 'localhost', ca_certificate: '/unused', certificate_sha256: 'ab'.repeat(32) };
  const mailbox = { addressHash: '12'.repeat(32), token: '34'.repeat(32), invitationPath: '/wallet/invitation' };
  let code = 'process_failed', acknowledged = 0;
  const client = new SignerRelayClient(endpoint, { async mailCrypto() { throw Object.assign(new Error('failure'), { code }); } });
  client.request = async method => method === 'GET' ? { messages: [{ id: '56'.repeat(32), ciphertext: 'ab'.repeat(100) }] } : (++acknowledged, { acknowledged: true });
  await assert.rejects(client.poll(mailbox)); assert.equal(acknowledged, 0);
  code = 'invalid_message'; assert.deepEqual(await client.poll(mailbox), []); assert.equal(acknowledged, 1);
  assert.throws(() => client.useMailbox(mailbox), /Legacy relay/);
});

const address = `tzark1${'q'.repeat(164)}`;
const message = { id: 'stable-message', kind: 'coin', payload: { private: 'contents' } };
const sealed = { id: '12'.repeat(32), ciphertext: 'ab'.repeat(100) };
const health = { ok: true, result: { service: 'zark-mail', version: 1 } };

test('delivery preparation sends only health and reuses its authenticated socket after sealing', async t => {
  const f = await fixture(t, r => r.path === '/health' ? health : { ok: true, result: { id: r.body.id } }, { session: true });
  const client = new SignerRelayClient(f.endpoint, { async sealDelivery() {
    assert.deepEqual(f.seen.map(r => r.path), ['/health']); return sealed;
  } });
  const preparation = client.prepareDelivery(); t.after(() => preparation.close());
  await preparation.ready;
  assert.equal(f.connections(), 1);
  const result = await client.send(address, message);
  assert.equal(result.id, sealed.id);
  assert.equal(f.connections(), 1);
  assert.equal(f.seen.length, 2);
  assert.deepEqual(f.seen[1].body, sealed);
});

test('legacy servers and expired preparations fall back before any delivery is sent', async t => {
  for (const session of [false, true]) {
    const f = await fixture(t, r => r.path === '/health' ? health : { ok: true, result: { id: r.body.id } }, { session });
    const client = new SignerRelayClient(f.endpoint, { async sealDelivery() { return sealed; } });
    const preparation = client.prepareDelivery(); await preparation.ready;
    preparation.close();
    assert.equal((await client.send(address, message)).id, sealed.id);
    assert.equal(f.seen.filter(r => r.method === 'POST').length, 1);
    assert.equal(f.connections(), 2);
  }
});

test('delivery failures after a write never cause an automatic reconnect or replay', async t => {
  const f = await fixture(t, (r, socket) => {
    if (r.path === '/health') return health;
    socket.destroy();
  }, { session: true });
  const client = new SignerRelayClient(f.endpoint, { async sealDelivery() { return sealed; } });
  await client.prepareDelivery().ready;
  await assert.rejects(client.send(address, message));
  assert.equal(f.connections(), 1);
  assert.equal(f.seen.filter(r => r.method === 'POST').length, 1);
});

test('preparation cancellation and pin failures cannot transmit a delivery or leak sockets', async t => {
  const f = await fixture(t, () => health, { session: true });
  const client = new SignerRelayClient(f.endpoint, {});
  const cancelled = client.prepareDelivery(); cancelled.close(); await cancelled.ready;
  assert.equal(f.seen.length, 0);
  const wrong = new SignerRelayClient({ ...f.endpoint, certificate_sha256: 'ff'.repeat(32) }, { async sealDelivery() { return sealed; } });
  await wrong.prepareDelivery().ready;
  await assert.rejects(wrong.send(address, message), /authentication/);
  assert.equal(f.seen.length, 0);
});

const box = { addressHash: '12'.repeat(32), token: '34'.repeat(32) };
const inbox = `/v1/mailboxes/${box.addressHash}/messages`;
const replies = r => r.path === '/health' ? health : r.method === 'POST' ? { ok: true, result: { id: r.body.id } }
  : r.method === 'DELETE' ? { ok: true, result: { acknowledged: true } } : { ok: true, result: { messages: [] } };

test('background requests share one parked session; deliveries and legacy servers never do', async t => {
  for (const session of [true, false]) {
    const f = await fixture(t, replies, { session });
    const client = new SignerRelayClient(f.endpoint, { async sealDelivery() { return sealed; } });
    t.after(() => client.releaseIdle());
    await client.health();
    await client.request('GET', inbox, { bearer: box.token });
    await client.ack(box, '56'.repeat(32));
    assert.equal(f.connections(), session ? 1 : 3);
    await client.send(address, message);
    assert.equal(f.connections(), session ? 2 : 4);
    await client.health();
    assert.equal(f.connections(), session ? 2 : 5);
    client.releaseIdle();
    await client.health();
    assert.equal(f.connections(), session ? 3 : 6);
  }
});

test('a parked session lost before any reply is replaced only for idempotent requests', async t => {
  let drop = 0;
  const f = await fixture(t, (r, socket) => {
    if (drop && r.path !== '/health') { drop--; socket.destroy(); return undefined; }
    return replies(r);
  }, { session: true });
  const client = new SignerRelayClient(f.endpoint, { async sealDelivery() { return sealed; } });
  t.after(() => client.releaseIdle());
  await client.health(); drop = 1;
  assert.deepEqual(await client.request('GET', inbox, { bearer: box.token }), { messages: [] });
  assert.equal(f.connections(), 2);
  assert.equal(f.seen.filter(r => r.path === inbox).length, 2);
  drop = 1;
  await assert.rejects(client.send(address, message));
  assert.equal(f.seen.filter(r => r.method === 'POST').length, 1);

  const partial = await fixture(t, (r, socket) => {
    if (r.path === '/health') return health;
    socket.end('{"ok":true,');
    return undefined;
  }, { session: true });
  const reader = new SignerRelayClient(partial.endpoint, {});
  t.after(() => reader.releaseIdle());
  await reader.health();
  await assert.rejects(reader.request('GET', inbox, { bearer: box.token }));
  assert.equal(partial.connections(), 1);
  assert.equal(partial.seen.filter(r => r.path === inbox).length, 1);
});

test('a parked session is closed after its idle window', async t => {
  const f = await fixture(t, replies, { session: true });
  const client = new SignerRelayClient(f.endpoint, {});
  await client.health();
  assert.equal(f.sockets.size, 1);
  await new Promise(resolve => setTimeout(resolve, 1_200));
  assert.equal(f.sockets.size, 0);
  await client.health();
  client.releaseIdle();
  assert.equal(f.connections(), 2);
});

test('preparation expires independently while the wallet is busy', async t => {
  const f = await fixture(t, () => health, { session: true });
  const client = new SignerRelayClient(f.endpoint, {});
  const prepared = new DeliveryPreparation(client.endpoint, 1000, 5);
  t.after(() => prepared.close());
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(await prepared.take(), null);
});
