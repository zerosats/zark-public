import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { createHash, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { startBridge } from './chain-bridge.mjs';
import { createGatewayClient } from './gateway-client.mjs';
import { downloadPublicAsset } from './public-download.mjs';

async function unusedPort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function fixture(t, observations = false) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'zark-chain-bridge-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const key = path.join(root, 'key.pem'), cert = path.join(root, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=chain.internal', '-addext', 'subjectAltName=DNS:chain.internal,IP:127.0.0.1',
    '-keyout', key, '-out', cert], { stdio: 'ignore' });
  const certificate = await readFile(cert);
  const fingerprint = createHash('sha256').update(new X509Certificate(certificate).raw).digest('hex');
  const received = [];
  const connections = [];
  const gateway = https.createServer({ key: await readFile(key), cert: certificate }, async (request, response) => {
    if (request.url === '/health') { response.writeHead(200, observations ? { 'X-Zark-Observation': '1' } : {}); response.end(); return; }
    if (request.url === '/assets/test.bin') { response.writeHead(200, { 'Content-Length': '6' }); response.end('public'); return; }
    if (request.url.startsWith('/assets/')) { response.writeHead(404); response.end(); return; }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received.push(Buffer.concat(chunks).toString('utf8'));
    const body = JSON.stringify({ result: { chain: 'signet' }, error: null, id: 1 });
    response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    response.end(body);
  });
  gateway.on('secureConnection', socket => connections.push(socket));
  await new Promise(resolve => gateway.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => {
    gateway.close(resolve);
    for (const socket of connections) socket.destroy();
  }));
  const directory = path.join(root, 'bridge');
  await mkdir(directory, { mode: 0o700 });
  const cookie = path.join(directory, '.cookie');
  await writeFile(cookie, `__cookie__:${'a'.repeat(48)}\n`, { mode: 0o600 });
  const config = { version: 1, port: await unusedPort(), cookie_file: cookie,
    address: `127.0.0.1:${gateway.address().port}`, server_name: 'chain.internal', certificate_sha256: fingerprint };
  const configFile = path.join(directory, 'bridge.json');
  await writeFile(configFile, JSON.stringify(config), { mode: 0o600 });
  return { root, cert, config, configFile, received, certificate, fingerprint, gateway, connections };
}

test('bridge authenticates gateway TLS and local cookie before forwarding Core RPC', async t => {
  const f = await fixture(t);
  const bridge = await startBridge(f.configFile, f.cert);
  t.after(() => new Promise(resolve => bridge.close(resolve)));
  const body = JSON.stringify({ method: 'getblockchaininfo', params: [], id: 1 });
  async function send(authorization) {
    return await new Promise((resolve, reject) => {
      const request = http.request({ host: '127.0.0.1', port: f.config.port, method: 'POST',
        headers: { Authorization: authorization, 'Content-Length': Buffer.byteLength(body) } }, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }));
      });
      request.on('error', reject);
      request.end(body);
    });
  }
  assert.equal((await send('Basic wrong')).status, 401);
  assert.deepEqual(f.received, []);
  const auth = `Basic ${Buffer.from(`__cookie__:${'a'.repeat(48)}`).toString('base64')}`;
  const result = await send(auth);
  assert.equal(result.status, 200);
  assert.equal(JSON.parse(result.body).result.chain, 'signet');
  assert.deepEqual(f.received, [body]);
  assert.equal((await send(auth)).status, 200);
  assert.deepEqual(f.received, [body, body]);
  assert.equal(f.connections.length, 1, 'health check and sequential RPCs share authenticated TLS');
});

test('bridge advertises only authenticated observation support and forwards exact requests', async t => {
  const f = await fixture(t, true);
  const bridge = await startBridge(f.configFile, f.cert);
  t.after(() => new Promise(resolve => bridge.close(resolve)));
  const auth = `Basic ${Buffer.from(`__cookie__:${'a'.repeat(48)}`).toString('base64')}`;
  async function rpc(method, params) {
    const body = JSON.stringify({ method, params, id: 1 });
    return new Promise((resolve, reject) => {
      const request = http.request({ host: '127.0.0.1', port: f.config.port, method: 'POST',
        headers: { Authorization: auth, 'Content-Length': Buffer.byteLength(body) } }, response => {
        const chunks = []; response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => resolve(JSON.parse(Buffer.concat(chunks))));
      });
      request.on('error', reject); request.end(body);
    });
  }
  assert.equal((await rpc('getblockchaininfo', [])).result.zark_observation_version, 1);
  const params = ['1', '66'.repeat(32), '0', '77'.repeat(32), '0'];
  const result = await rpc('zark_observe', params);
  assert.equal(result.result.zark_observation_version, undefined);
  assert.deepEqual(JSON.parse(f.received[1]).params, params);
  assert.equal(f.connections.length, 1);
});

test('bridge answers a prepare locally and advertises it without an observation gateway', async t => {
  const f = await fixture(t);
  const bridge = await startBridge(f.configFile, f.cert);
  t.after(() => new Promise(resolve => bridge.close(resolve)));
  const auth = `Basic ${Buffer.from(`__cookie__:${'a'.repeat(48)}`).toString('base64')}`;
  async function rpc(method, authorization = auth) {
    const body = JSON.stringify({ method, params: [], id: 7 });
    return new Promise((resolve, reject) => {
      const request = http.request({ host: '127.0.0.1', port: f.config.port, method: 'POST',
        headers: { Authorization: authorization, 'Content-Length': Buffer.byteLength(body) } }, response => {
        const chunks = []; response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }));
      });
      request.on('error', reject); request.end(body);
    });
  }
  assert.equal((await rpc('zark_prepare', 'Basic wrong')).status, 401);
  assert.deepEqual(JSON.parse((await rpc('zark_prepare')).body), { result: true, error: null, id: 7 });
  const info = JSON.parse((await rpc('getblockchaininfo')).body).result;
  assert.equal(info.zark_prepare_version, 1);
  assert.equal(info.zark_observation_version, undefined);
  assert.deepEqual(f.received.map(body => JSON.parse(body).method), ['getblockchaininfo']);
});

test('gateway client adopts one prepared connection for the next request', async t => {
  const f = await fixture(t);
  const client = createGatewayClient(f.config, f.certificate);
  t.after(() => client.close());
  assert.equal(client.prepare(), true);
  assert.equal(client.prepare(), false, 'one prepared connection at a time');
  while (f.connections.length === 0) await new Promise(resolve => setTimeout(resolve, 5));
  const body = Buffer.from('{"method":"getblockchaininfo","params":[]}');
  assert.equal((await client.request(body, 'POST')).status, 200);
  assert.equal(f.connections.length, 1);
  assert.deepEqual(f.received, [body.toString()]);
  assert.equal(client.prepare(), false, 'an idle pooled connection is already open');
  assert.equal((await client.request(body, 'POST')).status, 200);
  assert.equal(f.connections.length, 1);
});

test('prepared gateway connections authenticate their peer and expire unused', async t => {
  const trusted = await fixture(t);
  const other = await fixture(t);
  const wrong = createGatewayClient({ ...trusted.config, address: other.config.address }, trusted.certificate);
  t.after(() => wrong.close());
  assert.equal(wrong.prepare(), true);
  await assert.rejects(wrong.request(Buffer.from('{"method":"getblockchaininfo","params":[]}'), 'POST'));
  assert.deepEqual(other.received, []);
  const client = createGatewayClient(trusted.config, trusted.certificate);
  t.after(() => client.close());
  assert.equal(client.prepare(50), true);
  while (trusted.connections.length === 0) await new Promise(resolve => setTimeout(resolve, 5));
  await new Promise(resolve => trusted.connections[0].once('close', resolve));
  assert.equal((await client.request(undefined, 'GET', '/health')).status, 200);
  assert.equal(trusted.connections.length, 2, 'an expired preparation is never adopted');
  const closing = createGatewayClient(trusted.config, trusted.certificate);
  assert.equal(closing.prepare(), true);
  while (trusted.connections.length === 2) await new Promise(resolve => setTimeout(resolve, 5));
  closing.close();
  await new Promise(resolve => trusted.connections[2].once('close', resolve));
  assert.equal(closing.prepare(), false);
});

test('gateway client pins its endpoint and closes its pool', async t => {
  const f = await fixture(t);
  const client = createGatewayClient(f.config, f.certificate);
  t.after(() => client.close());
  await client.request(undefined, 'GET', '/health');
  f.config.address = '127.0.0.1:1';
  f.config.certificate_sha256 = '00'.repeat(32);
  assert.equal((await client.request(undefined, 'GET', '/health')).status, 200);
  assert.equal(f.connections.length, 1);
  client.close();
  await assert.rejects(client.request(undefined, 'GET', '/health'), /closed/);
});

test('gateway client authenticates the actual TLS peer before sending an RPC', async t => {
  const trusted = await fixture(t);
  const other = await fixture(t);
  const client = createGatewayClient({ ...trusted.config, address: other.config.address }, trusted.certificate);
  t.after(() => client.close());
  await assert.rejects(client.request(Buffer.from('{"method":"getblockchaininfo","params":[]}'), 'POST'));
  assert.deepEqual(other.received, []);
});

test('gateway client does not automatically replay an RPC with an uncertain response', async t => {
  const f = await fixture(t);
  let requests = 0;
  f.gateway.removeAllListeners('request');
  f.gateway.on('request', async (request, response) => {
    for await (const _ of request) { /* Consume the request before dropping its reply. */ }
    requests++;
    response.destroy();
  });
  const client = createGatewayClient(f.config, f.certificate);
  t.after(() => client.close());
  await assert.rejects(client.request(Buffer.from('{"method":"sendrawtransaction","params":[]}'), 'POST'));
  assert.equal(requests, 1);
});

test('bridge rejects a changed gateway certificate pin before listening', async t => {
  const f = await fixture(t);
  f.config.certificate_sha256 = '00'.repeat(32);
  await writeFile(f.configFile, JSON.stringify(f.config));
  await assert.rejects(startBridge(f.configFile, f.cert), /certificate pin mismatch/);
});

test('public asset downloader verifies the pinned source hash', async t => {
  const f = await fixture(t);
  const connection = { host: '127.0.0.1', port: f.gateway.address().port, certificate: f.certificate,
    service: { chain_server_name: 'chain.internal', chain_certificate_sha256: f.fingerprint } };
  const correct = createHash('sha256').update('public').digest('hex');
  const downloaded = await downloadPublicAsset({ path: 'test.bin', sha256: correct }, f.root, connection);
  assert.equal((await readFile(downloaded)).toString(), 'public');
  await assert.rejects(downloadPublicAsset({ path: 'test.bin', sha256: '00'.repeat(32) }, f.root, connection), /hash mismatch/);
  await assert.rejects(downloadPublicAsset({ path: 'absent.bin', sha256: correct }, f.root, connection), /unavailable/);
});
