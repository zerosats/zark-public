// Local Bitcoin Core JSON-RPC socket for bitcoin-cli. The upstream TLS peer is
// authenticated before any local credential or transaction body is forwarded.
import http from 'node:http';
import { createHash, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { readPrivate } from './storage.mjs';
import { gateway, createGatewayClient } from './gateway-client.mjs';
export { gatewayRequest } from './gateway-client.mjs';

const MAX_REQUEST = 16 * 1024 * 1024;
function endpoint(config) {
  if (config?.version !== 1 || !Number.isInteger(config.port) || config.port < 1024 || config.port > 65535) {
    throw new Error('Invalid frozen chain bridge configuration');
  }
  return gateway(config);
}

export async function startBridge(configFile, certificateFile) {
  const config = JSON.parse((await readPrivate(configFile, 16_384)).toString('utf8'));
  endpoint(config);
  const certificate = await readFile(certificateFile);
  const fingerprint = createHash('sha256').update(new X509Certificate(certificate).raw).digest('hex');
  if (fingerprint !== config.certificate_sha256) throw new Error('Chain gateway certificate pin mismatch');
  const cookie = await readPrivate(config.cookie_file, 512);
  if (!/^__cookie__:[A-Za-z0-9_-]{40,100}\n?$/.test(cookie.toString('utf8'))) throw new Error('Invalid local Bitcoin RPC cookie');
  const authorization = `Basic ${Buffer.from(cookie.toString('utf8').trim()).toString('base64')}`;
  const client = createGatewayClient(config, certificate);
  let observationVersion = 0;
  try {
    const result = await client.request(undefined, 'GET', '/health');
    if (result.status !== 200) throw new Error('Chain gateway health check failed');
    observationVersion = result.observationVersion;
  } catch (error) { client.close(); throw error; }
  const server = http.createServer(async (request, response) => {
    if (request.method !== 'POST' || request.url !== '/') {
      response.writeHead(404, { 'Content-Length': '0' }); response.end(); return;
    }
    if (request.headers.authorization !== authorization) {
      response.writeHead(401, { 'Content-Length': '0' }); response.end(); return;
    }
    const length = Number(request.headers['content-length']);
    if (!Number.isInteger(length) || length < 1 || length > MAX_REQUEST || request.headers['transfer-encoding']) {
      response.writeHead(413, { 'Content-Length': '0', Connection: 'close' }); response.end(); return;
    }
    try {
      const chunks = []; let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > length) throw new Error('Invalid local RPC request size');
        chunks.push(chunk);
      }
      if (size !== length) throw new Error('Incomplete local RPC request');
      const body = Buffer.concat(chunks);
      let call = null;
      try { call = JSON.parse(body); } catch { /* The gateway rejects it unchanged. */ }
      // Only opens the gateway connection for an imminent read. Nothing is
      // forwarded, and no chain state is answered locally.
      if (call?.method === 'zark_prepare') {
        client.prepare();
        const reply = Buffer.from(JSON.stringify({ result: true, error: null, id: call.id ?? null }));
        response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': reply.length });
        response.end(reply);
        return;
      }
      const result = await client.request(body, 'POST');
      // Advertise only this bridge's and its authenticated gateway's capabilities.
      // This is never a cached chain answer; the Core result above remains fresh.
      if (result.status === 200 && call?.method === 'getblockchaininfo') {
        const reply = JSON.parse(result.body);
        if (reply.error == null && reply.result && typeof reply.result === 'object' && !Array.isArray(reply.result)) {
          if (observationVersion === 1) reply.result.zark_observation_version = 1;
          reply.result.zark_prepare_version = 1;
          result.body = Buffer.from(JSON.stringify(reply));
        }
      }
      response.writeHead(result.status, { 'Content-Type': 'application/json', 'Content-Length': result.body.length });
      response.end(result.body);
    } catch {
      response.writeHead(502, { 'Content-Length': '0', Connection: 'close' }); response.end();
    }
  });
  server.once('close', () => client.close());
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.port, '127.0.0.1', resolve);
    });
    return server;
  } catch (error) { client.close(); server.close(); throw error; }
}
