// Each pool belongs to one immutable endpoint and certificate pin. Never share
// sockets across profiles or retry a failed POST: its outcome may be unknown.
import https from 'node:https';
import tls from 'node:tls';
import { createHash, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { timed, timing } from './timing.mjs';

const MAX_RESPONSE = 32 * 1024 * 1024;
const REQUEST_TIMEOUT = 10_000;
// A transfer checks the chain before and after its proof. The idle socket must
// outlive that gap and close before the gateway's 45 s limit can race a reuse.
const IDLE_TIMEOUT = 30_000;
// A receive first reads the chain after its proof, so a prepared connection
// waits as long as an idle pooled one and holds no more gateway threads.
const PREPARED_LIFETIME = IDLE_TIMEOUT;

export function gateway(config) {
  const match = /^(.*):(\d{1,5})$/.exec(config?.address ?? '');
  if (!match || isIP(match[1]) !== 4 || +match[2] < 1 || +match[2] > 65535 ||
      config.server_name !== 'chain.internal' || !/^[0-9a-f]{64}$/.test(config.certificate_sha256)) {
    throw new Error('Invalid chain gateway configuration');
  }
  return { host: match[1], port: +match[2] };
}

function connectOptions(config, certificate) {
  const { host, port } = gateway(config);
  return { host, port, servername: config.server_name, ca: certificate, rejectUnauthorized: true,
    checkServerIdentity: (_, peer) => {
      const error = tls.checkServerIdentity(config.server_name, peer);
      if (error) return error;
      if (!peer.raw || createHash('sha256').update(peer.raw).digest('hex') !== config.certificate_sha256) {
        return new Error('Chain gateway certificate pin mismatch');
      }
    } };
}

function measured(socket) {
  const started = performance.now();
  socket.once('secureConnect', () => timing('chain_gateway_connect', performance.now() - started));
  return socket;
}

// The next request that needs a new socket adopts a prepared one, which was
// authenticated exactly as the agent's own connections are.
class PreparedAgent extends https.Agent {
  prepared = null;
  createConnection(options, callback) {
    const prepared = this.prepared;
    this.prepared = null;
    if (prepared) clearTimeout(prepared.timer);
    if (prepared && !prepared.socket.destroyed) return prepared.socket;
    return measured(super.createConnection(options, callback));
  }
}

function request(connection, agent, body, method, url) {
  return timed('chain_gateway', () => new Promise((resolve, reject) => {
    const request = https.request({ ...connection, path: url, method, agent,
      headers: method === 'POST' ? { 'Content-Type': 'application/json', 'Content-Length': body.length } : {},
      timeout: REQUEST_TIMEOUT }, response => {
        const chunks = []; let size = 0;
        response.on('data', chunk => {
          size += chunk.length;
          if (size > MAX_RESPONSE) { request.destroy(new Error('Chain gateway response too large')); return; }
          chunks.push(chunk);
        });
        response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks),
          observationVersion: response.headers['x-zark-observation'] === '1' ? 1 : 0 }));
        response.on('error', reject);
      });
    request.on('timeout', () => request.destroy(new Error('Chain gateway timeout')));
    request.on('error', reject);
    request.end(body);
  }));
}

/** Keep the one-shot entry point for callers that do not own a client lifetime. */
export function gatewayRequest(config, certificate, body, method, url = '/rpc') {
  return request(connectOptions(config, certificate), false, body, method, url);
}

export function createGatewayClient(config, certificate) {
  const pinned = Object.freeze({ address: config.address, server_name: config.server_name,
    certificate_sha256: config.certificate_sha256 });
  gateway(pinned);
  const ca = Buffer.from(certificate);
  if (createHash('sha256').update(new X509Certificate(ca).raw).digest('hex') !== pinned.certificate_sha256) {
    throw new Error('Public chain certificate pin mismatch');
  }
  // Authentication belongs to this immutable endpoint's pool. Node disables
  // reuse when a custom identity check is supplied only at the request level.
  const connection = connectOptions(pinned, ca);
  const agent = new PreparedAgent({ ...connection, keepAlive: true, maxSockets: 4, maxTotalSockets: 4,
    maxFreeSockets: 2, timeout: IDLE_TIMEOUT,
    // Require normal certificate/pin authentication on every new connection.
    // Reusing an already authenticated socket avoids that handshake entirely.
    maxCachedSessions: 0 });
  let closed = false;
  const discard = () => { agent.prepared?.socket.destroy(); agent.prepared = null; };
  return {
    request(body, method, url = '/rpc') {
      if (closed) return Promise.reject(new Error('Chain gateway client is closed'));
      return request(connection, agent, body, method, url);
    },
    /** Opens the connection for an imminent request unless one is open or opening. */
    prepare(lifetime = PREPARED_LIFETIME) {
      const open = pool => Object.values(pool).some(sockets => sockets.length > 0);
      if (closed || agent.prepared || open(agent.sockets) || open(agent.freeSockets)) return false;
      const socket = measured(tls.connect(connection));
      socket.setNoDelay(true);
      const prepared = { socket, timer: setTimeout(() => { if (agent.prepared === prepared) discard(); }, lifetime) };
      prepared.timer.unref();
      socket.on('error', () => { if (agent.prepared === prepared) { clearTimeout(prepared.timer); discard(); } });
      agent.prepared = prepared;
      return true;
    },
    close() { closed = true; discard(); agent.destroy(); },
  };
}
