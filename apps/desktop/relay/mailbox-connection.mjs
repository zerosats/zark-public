// Bounded TLS frames shared by one-shot requests and an action's prepared
// delivery. Never replay a frame after handing any bytes to the socket.
import tls from 'node:tls';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { RelayError } from './messaging-client.mjs';
import { timed } from '../runtime/timing.mjs';

export const MAIL_ALPN = 'zark-mail/1';
export const MAIL_SESSION_ALPN = 'zark-mail/1-session';
export const MAIL_LIMIT = 3_000_000;
const timeout = () => new RelayError(503, 'timeout', 'Signer messaging timed out; retry the saved message.');
const remaining = deadline => Math.max(1, Math.ceil(deadline - performance.now()));

class Connection {
  constructor(socket) {
    this.socket = socket; this.pending = null; this.closed = false; this.received = false;
    socket.on('error', () => this.close(new Error('Signer messaging connection failed')));
    socket.on('end', () => this.close(new Error('Incomplete messaging response')));
    socket.on('close', () => this.close(new Error('Messaging connection closed')));
    socket.on('data', chunk => this.data(chunk));
  }
  close(error = new Error('Messaging connection closed')) {
    this.closed = true; this.socket.destroy();
    if (this.pending) {
      const pending = this.pending; this.pending = null;
      clearTimeout(pending.timer); pending.reject(error);
    }
  }
  data(chunk) {
    const pending = this.pending;
    if (!pending) { this.close(new Error('Unexpected messaging response')); return; }
    this.received = true;
    pending.size += chunk.length;
    if (pending.size > MAIL_LIMIT) { this.close(new Error('Messaging response exceeds byte limit')); return; }
    pending.chunks.push(chunk);
    if (!chunk.includes(10)) return;
    const all = Buffer.concat(pending.chunks);
    if (all.indexOf(10) !== all.length - 1) { this.close(new Error('Invalid messaging framing')); return; }
    this.pending = null; clearTimeout(pending.timer);
    pending.resolve(all.subarray(0, -1));
  }
  exchange(bytes, deadline) {
    return timed('mailbox_exchange', () => new Promise((resolve, reject) => {
      if (this.closed || this.pending || deadline <= performance.now()) { reject(timeout()); return; }
      this.received = false;
      this.socket.ref();
      this.pending = { resolve, reject, size: 0, chunks: [], timer: setTimeout(() => this.close(timeout()), remaining(deadline)) };
      try { this.socket.write(bytes); }
      catch { this.close(new Error('Signer messaging connection failed')); }
    }));
  }
}

export function connectMailbox(endpoint, deadline, onSocket = () => {}) {
  return timed('mailbox_connect', async () => {
    const ca = await readFile(endpoint.ca_certificate);
    if (deadline <= performance.now()) throw timeout();
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host: endpoint.host, port: endpoint.port,
        servername: endpoint.server_name, ca, rejectUnauthorized: true,
        minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
        ALPNProtocols: [MAIL_SESSION_ALPN, MAIL_ALPN] });
      socket.setNoDelay(true);
      let finished = false;
      const fail = error => {
        if (finished) return;
        finished = true; clearTimeout(timer); socket.destroy(); reject(error);
      };
      const timer = setTimeout(() => fail(timeout()), remaining(deadline));
      socket.once('error', () => fail(new Error('Signer messaging connection failed')));
      socket.once('close', () => fail(new Error('Messaging connection closed')));
      onSocket(socket);
      socket.once('secureConnect', () => {
        const certificate = socket.getPeerCertificate();
        if (!socket.authorized || ![MAIL_ALPN, MAIL_SESSION_ALPN].includes(socket.alpnProtocol) ||
            !certificate.raw || createHash('sha256').update(certificate.raw).digest('hex') !== endpoint.certificate_sha256) {
          fail(new Error('Signer messaging TLS authentication failed')); return;
        }
        finished = true; clearTimeout(timer); resolve(new Connection(socket));
      });
    });
  });
}

export class DeliveryPreparation {
  constructor(endpoint, timeoutMs, ttlMs = 20_000) {
    this.closed = false; this.connection = null; this.socket = null;
    // The server's idle expiry is 30 seconds. An expired preparation is discarded
    // BEFORE delivery starts; failures after a delivery write are never retried.
    this.timer = setTimeout(() => this.close(), ttlMs); this.timer.unref();
    this.ready = this.warm(endpoint, performance.now() + timeoutMs).catch(() => { this.close(); return null; });
  }
  async warm(endpoint, deadline) {
    const connection = await connectMailbox(endpoint, deadline, socket => {
      this.socket = socket;
      if (this.closed) socket.destroy();
    });
    this.connection = connection;
    if (this.closed) { connection.close(); return null; }
    if (connection.socket.alpnProtocol !== MAIL_SESSION_ALPN) { this.close(); return null; }
    // Only this public health request precedes durable handover. It moves the
    // socket into the server's bounded idle pool instead of occupying ingress.
    const bytes = Buffer.from('{"version":1,"method":"GET","path":"/health","body":null}\n');
    const reply = JSON.parse((await connection.exchange(bytes, deadline)).toString('utf8'));
    if (reply.ok !== true || reply.result?.service !== 'zark-mail' || reply.result?.version !== 1 || reply.error) {
      throw new Error('Invalid messaging health response');
    }
    if (this.closed || connection.closed) { this.close(); return null; }
    connection.socket.unref();
    return connection;
  }
  async take() {
    const connection = await this.ready;
    if (this.closed || !connection || connection.closed) { this.close(); return null; }
    clearTimeout(this.timer); this.closed = true; this.connection = null; this.socket = null;
    return connection;
  }
  close() {
    this.closed = true; clearTimeout(this.timer);
    this.connection?.close(); this.socket?.destroy();
  }
}
