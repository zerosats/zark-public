/** Hosted mailbox/board client: same pinned TLS endpoint as signing, separate ALPN. */
import { createHash } from 'node:crypto';
import { MessagingClient, RelayError, addressHash } from './messaging-client.mjs';
import { connectMailbox, DeliveryPreparation, MAIL_ALPN as ALPN, MAIL_LIMIT as LIMIT, MAIL_SESSION_ALPN } from './mailbox-connection.mjs';

const HASH = /^[a-f0-9]{64}$/;
const IDLE_MS = 1_000;
const ACK = /^\/v1\/mailboxes\/[a-f0-9]{64}\/messages\/[A-Za-z0-9_-]{1,128}$/;
const idempotent = (method, route) => method === 'GET' || (method === 'DELETE' && ACK.test(route));
const digest = value => createHash('sha256').update(value).digest('hex');
const CODES = new Set(['unauthorized', 'mailbox_not_found', 'mailbox_expired', 'mailbox_exists', 'message_replayed', 'message_conflict', 'offer_not_found', 'offer_expired', 'offer_terms_conflict', 'offer_claimed', 'offer_unavailable', 'address_in_use', 'storage_quota', 'storage_fault', 'invalid_request', 'overloaded', 'timeout']);

export class SignerRelayClient extends MessagingClient {
  constructor(endpoint, wallet, { timeoutMs = 15_000 } = {}) {
    super();
    if (!endpoint || !HASH.test(endpoint.certificate_sha256 ?? '') || !endpoint.server_name || !endpoint.ca_certificate) throw new Error('Invalid signer messaging endpoint');
    const match = /^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/.exec(endpoint.address);
    if (!match || Number(match[3]) < 1 || Number(match[3]) > 65535) throw new Error('Invalid signer messaging address');
    this.endpoint = Object.freeze({ ...endpoint, host: match[1] ?? match[2], port: Number(match[3]) });
    this.host = this.endpoint.host; this.port = this.endpoint.port;
    this.wallet = wallet; this.timeoutMs = timeoutMs;
    this.prepared = null; this.idle = null; this.idleTimer = null;
  }
  prepareDelivery() {
    this.prepared?.close();
    const prepared = new DeliveryPreparation(this.endpoint, this.timeoutMs);
    this.prepared = prepared;
    return prepared;
  }
  async request(method, route, { body = null, bearer } = {}, prepared) {
    if (bearer !== undefined && !HASH.test(bearer)) throw new Error('Invalid messaging token');
    const bytes = Buffer.from(`${JSON.stringify({ version: 1, method, path: route, ...(bearer === undefined ? {} : { bearer }), body })}\n`);
    if (bytes.length > LIMIT) throw new Error('Messaging request exceeds byte limit');
    const deadline = performance.now() + this.timeoutMs;
    const repeatable = !prepared && idempotent(method, route);
    let connection, reply;
    try {
      const idle = repeatable ? this.takeIdle() : null;
      if (idle) {
        try { reply = await idle.exchange(bytes, deadline); connection = idle; }
        catch (error) {
          idle.close();
          // A parked session can be closed by the server as this frame is
          // written. Only an idempotent request with no reply bytes is resent.
          if (idle.received || deadline <= performance.now()) throw error;
        }
      }
      if (!reply) {
        connection = await prepared?.take() ?? await connectMailbox(this.endpoint, deadline);
        reply = await connection.exchange(bytes, deadline);
      }
      let response;
      try { response = JSON.parse(reply.toString('utf8')); }
      catch { throw new Error('Invalid messaging response'); }
      if (repeatable) { this.keepIdle(connection); connection = null; }
      if (response?.ok === true && response.result && !response.error) return response.result;
      if (response?.ok !== false || response.result) throw new Error('Invalid messaging response');
      const code = CODES.has(response.error?.code) ? response.error.code : 'remote_rejected';
      throw new RelayError(400, code, `Signer messaging request failed (${code})`);
    } finally { bytes.fill(0); connection?.close(); prepared?.close(); }
  }
  // One parked session at most, closed soon after a burst of background
  // requests: the server's idle pool is small and shared with signing.
  keepIdle(connection) {
    if (connection.closed || connection.socket.alpnProtocol !== MAIL_SESSION_ALPN || this.idle) { connection.close(); return; }
    connection.socket.unref();
    this.idle = connection;
    this.idleTimer = setTimeout(() => this.releaseIdle(), IDLE_MS); this.idleTimer.unref();
  }
  takeIdle() {
    const connection = this.idle; this.idle = null; clearTimeout(this.idleTimer);
    if (!connection?.closed) return connection;
    return null;
  }
  releaseIdle() { this.takeIdle()?.close(); }
  async createMailbox(receiveAddress, { token, invitationPath, ttlMs = 604_800_000 } = {}) {
    if (!HASH.test(token ?? '') || !invitationPath) throw new Error('Mailbox registration requires a local invitation');
    const registration = await this.wallet.mailCrypto({ op: 'register', invitation: invitationPath, token_hash: digest(token), ttl: ttlMs });
    const record = await this.request('POST', '/v1/mailboxes', { body: { receiveAddress, readTokenHash: digest(token), ttlMs, signature: registration.signature } });
    if (record.addressHash !== addressHash(receiveAddress)) throw new Error('Mailbox response mismatch');
    const saved = { ...record, token, transport: ALPN, invitationPath };
    this.useMailbox(saved); return saved;
  }
  useMailbox(record) {
    if (record?.transport !== ALPN || !record.invitationPath) throw Object.assign(new Error('Legacy relay mailbox: drain the old relay before upgrading; create a fresh receiving address'), { code: 'legacy_mailbox' });
    return super.useMailbox(record);
  }
  async send(address, message) {
    // Stable ciphertext and opaque delivery ID survive retries/restarts. No coin,
    // amount, logical operation ID, message kind or swap manifest is public here.
    const prepared = this.prepared; this.prepared = null;
    try {
      const sealed = await this.wallet.sealDelivery(address, message);
      return await this.request('POST', `/v1/mailboxes/${addressHash(address)}/messages`, { body: sealed }, prepared);
    } finally { prepared?.close(); }
  }
  async poll(mailbox) {
    const result = await this.request('GET', `/v1/mailboxes/${mailbox.addressHash}/messages`, { bearer: mailbox.token });
    if (!Array.isArray(result.messages) || result.messages.length > 32) throw new Error('Invalid mailbox response');
    const messages = [];
    for (const wire of result.messages) {
      if (!HASH.test(wire.id ?? '') || typeof wire.ciphertext !== 'string') throw new Error('Invalid encrypted message');
      try {
        const { message } = await this.wallet.mailCrypto({ op: 'open', invitation: mailbox.invitationPath, id: wire.id, ciphertext: wire.ciphertext });
        if (!message || typeof message.kind !== 'string' || !message.payload || typeof message.payload !== 'object' || Array.isArray(message.payload)) throw Object.assign(new Error('Invalid private message'), { code: 'invalid_message' });
        messages.push({ id: wire.id, kind: message.kind, payload: message.payload });
      } catch (error) {
        // Only a definitive authenticated-decryption failure may be discarded.
        // Local process/configuration failures retain the message for retry.
        if (error.code !== 'invalid_message') throw error;
        await this.ack(mailbox, wire.id);
      }
    }
    return messages;
  }
}
