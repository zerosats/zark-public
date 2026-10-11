/** HTTP relay compatibility transport, retained for draining and isolated tests. */
import { randomBytes } from 'node:crypto';
import { MessagingClient, RelayError, addressHash, digest, newToken, token, id, mailboxHash } from './messaging-client.mjs';
export { RelayError, addressHash } from './messaging-client.mjs';

export class RelayClient extends MessagingClient {
  constructor(baseUrl = 'http://127.0.0.1:7449', { timeoutMs = 15_000, maxResponseBytes = 32 * 1024 * 1024, fetchImpl = globalThis.fetch } = {}) {
    super();
    const url = new URL(baseUrl);
    const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Relay URL must be an HTTPS origin or loopback HTTP origin');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0) throw new Error('Invalid relay client limits');
    this.baseUrl = url.origin; this.timeoutMs = timeoutMs; this.maxResponseBytes = maxResponseBytes; this.fetchImpl = fetchImpl;
  }
  async request(method, route, { body, bearer } = {}) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (bearer !== undefined) headers.Authorization = `Bearer ${token(bearer)}`;
    const response = await this.fetchImpl(`${this.baseUrl}${route}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs) });
    const chunks = []; let bytes = 0;
    for await (const chunk of response.body) {
      bytes += chunk.byteLength;
      if (bytes > this.maxResponseBytes) throw new Error('Relay response exceeds byte limit');
      chunks.push(chunk);
    }
    let result;
    try { result = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new Error('Relay returned invalid JSON'); }
    if (!response.ok) throw new RelayError(response.status, result.error?.code ?? 'relay_error', result.error?.message ?? 'Relay request failed');
    return result;
  }
  async createMailbox(receiveAddress, { token: chosenToken = newToken(), ttlMs } = {}) {
    const key = addressHash(receiveAddress); token(chosenToken);
    const result = await this.request('POST', '/v1/mailboxes', { body: { addressHash: key, readTokenHash: digest(chosenToken), ttlMs } });
    const record = { ...result, token: chosenToken }; this.mailboxes.set(key, record); return record;
  }
  async send(addressOrHash, { id: messageId = randomBytes(16).toString('hex'), kind = 'offer', payload, ttlMs }) {
    return this.request('POST', `/v1/mailboxes/${mailboxHash(addressOrHash)}/messages`, { body: { id: id(messageId), kind, payload, ttlMs } });
  }
  async poll(mailbox) {
    const { messages } = await this.request('GET', `/v1/mailboxes/${mailboxHash(mailbox.addressHash)}/messages`, { bearer: mailbox.token }); return messages;
  }
}
