/** Native Node client. Credentials stay in local wallet state, never renderer URLs. */
import { createHash, randomBytes } from 'node:crypto';

export const digest = (value) => createHash('sha256').update(value).digest('hex');
export const newToken = () => randomBytes(32).toString('hex');
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const HASH = /^[a-f0-9]{64}$/;
const ADDRESS = /^tzark1[023456789acdefghjklmnpqrstuvwxyz]{164}$/;
export function addressHash(receiveAddress) {
  if (typeof receiveAddress !== 'string' || !ADDRESS.test(receiveAddress)) throw new Error('Expected a canonical test-network receiving address');
  return digest(receiveAddress);
}
export function token(value) {
  if (typeof value !== 'string' || !HASH.test(value)) throw new Error('Expected a 32-byte lowercase hexadecimal token');
  return value;
}
export function id(value) { if (typeof value !== 'string' || !ID.test(value)) throw new Error('Invalid relay identifier'); return value; }
export function mailboxHash(value) {
  if (typeof value === 'string' && HASH.test(value)) return value;
  return addressHash(value);
}
export class RelayError extends Error {
  constructor(status, code, message) { super(message); this.name = 'RelayError'; this.status = status; this.code = code; }
}
// Transport-neutral board and mailbox operations. Subclasses provide request().
export class MessagingClient {
  constructor() { this.mailboxes = new Map(); }
  async health() { return this.request('GET', '/health'); }
  // Restore a locally persisted record when restarting the desktop backend.
  useMailbox(record) {
    if (!record || !HASH.test(record.addressHash)) throw new Error('Invalid mailbox record');
    token(record.token); this.mailboxes.set(record.addressHash, { ...record }); return record;
  }
  async ack(mailbox, messageId) {
    return this.request('DELETE', `/v1/mailboxes/${mailboxHash(mailbox.addressHash)}/messages/${id(messageId)}`, { bearer: mailbox.token });
  }
  async listOffers() { return (await this.request('GET', '/v1/offers')).offers; }
  async createOffer({ amountSat, receiveAddress, mailbox, ownerToken = newToken(), ttlMs, swapVersion = 1 }) {
    const key = addressHash(receiveAddress); token(ownerToken);
    const box = mailbox ?? this.mailboxes.get(key);
    if (box?.addressHash !== key) throw new Error('Register or restore the receiving mailbox before creating an offer');
    const offer = await this.request('POST', '/v1/offers', { bearer: box.token, body: { amountSat, receiveAddress, addressHash: key, ownerTokenHash: digest(ownerToken), ttlMs, swapVersion } });
    return { ...offer, ownerToken };
  }
  async claimOffer(offerId, { receiveAddress, mailbox, token: claimToken = newToken(), swapVersion = 1 }) {
    const key = addressHash(receiveAddress); token(claimToken);
    const box = mailbox ?? this.mailboxes.get(key);
    if (box?.addressHash !== key) throw new Error('Register or restore the receiving mailbox before claiming an offer');
    const offer = await this.request('POST', `/v1/offers/${id(offerId)}/claim`, { bearer: box.token, body: { receiveAddress, addressHash: key, claimTokenHash: digest(claimToken), swapVersion } });
    return { ...offer, claimToken };
  }
  async getOffer(offerId, bearer) { return this.request('GET', `/v1/offers/${id(offerId)}`, { bearer }); }
  async cancelOffer(offerId, ownerToken) { return this.request('DELETE', `/v1/offers/${id(offerId)}`, { bearer: ownerToken }); }
}
