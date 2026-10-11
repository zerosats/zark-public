import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { readPrivate, writePrivateImmutable } from './storage.mjs';
import { RejectedMessage } from './message-errors.mjs';

const HEX = /^[a-f0-9]{64}$/;
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const random = () => randomBytes(16).toString('hex');
export const SWAP_VERSION = 2;
export function coinTerms(coins) {
  if (!Array.isArray(coins) || coins.length < 1 || coins.length > 5) throw new RejectedMessage('Invalid swap coins');
  const terms = coins.map(c => {
    if (!c || typeof c.id !== 'string' || !HEX.test(c.id) || !Number.isSafeInteger(c.amountSat) || c.amountSat < 1 || c.amountSat > 2_100_000_000_000_000) throw new RejectedMessage('Invalid swap coins');
    return { id: c.id, amountSat: c.amountSat };
  }).sort((a, b) => a.id.localeCompare(b.id));
  if (new Set(terms.map(c => c.id)).size !== terms.length) throw new RejectedMessage('Duplicate swap coin');
  total(terms);
  return terms;
}
export function total(coins) {
  const value = coins.reduce((sum, c) => sum + c.amountSat, 0);
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_100_000_000_000_000) throw new RejectedMessage('Invalid amount');
  return value;
}
export function intent(draft) {
  if (!draft || typeof draft.coin !== 'string' || !HEX.test(draft.coin) || typeof draft.context !== 'string' || !/^[a-f0-9]{474}$/.test(draft.context) || !draft.context.startsWith('0a000000') || draft.context.slice(72, 136) !== draft.coin || !Number.isSafeInteger(draft.revision) || draft.revision < 1) throw new RejectedMessage('Invalid swap intent');
  const bytes = Buffer.from(draft.context, 'hex');
  if (bytes.readBigUInt64LE(196) !== BigInt(draft.revision) || bytes.subarray(204).some(b => b !== 0)) throw new RejectedMessage('Invalid swap intent');
  return { coin: draft.coin, context: draft.context, revision: draft.revision };
}
function hex(bytes) {
  if (!Array.isArray(bytes) || bytes.length !== 32 || !bytes.every(b => Number.isInteger(b) && b >= 0 && b <= 255)) throw new RejectedMessage('Invalid manifest');
  const value = Buffer.from(bytes).toString('hex');
  if (/^0+$/.test(value)) throw new RejectedMessage('Invalid manifest');
  return value;
}
export function validateGroupManifest(manifest, own, peer) {
  const expected = [...own, ...peer].map(intent).sort((a, b) => a.coin.localeCompare(b.coin));
  if (own.length < 1 || own.length > 5 || peer.length < 1 || peer.length > 5 || new Set(expected.map(d => d.coin)).size !== expected.length) throw new RejectedMessage('Invalid manifest');
  if (!manifest || Object.keys(manifest).sort().join() !== 'deployment,expires_at,id,members' || !Number.isSafeInteger(manifest.expires_at) || !Array.isArray(manifest.members) || manifest.members.length !== expected.length) throw new RejectedMessage('Invalid manifest');
  hex(manifest.id);
  const deployment = hex(manifest.deployment);
  for (let i = 0; i < expected.length; i++) {
    const d = expected[i], m = manifest.members[i];
    if (deployment !== d.context.slice(8, 72) || !m || Object.keys(m).sort().join() !== 'coin,operation,previous_state,recipient_claim,revision,sender_session' || m.revision !== d.revision) throw new RejectedMessage('Invalid manifest member');
    for (const [name, offset] of [['coin', 36], ['previous_state', 68], ['operation', 100], ['recipient_claim', 132], ['sender_session', 164]]) if (hex(m[name]) !== d.context.slice(offset * 2, offset * 2 + 64)) throw new RejectedMessage('Invalid manifest member');
  }
  return manifest;
}
function invitations(values, coins, peerAddress) {
  if (!Array.isArray(values) || values.length !== coins.length || values.some(v => !v || typeof v.coin !== 'string' || !HEX.test(v.coin) || typeof v.address !== 'string')) throw new RejectedMessage('Invalid swap invitations');
  const slots = values.map(v => ({ coin: v.coin, address: v.address })).sort((a, b) => a.coin.localeCompare(b.coin));
  if (new Set(slots.map(v => v.address)).size !== slots.length || slots.some((v, i) => v.coin !== coins[i].id || v.address === peerAddress)) throw new RejectedMessage('Invalid swap invitations');
  return slots;
}
function freeze(record, key, value) {
  if (record[key] !== undefined && JSON.stringify(record[key]) !== JSON.stringify(value)) throw new RejectedMessage('Frozen swap terms differ');
  record[key] = value;
}

/** Private multi-coin negotiation. Native swap-group alone authorizes readiness. */
export class MultiSwap {
  constructor(controller) { this.c = controller; }
  async selected(ids) {
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 5 || new Set(ids).size !== ids.length) throw new Error('Invalid swap coins');
    return coinTerms(await Promise.all(ids.map(id => this.c.coin(id))));
  }
  async start(ids, offerId) {
    const c = this.c, coins = await this.selected(ids), amountSat = total(coins);
    let offer;
    if (offerId) {
      offer = (await c.relay.listOffers()).find(o => o.id === offerId && o.swapVersion === SWAP_VERSION && o.amountSat === amountSat);
      if (!offer) throw new Error('Offer unavailable');
      await c.checkAddress(offer.receiveAddress, 'zark');
    }
    const s = { version: SWAP_VERSION, id: random(), role: offer ? 'joiner' : 'maker', coins, amountSat, phase: offer ? 'claiming' : 'publishing', token: randomBytes(32).toString('hex'), ...(offer ? { offerId, offerExpiresAt: offer.expiresAt, peerAddress: offer.receiveAddress } : {}), drafts: [], outgoing: [], incoming: [] };
    c.state.swaps.push(s); await c.save(); await this.progress(s);
  }
  async send(s, type, payload) {
    const box = this.c.state.invitations.find(b => b.id === s.id);
    const inner = { kind: type.startsWith('coin-') ? 'swap2-coin' : `swap2-${type}`, payload: { swapId: s.offerId, version: SWAP_VERSION, ...payload } };
    s.messages ??= {};
    if (s.messages[type] && s.messages[type].digest !== hash(inner)) throw new Error('Frozen swap message differs');
    if (!s.messages[type]) {
      const { signature } = await this.c.wallet.mailCrypto({ op: 'sign_peer', invitation: box.invitationPath, recipient: s.peerAddress, message: inner });
      s.messages[type] = { digest: hash(inner), signature }; await this.c.save();
    }
    const { signature } = s.messages[type];
    return this.c.sendOnce(s.peerAddress, { id: `${s.id}-${type}`, kind: 'swap2', payload: { address: box.address, signature, message: inner } });
  }
  async slots(s) {
    if (s.slots) return;
    const slots = [];
    for (const coin of s.peerCoins) {
      const box = await this.c.invitation(`${s.id}-receive-${coin.id}`);
      slots.push({ coin: coin.id, address: box.address, invitationPath: box.invitationPath });
    }
    s.slots = slots; await this.c.save();
  }
  publicSlots(s) { return s.slots.map(({ coin, address }) => ({ coin, address })); }
  async peerSlots(s, values) {
    const slots = invitations(values, s.coins, s.peerAddress);
    for (const slot of slots) {
      try { await this.c.checkAddress(slot.address, 'zark'); }
      catch (error) {
        if (error.code === 'invalid_address') throw new RejectedMessage('Invalid swap invitations');
        throw error;
      }
    }
    freeze(s, 'peerSlots', slots);
  }
  peerCoins(s, values) {
    const terms = coinTerms(values);
    if (total(terms) !== s.amountSat || terms.some(t => s.coins.some(c => c.id === t.id))) throw new RejectedMessage('Coin amount does not match');
    freeze(s, 'peerCoins', terms);
  }
  agreement(s) {
    const box = this.c.state.invitations.find(b => b.id === s.id);
    const own = { address: box.address, coins: s.coins, receive: this.publicSlots(s) };
    const peer = { address: s.peerAddress, coins: s.peerCoins, receive: s.peerSlots };
    return { version: SWAP_VERSION, offer: s.offerId, sides: s.role === 'maker' ? [own, peer] : [peer, own] };
  }
  async approve(id) {
    const s = this.c.state.swaps.find(s => s.id === id && s.version === SWAP_VERSION);
    if (!s || s.phase !== 'approval' || !s.peerSlots) throw new RejectedMessage('Offer unavailable');
    s.agreement = this.agreement(s); s.agreementId = hash(s.agreement); s.approved = true; s.phase = 'drafting';
    await this.c.save(); await this.progress(s);
  }
  async message(box, message) {
    const c = this.c, auth = message.payload;
    if (!auth || typeof auth.address !== 'string' || typeof auth.signature !== 'string' || !auth.message || !['swap2-hello', 'swap2-terms', 'swap2-slots', 'swap2-drafts', 'swap2-manifest', 'swap2-coin'].includes(auth.message.kind) || !auth.message.payload || typeof auth.message.payload !== 'object' || Array.isArray(auth.message.payload)) throw new RejectedMessage('Invalid authenticated swap message');
    const verified = await c.wallet.mailCrypto({ op: 'verify_peer', address: auth.address, recipient: box.address, message: auth.message, signature: auth.signature });
    if (verified.verified !== true) throw new RejectedMessage('Invalid peer signature');
    message = auth.message;
    const p = message.payload;
    const s = c.state.swaps.find(s => s.version === SWAP_VERSION && s.id === box.id && s.offerId === p?.swapId);
    if (!s || p.version !== SWAP_VERSION || ['cancelled', 'complete'].includes(s.phase)) throw new RejectedMessage('Offer unavailable');
    if (s.peerAddress && auth.address !== s.peerAddress) throw new RejectedMessage('Wrong swap peer');
    // Reject malformed input even when valid messages of this kind would need
    // to wait for a local prerequisite. Never blanket-catch operational errors.
    if (['swap2-hello', 'swap2-terms'].includes(message.kind)) coinTerms(p.coins);
    if (['swap2-terms', 'swap2-slots'].includes(message.kind)) invitations(p.slots, s.coins, s.peerAddress);
    if (['swap2-drafts', 'swap2-manifest', 'swap2-coin'].includes(message.kind) && (typeof p.agreementId !== 'string' || !HEX.test(p.agreementId))) throw new RejectedMessage('Invalid swap agreement');
    if (message.kind === 'swap2-drafts') {
      if (!Array.isArray(p.drafts) || !p.drafts.length || p.drafts.length > 5) throw new RejectedMessage('Invalid swap drafts');
      p.drafts.forEach(intent);
    }
    if (message.kind === 'swap2-manifest') {
      const m = p.manifest, now = Math.floor(Date.now() / 1000);
      if (!m || Object.keys(m).sort().join() !== 'deployment,expires_at,id,members' || !Number.isSafeInteger(m.expires_at) || m.expires_at <= now || m.expires_at > now + 86400 || !Array.isArray(m.members) || m.members.length < 2 || m.members.length > 10) throw new RejectedMessage('Invalid manifest');
      hex(m.id); hex(m.deployment);
      for (const member of m.members) {
        if (!member || Object.keys(member).sort().join() !== 'coin,operation,previous_state,recipient_claim,revision,sender_session' || !Number.isSafeInteger(member.revision) || member.revision < 1) throw new RejectedMessage('Invalid manifest member');
        for (const key of ['coin', 'operation', 'previous_state', 'recipient_claim', 'sender_session']) hex(member[key]);
      }
    }
    if (message.kind === 'swap2-coin') {
      if (typeof p.coin !== 'string' || !HEX.test(p.coin) || typeof p.transferOperation !== 'string' || !HEX.test(p.transferOperation) || !Number.isSafeInteger(p.amountSat) || p.amountSat <= 0 || typeof p.envelope !== 'string' || !p.envelope.length || p.envelope.length > 2_666_668) throw new RejectedMessage('Invalid swap offer');
      const bytes = Buffer.from(p.envelope, 'base64');
      if (!bytes.length || bytes.length > 2_000_000 || bytes.toString('base64') !== p.envelope) throw new RejectedMessage('Invalid swap envelope');
    }
    if (message.kind === 'swap2-hello') {
      if (s.role !== 'maker') throw new RejectedMessage('Wrong swap role');
      const remote = await c.relay.getOffer(s.offerId, s.token);
      if (remote.swapVersion !== SWAP_VERSION || remote.status !== 'claimed' || remote.claim?.receiveAddress !== p.address || p.address !== auth.address) throw new RejectedMessage('Wrong swap claimant');
      freeze(s, 'peerAddress', p.address); this.peerCoins(s, p.coins); await this.slots(s);
      if (s.phase === 'open') s.phase = 'negotiating';
      await c.save();
    } else if (message.kind === 'swap2-terms') {
      if (s.role !== 'joiner') throw new RejectedMessage('Wrong swap role');
      this.peerCoins(s, p.coins); await this.peerSlots(s, p.slots); await this.slots(s);
      if (!s.approved) s.phase = 'approval'; await c.save();
    } else if (message.kind === 'swap2-slots') {
      if (s.role !== 'maker') throw new RejectedMessage('Wrong swap role');
      if (!s.peerCoins) throw new Error('Swap terms not ready');
      await this.peerSlots(s, p.slots); if (!s.approved) s.phase = 'approval'; await c.save();
    } else if (message.kind === 'swap2-drafts') {
      if (!s.slots || !s.peerSlots) throw new Error('Swap agreement not ready');
      if (p.agreementId !== hash(this.agreement(s)) || !Array.isArray(p.drafts) || p.drafts.length !== s.peerCoins.length) throw new RejectedMessage('Wrong swap agreement');
      const drafts = p.drafts.map(intent).sort((a, b) => a.coin.localeCompare(b.coin));
      if (drafts.some((d, i) => d.coin !== s.peerCoins[i].id)) throw new RejectedMessage('Wrong swap members');
      freeze(s, 'peerDrafts', drafts); await c.save();
    } else if (message.kind === 'swap2-manifest') {
      if (s.role !== 'joiner') throw new RejectedMessage('Wrong swap role');
      if (!s.approved || !s.peerDrafts || s.drafts.length !== s.coins.length) throw new Error('Swap agreement not ready');
      if (p.agreementId !== s.agreementId) throw new RejectedMessage('Wrong swap agreement');
      validateGroupManifest(p.manifest, s.drafts, s.peerDrafts);
      const now = Math.floor(Date.now() / 1000);
      if (p.manifest.expires_at <= now || p.manifest.expires_at > now + 86400) throw new RejectedMessage('Invalid manifest expiry');
      const file = path.join(c.store.directory, `${s.id}-batch.json`);
      await writePrivateImmutable(file, JSON.stringify(p.manifest)); s.manifestPath = file; s.expiresAt = p.manifest.expires_at; s.phase = 'joining'; await c.save();
    } else if (message.kind === 'swap2-coin') {
      if (!s.manifestPath) throw new Error('Swap manifest not ready');
      if (p.agreementId !== s.agreementId) throw new RejectedMessage('Wrong swap agreement');
      const peer = s.peerDrafts.find(d => d.coin === p.coin), term = s.peerCoins.find(d => d.id === p.coin);
      if (!peer || p.transferOperation !== peer.context.slice(200, 264) || p.amountSat !== term.amountSat || typeof p.envelope !== 'string' || p.envelope.length > 2_666_668) throw new RejectedMessage('Wrong swap offer');
      const bytes = Buffer.from(p.envelope, 'base64');
      if (!bytes.length || bytes.length > 2_000_000 || bytes.toString('base64') !== p.envelope) throw new RejectedMessage('Invalid swap envelope');
      const file = path.join(c.store.directory, `${s.id}-${p.coin}.offer`);
      await writePrivateImmutable(file, bytes);
      if (!s.incoming.some(v => v.coin === p.coin)) { s.incoming.push({ coin: p.coin, offerPath: file }); await c.save(); }
    } else throw new RejectedMessage('Unknown swap message');
  }
  async progress(s) {
    const c = this.c;
    if (['complete', 'cancelled'].includes(s.phase)) return;
    const expiry = s.expiresAt ? s.expiresAt * 1000 : s.offerExpiresAt;
    if (expiry && expiry <= Date.now()) {
      // A CLI response may have been lost after it persisted a sender guard.
      // Consult the durable adapter intent, not just successful GUI results.
      const pending = s.peerSlots ? await c.wallet.pendingBatchDrafts(s.peerSlots) : [];
      const paths = [...new Set([...s.drafts, ...pending].map(d => d.operationPath))];
      if (!paths.length && !s.groupOperation) { s.phase = 'cancelled'; await c.save(); return; }
      try {
        const results = [];
        if (s.groupOperation) results.push(await c.wallet.swapAbort(s.groupOperation));
        else for (const operation of paths) results.push(await c.wallet.batchAbort(operation));
        if (results.every(r => r.aborted === true)) { s.phase = 'cancelled'; await c.save(); return; }
      } catch { /* A committed or uncertain batch retains every lock and resumes. */ }
    }
    // All delivery is durable before the native group exists. Its recovery must
    // not depend on a still-live mailbox, board advertisement, or peer client.
    if (s.groupPlan) return this.runGroup(s);
    const box = await c.invitation(s.id);
    if (s.phase === 'publishing') {
      const offer = await c.relay.createOffer({ amountSat: s.amountSat, receiveAddress: box.address, ownerToken: s.token, swapVersion: SWAP_VERSION });
      if (offer.swapVersion !== SWAP_VERSION) throw new Error('Unsupported swap offer');
      s.offerId = offer.id; s.offerExpiresAt = offer.expiresAt; s.phase = offer.status === 'cancelled' ? 'cancelled' : 'open'; await c.save(); return;
    }
    if (s.phase === 'claiming') {
      const offer = await c.relay.claimOffer(s.offerId, { receiveAddress: box.address, token: s.token, swapVersion: SWAP_VERSION });
      if (offer.swapVersion !== SWAP_VERSION || offer.receiveAddress !== s.peerAddress || offer.amountSat !== s.amountSat) throw new Error('Offer unavailable');
      await this.send(s, 'hello', { address: box.address, coins: s.coins }); s.phase = 'negotiating'; await c.save();
    }
    if (s.role === 'maker' && s.peerCoins && s.slots) await this.send(s, 'terms', { coins: s.coins, slots: this.publicSlots(s) });
    if (s.role === 'joiner' && s.slots) await this.send(s, 'slots', { slots: this.publicSlots(s) });
    if (!s.approved) return;
    for (const coin of s.coins) {
      if (!s.drafts.some(d => d.coin === coin.id)) {
        const slot = s.peerSlots.find(v => v.coin === coin.id);
        const draft = await c.wallet.batchDraft({ coin: coin.id, address: slot.address });
        intent(draft); s.drafts.push(draft); s.drafts.sort((a, b) => a.coin.localeCompare(b.coin)); await c.save();
      }
    }
    await this.send(s, 'drafts', { agreementId: s.agreementId, drafts: s.drafts.map(intent) });
    if (!s.peerDrafts) return;
    if (!s.manifestPath && s.role === 'maker') {
      s.expiresAt ??= Math.floor(Date.now() / 1000) + 14400; await c.save();
      const peer = path.join(c.store.directory, `${s.id}-peers.json`), output = path.join(c.store.directory, `${s.id}-batch.json`);
      await writePrivateImmutable(peer, JSON.stringify(s.peerDrafts));
      await c.wallet.batchManifestMany({ drafts: s.drafts.map(d => d.operationPath), peer, expiresAt: s.expiresAt, output });
      const manifest = JSON.parse(await readPrivate(output)); validateGroupManifest(manifest, s.drafts, s.peerDrafts);
      s.manifestPath = output; s.phase = 'joining'; await c.save();
    }
    if (!s.manifestPath) return;
    if (s.role === 'maker') await this.send(s, 'manifest', { agreementId: s.agreementId, manifest: JSON.parse(await readPrivate(s.manifestPath)) });
    for (const draft of s.drafts) {
      let leg = s.outgoing.find(o => o.coin === draft.coin);
      if (!leg) { leg = { coin: draft.coin, operationPath: draft.operationPath }; s.outgoing.push(leg); await c.save(); }
      if (!leg.result) {
        const result = leg.joined ? await c.wallet.advance(draft.operationPath) : await c.wallet.batchSend({ operationPath: draft.operationPath, manifestPath: s.manifestPath });
        leg.joined = true;
        if (result.offerPath) leg.result = result;
        await c.save();
      }
      if (leg.result && !leg.delivered) {
        const bytes = await readPrivate(leg.result.offerPath, 2_000_000);
        await this.send(s, `coin-${leg.coin}`, { agreementId: s.agreementId, coin: leg.coin, transferOperation: leg.result.transferOperation, amountSat: s.coins.find(c => c.id === leg.coin).amountSat, envelope: bytes.toString('base64') });
        leg.delivered = true; await c.save();
      }
    }
    if (!s.outgoing.every(o => o.delivered) || s.incoming.length !== s.peerCoins.length) return;
    if (!s.groupPlan) {
      const operation = path.join(c.home, '.desktop', 'operations', `swap-group-${s.id}`);
      const plan = { version: 1, agreement_id: s.agreementId, manifest: s.manifestPath,
        outgoing: s.drafts.map(d => ({ operation: d.operationPath, amount_sat: s.coins.find(v => v.id === d.coin).amountSat })),
        incoming: s.peerDrafts.map(d => ({ operation: path.join(c.home, '.desktop', 'operations', `swap-receive-${s.id}-${d.coin}`), invitation: s.slots.find(v => v.coin === d.coin).invitationPath, offer: s.incoming.find(v => v.coin === d.coin).offerPath, coin: d.coin, transfer_operation: d.context.slice(200, 264), amount_sat: s.peerCoins.find(v => v.id === d.coin).amountSat, recovery_fee: 1000 })) };
      const file = path.join(c.store.directory, `${s.id}-group.json`); await writePrivateImmutable(file, JSON.stringify(plan));
      s.groupPlan = file; s.groupOperation = operation; await c.save();
    }
    return this.runGroup(s);
  }
  async runGroup(s) {
    const c = this.c;
    const result = await c.wallet.swapGroup({ operationPath: s.groupOperation, planPath: s.groupPlan });
    s.groupResult = result;
    // Require exact native result sets; never declare success from one leg.
    const exact = (actual, expected) => Array.isArray(actual) && actual.length === expected.length && new Set(actual.map(v => v.operation)).size === expected.length && actual.every(v => expected.includes(v.operation));
    const incomingPaths = s.peerDrafts.map(d => path.join(c.home, '.desktop', 'operations', `swap-receive-${s.id}-${d.coin}`));
    if (result.completed === true && exact(result.incoming, incomingPaths) && exact(result.outgoing, s.drafts.map(d => d.operationPath)) && result.incoming.every(v => v.accepted && v.recovery_saved) && result.outgoing.every(v => v.completed)) {
      s.phase = 'complete';
      for (const slot of s.slots) { const invite = c.state.invitations.find(b => b.invitationPath === slot.invitationPath); invite.used = `${s.id}:${slot.coin}`; }
    } else s.phase = 'recovering';
    await c.save();
  }
}
