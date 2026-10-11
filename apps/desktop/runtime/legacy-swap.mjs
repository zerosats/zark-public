import path from 'node:path';
import { writePrivateImmutable, readPrivate } from './storage.mjs';
import { RejectedMessage } from './message-errors.mjs';

const HEX = /^[a-f0-9]{64}$/;
function publicIntent(draft) {
  if (!draft || !HEX.test(draft.coin) || typeof draft.context !== 'string' || !/^[a-f0-9]{474}$/.test(draft.context) || !draft.context.startsWith('0a000000') || draft.context.slice(72, 136) !== draft.coin || !Number.isSafeInteger(draft.revision) || draft.revision < 1) throw new RejectedMessage('Invalid swap intent');
  const bytes = Buffer.from(draft.context, 'hex');
  if (bytes.readBigUInt64LE(196) !== BigInt(draft.revision) || bytes.subarray(204).some(byte => byte !== 0)) throw new RejectedMessage('Invalid swap intent');
  return { coin: draft.coin, context: draft.context, revision: draft.revision };
}
function digestBytes(value) {
  if (!Array.isArray(value) || value.length !== 32 || !value.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) throw new RejectedMessage('Invalid manifest digest');
  const hex = Buffer.from(value).toString('hex');
  if (/^0+$/.test(hex)) throw new RejectedMessage('Empty manifest digest');
  return hex;
}
function validateManifest(manifest, own, peer) {
  own = publicIntent(own); peer = publicIntent(peer);
  if (!manifest || !Array.isArray(manifest.members) || manifest.members.length !== 2 || !Number.isSafeInteger(manifest.expires_at) || manifest.expires_at <= Math.floor(Date.now() / 1000) || manifest.expires_at > Math.floor(Date.now() / 1000) + 86400) throw new RejectedMessage('Invalid manifest');
  if (Object.keys(manifest).length !== 4 || !Object.keys(manifest).every(key => ['id', 'deployment', 'expires_at', 'members'].includes(key))) throw new RejectedMessage('Unexpected manifest field');
  digestBytes(manifest.id);
  const deployment = digestBytes(manifest.deployment);
  if (deployment !== own.context.slice(8, 72) || deployment !== peer.context.slice(8, 72) || own.coin === peer.coin) throw new RejectedMessage('Wrong manifest deployment');
  const expected = [own, peer].sort((a, b) => a.coin.localeCompare(b.coin));
  for (let i = 0; i < 2; i++) {
    const member = manifest.members[i], intent = expected[i];
    if (!member || member.revision !== intent.revision) throw new RejectedMessage('Wrong manifest revision');
    if (Object.keys(member).length !== 6 || !Object.keys(member).every(key => ['coin', 'previous_state', 'operation', 'recipient_claim', 'sender_session', 'revision'].includes(key))) throw new RejectedMessage('Unexpected member field');
    for (const [field, offset] of [['coin', 36], ['previous_state', 68], ['operation', 100], ['recipient_claim', 132], ['sender_session', 164]]) {
      if (digestBytes(member[field]) !== intent.context.slice(offset * 2, offset * 2 + 64)) throw new RejectedMessage('Wrong manifest member');
    }
  }
  return manifest;
}

// Compatibility for persisted single-coin swaps. New UI actions use MultiSwap.
// Keep this until existing profiles and their pending journals are drained.
export class LegacySwap {
  constructor(controller) { this.controller = controller; }
  async publish(swap) {
    const c = this.controller;
    const box = await c.invitation(swap.id);
    const offer = await c.relay.createOffer({ amountSat: swap.amountSat, receiveAddress: box.address, ownerToken: swap.token });
    swap.offerId = offer.id; swap.offerExpiresAt = offer.expiresAt; swap.phase = offer.status === 'cancelled' ? 'cancelled' : 'open'; await c.save();
  }
  async draft(swap) {
    const c = this.controller;
    if (!swap.draft) {
      c.emit({ progress: 'Proving…' });
      try { swap.draft = await c.wallet.batchDraft({ coin: swap.coin, address: swap.peerAddress }); }
      finally { c.emit({ progress: '' }); }
      await c.save();
    }
    return publicIntent(swap.draft);
  }
  async join(swap) {
    const c = this.controller;
    const box = await c.invitation(swap.id);
    const offer = await c.relay.claimOffer(swap.offerId, { receiveAddress: box.address, token: swap.token });
    if (offer.receiveAddress !== swap.peerAddress || offer.amountSat !== swap.amountSat) throw new Error('Offer unavailable');
    const intent = await this.draft(swap);
    await c.sendOnce(swap.peerAddress, { id: `${swap.id}-intent`, kind: 'swap-intent', payload: { swapId: swap.offerId, address: box.address, intent } });
    swap.phase = 'waiting_manifest'; await c.save();
  }
  async manifestFor(swap, peer) {
    const c = this.controller;
    swap.peer = publicIntent(peer);
    const intent = await this.draft(swap);
    swap.expiresAt ??= Math.floor(Date.now() / 1000) + 14400;
    const file = path.join(c.store.directory, `${swap.id}-peer.json`);
    await writePrivateImmutable(file, JSON.stringify(swap.peer)); await c.save();
    const output = path.join(c.store.directory, `${swap.id}-batch.json`);
    await c.wallet.batchManifest({ first: swap.draft.operationPath, peer: file, expiresAt: swap.expiresAt, output });
    swap.manifestPath = output; swap.phase = 'delivering_manifest'; await c.save();
    const manifest = JSON.parse(await readPrivate(output));
    validateManifest(manifest, intent, swap.peer);
    await this.deliverManifest(swap);
  }
  async deliverManifest(swap) {
    const c = this.controller;
    const manifest = JSON.parse(await readPrivate(swap.manifestPath));
    await c.sendOnce(swap.peerAddress, { id: `${swap.id}-manifest`, kind: 'swap-manifest', payload: { swapId: swap.offerId, intent: publicIntent(swap.draft), manifest } });
    swap.phase = 'joining'; await c.save();
  }
  async progressSwap(swap) {
    const c = this.controller;
    if (['complete', 'cancelled'].includes(swap.phase)) return;
    const expiresAt = swap.expiresAt ? swap.expiresAt * 1000 : swap.offerExpiresAt;
    if (expiresAt && expiresAt <= Date.now()) {
      if (!swap.draft) { swap.phase = 'cancelled'; await c.save(); return; }
      try {
        const aborted = await c.wallet.batchAbort(swap.draft.operationPath);
        if (aborted.aborted === true) {
          swap.phase = 'cancelled';
          for (const task of c.state.tasks) if (task.swapId === swap.id && task.phase !== 'complete') task.phase = 'rejected';
          await c.save(); return;
        }
      } catch { /* A committed batch cannot abort; preserve and resume both journals. */ }
    }
    if (!c.online && ['publishing', 'claiming', 'making_manifest', 'delivering_manifest'].includes(swap.phase)) return;
    if (swap.phase === 'publishing') return this.publish(swap);
    if (swap.phase === 'claiming') return this.join(swap);
    if (swap.phase === 'making_manifest') return this.manifestFor(swap, swap.peer);
    if (swap.phase === 'delivering_manifest') return this.deliverManifest(swap);
    if (!['joining', 'joined', 'delivering_offer', 'waiting_receive'].includes(swap.phase)) return;
    if (swap.outbound) {
      if (!swap.delivered) {
        if (!c.online) return;
        await c.deliver(swap.outbound, swap.peerAddress, swap.amountSat, { swapId: swap.offerId }, `${swap.id}-offer`);
        swap.delivered = true; swap.phase = 'waiting_receive'; await c.save();
      }
      if (!swap.outgoingComplete) {
        swap.outgoingComplete = (await c.wallet.complete(swap.draft.operationPath)).completed === true;
        await c.save();
      }
      if (swap.outgoingComplete && c.state.tasks.some(t => t.swapId === swap.id && t.phase === 'complete')) { swap.phase = 'complete'; await c.save(); }
      return;
    }
    const result = swap.phase === 'joining'
      ? await c.wallet.batchSend({ operationPath: swap.draft.operationPath, manifestPath: swap.manifestPath })
      : await c.wallet.advance(swap.draft.operationPath);
    if (result.offerPath) {
      swap.outbound = result; swap.phase = 'delivering_offer'; await c.save();
      await this.progressSwap(swap);
    } else { swap.phase = 'joined'; }
    await c.save();
  }
  async message(box, message) {
    const c = this.controller, p = message.payload;
    if (message.kind === 'swap-intent') {
      const swap = c.state.swaps.find(s => s.offerId === p.swapId && s.id === box.id && s.role === 'maker');
      if (!swap || !['open', 'making_manifest'].includes(swap.phase)) throw new RejectedMessage('Offer unavailable');
      const remote = await c.relay.getOffer(swap.offerId, swap.token);
      if (remote.status !== 'claimed' || remote.claim?.receiveAddress !== p.address) throw new RejectedMessage('Claim differs');
      const peer = publicIntent(p.intent);
      if (swap.peer && JSON.stringify(peer) !== JSON.stringify(swap.peer)) throw new RejectedMessage('Claim intent differs');
      swap.peerAddress = p.address; swap.peer = peer; swap.phase = 'making_manifest';
      await c.save();
    } else if (message.kind === 'swap-manifest') {
      const swap = c.state.swaps.find(s => s.offerId === p.swapId && s.id === box.id && s.role === 'joiner');
      if (!swap || swap.phase !== 'waiting_manifest') throw new RejectedMessage('Offer unavailable');
      const peer = publicIntent(p.intent);
      // Rust checks the exact own draft/context and deployment before reserving.
      validateManifest(p.manifest, swap.draft, peer);
      const manifestPath = path.join(c.store.directory, `${swap.id}-batch.json`);
      await writePrivateImmutable(manifestPath, JSON.stringify(p.manifest));
      swap.peer = peer; swap.manifestPath = manifestPath; swap.expiresAt = p.manifest.expires_at; swap.phase = 'joining'; await c.save();
    }
  }
}
