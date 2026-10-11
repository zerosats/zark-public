import path from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { Store, readPrivate } from './storage.mjs';
import { LegacySwap } from './legacy-swap.mjs';
import { MultiSwap, SWAP_VERSION } from './multi-swap.mjs';
import { RejectedMessage } from './message-errors.mjs';
import { amount } from './wallet/validation.mjs';
import { createDeposit, importDeposit, broadcastDeposit, claimTestSats, faucetOffer, depositView } from './deposit-workflow.mjs';
import { acceptCoinOffer } from './incoming-offer.mjs';
import { timed, timing } from './timing.mjs';

const identifier = () => randomBytes(16).toString('hex');
const secret = () => randomBytes(32).toString('hex');
export function safeError(error) {
  if (error?.code === 'worker_unavailable') return 'Restart the wallet, then retry the saved operation.';
  if (error?.code === 'legacy_mailbox') return 'This wallet needs the legacy relay migration before connecting. See the desktop setup instructions.';
  const message = String(error?.message ?? 'Wallet operation failed');
  if (error?.code === 'invalid_address') return 'Check the receiving address';
  if (error?.code === 'faucet') return message;
  if (error?.code === 'signer_unauthorized' || message === 'Signer authorization required') return 'Signer authorization required';
  if (error?.code === 'amount_mismatch' || message === 'Coin amount does not match') return 'Coin amount does not match';
  if (error?.code === 'awaiting_confirmation') return 'Waiting for a Bitcoin confirmation. Your saved action will retry.';
  if (/unauthorized/i.test(message)) return 'Signer authorization required';
  if (/fetch failed|ECONN|timeout|unavailable/i.test(message)) return 'Connection unavailable. Retry.';
  if (/expected.*amount|amount.*match/i.test(message)) return 'Coin amount does not match';
  // Never render arbitrary peer messages, CLI stderr, file contents or tokens.
  const allowed = ['Invalid amount', 'Coin unavailable', 'Offer unavailable', 'Wallet operation failed', 'Swap already started', 'No pending deposit', 'Transaction does not fund this deposit', 'Ambiguous deposit output', 'Signed transaction required', 'Finish the pending deposit first'];
  return allowed.includes(message) ? message : 'Action failed. Retry the saved operation.';
}
/** Coordinates existing CLI operations; the Rust wallet remains the authority. */
export class Controller {
  constructor({ wallet, relay, home, emit = () => {}, decodeTransaction, faucet }) {
    this.wallet = wallet; this.relay = relay; this.home = home; this.emit = emit; this.faucet = faucet;
    this.store = new Store(path.join(home, '.desktop-gui'));
    this.decodeTransaction = decodeTransaction;
    this.tail = Promise.resolve(); this.online = false; this.waiting = 0;
    this.offers = [];
    this.multiSwap = new MultiSwap(this);
    this.legacySwap = new LegacySwap(this);
  }
  async initialize() {
    this.state = await this.store.load();
    if (this.state.version !== 1) throw new Error('Unsupported desktop state');
    this.state.deliveries ??= [];
    for (const box of this.state.invitations) if (box.mailbox && !box.retired) this.relay.useMailbox(box.mailbox);
  }
  save() { return this.store.save(this.state); }
  serial(fn) { const result = this.tail.then(fn); this.tail = result.catch(() => {}); return result; }
  async checkAddress(address, kind) {
    let result;
    // validate-address is a local check, so any failure means the address is bad.
    try { result = await this.wallet.validateAddress(address); }
    catch (error) { error.code = 'invalid_address'; throw error; }
    if (result.valid !== true || result.kind !== kind) {
      const error = new Error('Check the receiving address'); error.code = 'invalid_address'; throw error;
    }
  }
  async coin(id) {
    const view = await this.wallet.snapshot();
    const item = view.coins.find(c => c.id === id && ['available', 'owned', 'ready'].includes(c.status));
    if (!item || this.state.swaps.some(s => (s.coin === id || [...(s.coins ?? []), ...(s.peerCoins ?? [])].some(c => c.id === id)) && !['cancelled', 'complete'].includes(s.phase)) || this.state.tasks.some(t => ['send', 'withdraw'].includes(t.kind) && t.coin === id && t.phase !== 'complete')) throw new Error('Coin unavailable');
    return item;
  }
  async invitation(id = identifier()) {
    let record = this.state.invitations.find(x => x.id === id);
    if (!record) {
      const address = await this.wallet.newAddress();
      record = { id, address: address.address, invitationPath: address.invitationPath, token: secret() };
      this.state.invitations.push(record); await this.save();
    }
    if (!record.mailbox) {
      record.mailbox = await this.relay.createMailbox(record.address, { token: record.token, invitationPath: record.invitationPath });
      await this.save();
    }
    return record;
  }
  async action(action, args = {}) {
    // A queued user action makes background polling stop at its next step.
    this.waiting++;
    const queued = performance.now();
    return this.serial(async () => {
      this.waiting--;
      timing('action_queue', performance.now() - queued);
      if (['send', 'withdraw'].includes(action) && this.state.tasks.length >= 1024) throw new Error('Desktop task history is full');
      switch (action) {
        case 'refresh': {
          await this.poll();
          await this.emitFaucetOffer();
          break;
        }
        case 'receive': {
          if (args.kind === 'bitcoin') {
            await this.emitFaucetOffer();
            if (this.state.deposit && this.state.deposit.phase !== 'broadcast') this.depositView();
            else this.emit({ receiveKind: 'bitcoin', receiveAddress: '', receivePhase: 'address' });
            break;
          }
          const previous = this.state.invitations.find(x => x.id === this.state.receiveId && !x.used && !x.retired);
          if (previous?.mailbox && (!Number.isSafeInteger(previous.mailbox.expiresAt) || previous.mailbox.expiresAt <= Date.now())) {
            previous.retired = true;
            await this.save();
          }
          const box = await this.invitation(previous?.retired ? undefined : previous?.id);
          this.state.receiveId = box.id; await this.save();
          this.emit({ receiveKind: 'zark', receiveAddress: box.address, receivePhase: 'address' }); break;
        }
        case 'send': {
          await this.checkAddress(args.address, 'zark');
          const coin = await this.coin(args.coin);
          const task = { id: identifier(), kind: 'send', coin: coin.id, amountSat: coin.amountSat, address: args.address, phase: 'draft' };
          this.state.tasks.push(task); await this.save(); await this.runTask(task); break;
        }
        case 'withdraw': {
          await this.checkAddress(args.address, 'bitcoin');
          const coin = await this.coin(args.coin);
          const feeSat = amount(args.feeSat);
          if (feeSat >= coin.amountSat) throw new Error('Invalid amount');
          const task = { id: identifier(), kind: 'withdraw', coin: coin.id, amountSat: coin.amountSat - feeSat, address: args.address, feeSat, phase: 'draft' };
          this.state.tasks.push(task); await this.save(); await this.runTask(task); break;
        }
        case 'accept': {
          const task = this.state.tasks.find(t => t.id === args.operation && t.kind === 'receive' && t.phase === 'offer');
          if (!task) throw new Error('Offer unavailable');
          task.phase = 'accepting'; await this.save(); await this.runTask(task); break;
        }
        case 'retry': {
          const task = this.state.tasks.find(t => t.id === args.operation);
          if (!task) throw new Error('Offer unavailable');
          task.error = null; task.due = 0; await this.runTask(task); break;
        }
        case 'swapPublish': await this.multiSwap.start(args.coins); break;
        case 'swapJoin': await this.multiSwap.start(args.coins, args.offer); break;
        case 'swapCancel': {
          const swap = this.state.swaps.find(s => s.offerId === args.offer && s.role === 'maker');
          if (!swap || swap.phase !== 'open') throw new Error('Swap already started');
          await this.relay.cancelOffer(swap.offerId, swap.token);
          swap.phase = 'cancelled'; await this.save(); break;
        }
        case 'swapApprove': await this.multiSwap.approve(args.swap); break;
        case 'deposit': await createDeposit(this, args); break;
        case 'depositImport': await importDeposit(this, args); break;
        case 'depositBroadcast': await broadcastDeposit(this); break;
        case 'testSats': await claimTestSats(this); break;
        default: throw new Error('Unknown action');
      }
      // The polling loop refreshes the public swap board. A completed send or
      // receive must not wait for an unrelated relay query before rendering.
      await this.render({ refreshOffers: !['send', 'accept'].includes(action) });
    });
  }
  depositView() { depositView(this); }
  async emitFaucetOffer() {
    const offer = await faucetOffer(this);
    this.emit({ faucetAmountSat: offer?.available ? offer.amountSat : 0 });
  }
  async sendOnce(address, message) {
    const digest = createHash('sha256').update(JSON.stringify({ address, kind: message.kind, payload: message.payload })).digest('hex');
    const prior = this.state.deliveries.find(record => record.id === message.id && record.address === address);
    if (prior && prior.digest !== digest) throw new Error('Frozen outbound message differs');
    if (!prior) {
      if (this.state.deliveries.length >= 4096) throw new Error('Desktop delivery history is full');
      this.state.deliveries.push({ id: message.id, address, digest }); await this.save();
    }
    try { return await this.relay.send(address, message); }
    catch (error) { if (error.code !== 'message_replayed') throw error; }
  }
  async progressSwap(swap) {
    return swap.version === SWAP_VERSION ? this.multiSwap.progress(swap) : this.legacySwap.progressSwap(swap);
  }
  async deliver(result, address, amountSat, extra, id) {
    const bytes = await readPrivate(result.offerPath, 2_000_000);
    await timed('mailbox_delivery', () => this.sendOnce(address, { id, kind: 'coin', payload: { coin: result.coin, transferOperation: result.transferOperation, amountSat, envelope: bytes.toString('base64'), ...extra } }));
  }
  async runTask(task) {
    this.emit({ progress: 'Proving…' });
    // Establish authenticated transport while the native wallet proves. The
    // preparation sends only health; delivery still follows durable handover.
    let delivery;
    try { if (task.kind === 'send' && task.phase === 'draft') delivery = this.relay.prepareDelivery?.(); }
    catch { /* Preparation is optional; the durable delivery still authenticates TLS. */ }
    try {
      if (task.kind === 'send') {
        if (!task.result) { task.result = await this.wallet.send({ coin: task.coin, address: task.address }); await this.save(); }
        if (task.phase === 'draft') {
          await this.deliver(task.result, task.address, task.amountSat, {}, task.id);
          task.phase = 'pending'; task.error = null; await this.save();
          // Delivery is durable; the interactive receive happens separately.
          // The existing pending-task loop checks retirement after acceptance.
          return;
        }
        if ((await this.wallet.complete(task.result.operationPath)).completed) task.phase = 'complete';
      } else if (task.kind === 'withdraw') {
        if (!task.result) { task.result = await this.wallet.withdraw({ coin: task.coin, address: task.address, feeSat: task.feeSat }); await this.save(); }
        const result = await this.wallet.advance(task.result.operationPath, { broadcast: true });
        task.phase = result.waiting ? 'pending' : 'complete';
      } else if (task.kind === 'receive' && task.phase !== 'offer' && task.phase !== 'rejected') {
        const box = this.state.invitations.find(b => b.id === task.invitationId);
        if (!box || (box.used && box.used !== task.messageKey)) { task.phase = 'rejected'; task.error = null; return; }
        const result = task.result
          ? await this.wallet.advance(task.result.operationPath)
          : await this.wallet.accept({ ...task.parameters, expectedAmountSat: task.amountSat });
        task.result = result;
        // A successful native receive has verified and reserved this invitation.
        box.used = task.messageKey;
        task.phase = result.accepted ? 'complete' : 'pending';
      }
      task.error = null;
    } catch (e) { task.error = safeError(e); throw e; }
    finally { delivery?.close(); task.due = Date.now() + 15000; await this.save(); this.emit({ progress: '' }); }
  }
  async message(box, message) {
    const key = `${box.id}:${message.id}`;
    if (this.state.seen.includes(key)) return;
    const p = message.payload;
    if (!p || typeof p !== 'object' || Array.isArray(p)) throw new RejectedMessage('Invalid message');
    if (message.kind === 'swap2') {
      await this.multiSwap.message(box, message);
    } else if (['swap-intent', 'swap-manifest'].includes(message.kind)) {
      await this.legacySwap.message(box, message);
    } else if (message.kind === 'coin') {
      await acceptCoinOffer(this, box, message, key);
    } else { throw new RejectedMessage('Unknown message'); }
    if (this.state.seen.length >= 8192) throw new Error('Desktop message history is full');
    this.state.seen.push(key); await this.save();
  }
  async poll() {
    // Each step below is durable and retried by a later tick, so background
    // work may stop between steps whenever a user action is queued.
    try { await this.relay.health(); this.online = true; } catch { this.online = false; }
    for (const box of this.online ? this.state.invitations : []) {
      if (this.waiting) break;
      if (!box.mailbox || box.retired) continue;
      const messages = await this.relay.poll(box.mailbox).catch(() => []);
      for (const message of messages) {
        if (this.waiting) break;
        try { await this.message(box, message); await this.relay.ack(box.mailbox, message.id); }
        catch (error) {
          if (error instanceof RejectedMessage) {
            // Malformed public metadata cannot occupy the mailbox indefinitely.
            // Network/storage/native failures stay queued for durable retry.
            await this.relay.ack(box.mailbox, message.id).catch(() => {});
          }
        }
      }
    }
    for (const swap of this.state.swaps) {
      if (this.waiting) break;
      if (swap.due > Date.now()) continue;
      try { await this.progressSwap(swap); swap.error = null; }
      catch (e) { swap.error = safeError(e); }
      swap.due = Date.now() + 15000;
    }
    for (const task of this.state.tasks) {
      if (this.waiting) break;
      if (['offer', 'complete', 'rejected'].includes(task.phase) || task.due > Date.now()) continue;
      if (!this.online && task.kind === 'send' && task.phase === 'draft') continue;
      try { await this.runTask(task); } catch { /* durable retry; projected into activity */ }
    }
    await this.save();
  }
  tick() {
    return this.serial(() => timed('poll_tick', async () => {
      try {
        await this.poll();
        // The queued action renders when it completes.
        if (!this.waiting) await this.render();
      } finally { this.relay.releaseIdle?.(); }
    }));
  }
  async render({ refreshOffers = true } = {}) {
    const local = await this.wallet.snapshot();
    const locked = new Set(this.state.swaps.filter(s => !['complete', 'cancelled'].includes(s.phase)).flatMap(s => s.coins ? [...s.coins, ...(s.peerCoins ?? [])].map(c => c.id) : [s.coin]));
    const coins = local.coins.map(c => ({ id: c.id, amountSat: c.amountSat, ownerOperation: c.ownerOperation ?? c.operationPath, status: locked.has(c.id) ? 'pending' : c.status }));
    if (refreshOffers) this.offers = await this.relay.listOffers().catch(() => []);
    const offers = this.offers;
    const activity = this.state.tasks.map(t => ({ id: t.id, label: ({ send: 'Send', receive: 'Receive', withdraw: 'Bitcoin' })[t.kind], amountSat: t.amountSat, state: t.error ? 'retry' : t.phase }));
    for (const deposit of this.state.deposits ?? []) activity.push({ id: deposit.id, label: deposit.source === 'faucet' ? 'Test sats' : 'Deposit', amountSat: deposit.amountSat, state: 'complete' });
    for (const swap of this.state.swaps) activity.push({ id: swap.id, label: 'Swap', amountSat: swap.amountSat, state: swap.error ? 'pending' : swap.phase === 'complete' ? 'complete' : 'pending' });
    const approvals = this.state.swaps.filter(s => s.version === SWAP_VERSION && s.phase === 'approval').map(s => ({ id: s.id, outgoingCount: s.coins.length, incomingCount: s.peerCoins.length, amountSat: s.amountSat }));
    this.emit({ snapshot: { totalSat: coins.reduce((n, c) => n + c.amountSat, 0), coins, offers: offers.filter(o => o.swapVersion === SWAP_VERSION).map(o => ({ id: o.id, amountSat: o.amountSat, own: this.state.swaps.some(s => s.offerId === o.id && s.role === 'maker') })), approvals, activity: activity.reverse().slice(0, 30), connected: this.online } });
  }
}
