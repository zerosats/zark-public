// Wallet UI state. A port of the macOS WalletModel and the Swift views' form
// rules; the runtime and the Rust wallet remain the authority for every action.

export function initialModel() {
  return {
    snapshot: { totalSat: 0, coins: [], offers: [], approvals: null, activity: [], connected: false },
    busy: false,
    error: null,
    progress: '',
    receiveAddress: '',
    receiveKind: 'zark',
    receivePhase: 'address',
    receiveAmountSat: null,
    receiveSource: 'external',
    // Current test sats grant; zero when the faucet is unavailable.
    faucetAmountSat: 0,
    // False until the first wallet snapshot; a packaged app may still be setting up.
    loaded: false,
  };
}

const EVENT_FIELDS = ['progress', 'receiveAddress', 'receiveKind', 'receivePhase', 'receiveAmountSat', 'receiveSource', 'faucetAmountSat'];

/** Applies one runtime event. A reply decides its action's outcome. */
export function applyEvent(model, event, isReply) {
  if (event.snapshot) { model.snapshot = event.snapshot; model.loaded = true; }
  for (const field of EVENT_FIELDS) if (event[field] !== undefined && event[field] !== null) model[field] = event[field];
  // An older background error must not turn a committed send into an apparent failure.
  if (isReply) model.error = event.error ?? null;
  else if (event.error) model.error = event.error;
}

export function applyShellError(model, message) {
  model.error = message;
  model.busy = false;
  model.progress = '';
}

export function beginAction(model, action) {
  model.busy = true;
  model.error = null;
  model.progress = action === 'refresh' ? '' : 'Working…';
}

export function endAction(model) {
  model.busy = false;
  model.progress = '';
}

export const sats = amount => Number(amount ?? 0).toLocaleString();

export const spendableCoins = coins => coins.filter(coin => coin.status === 'available');

export function activityState(state) {
  switch (state) {
    case 'offer': return 'Ready to receive';
    case 'failed': case 'retry': return 'Needs attention';
    case 'pending': case 'processing': return 'Pending';
    default: return null;
  }
}

/** Swift `Int64(text.trimmed)`: optional sign and digits only. */
export function parseInteger(text) {
  const clean = String(text).trim();
  if (!/^[+-]?\d{1,19}$/.test(clean)) return null;
  const value = Number(clean);
  return Number.isSafeInteger(value) ? value : null;
}

export function sendValidity({ kind, address, coin, fee }) {
  const cleanAddress = address.trim();
  if (!coin || !cleanAddress) return false;
  if (kind === 'zark') return true;
  const feeSat = parseInteger(fee);
  return cleanAddress.startsWith('tb1p') && feeSat !== null && feeSat > 0 && feeSat <= 10_000 && feeSat + 330 < coin.amountSat;
}

export function sendRequest({ kind, address, coinID, fee }) {
  const args = { coin: coinID, address: address.trim() };
  if (kind === 'bitcoin') args.feeSat = String(parseInteger(fee) ?? 0);
  return { action: kind === 'bitcoin' ? 'withdraw' : 'send', args };
}

export const MAX_SWAP_COINS = 5;

export function toggleSwapCoin(selection, id, enabled) {
  const next = new Set(selection);
  if (enabled && next.size < MAX_SWAP_COINS) next.add(id);
  else if (!enabled) next.delete(id);
  return next;
}

export function swapSelection(coins, selection) {
  const selected = coins.filter(coin => selection.has(coin.id));
  const total = selected.reduce((sum, coin) => sum + coin.amountSat, 0);
  const valid = selected.length > 0 && selected.length <= MAX_SWAP_COINS && selected.length === selection.size;
  return { selected, total, valid };
}

/** The Receive sheet's view of the shared receive state for one tab. */
export function receiveView(model, kind) {
  const same = model.receiveKind === kind;
  const phase = same ? model.receivePhase : 'address';
  const fromFaucet = model.receiveSource === 'faucet';
  let step = phase;
  if (kind === 'bitcoin' && fromFaucet && ['creating', 'awaiting_funding', 'ready'].includes(phase)) step = 'resume';
  else if (!['broadcast', 'awaiting_funding', 'ready'].includes(phase)) step = 'start';
  return { address: same ? model.receiveAddress : '', phase, step, fromFaucet };
}

export const showTestSatsCard = (model, preview) =>
  model.snapshot.activity.length === 0 && model.snapshot.totalSat === 0 && model.faucetAmountSat > 0 && !preview;
