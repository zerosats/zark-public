// Webview entry: bridges the Tauri shell to the views and owns sheet presentation.
import { initialModel, applyEvent, applyShellError, beginAction, endAction } from './model.js';
import { h, icon, feedback } from './components.js';
import { walletView } from './views/wallet.js';
import { sendSheet, sendState } from './views/send.js';
import { receiveSheet, receiveState, receiveLoad } from './views/receive.js';
import { swapSheet, swapState } from './views/swap.js';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const SHEETS = {
  send: { create: sendState, render: sendSheet },
  receive: { create: receiveState, render: receiveSheet, onOpen: receiveLoad },
  swap: { create: swapState, render: swapSheet },
};

const root = document.getElementById('app');

const app = {
  model: initialModel(),
  info: { preview: false, platform: '' },
  running: true,
  lastTiming: '',
  sheet: null,
  sheetState: null,

  async perform(action, args = {}) {
    if (app.model.busy || !app.running) return;
    const started = performance.now();
    beginAction(app.model, action);
    app.render();
    try { await invoke('perform', { action, args }); }
    finally {
      if (!['refresh', 'receive'].includes(action)) {
        const name = ({ testSats: 'Claim test sats', send: 'Send', accept: 'Accept', withdraw: 'Withdraw' })[action] || action;
        app.lastTiming = `${name}: ${((performance.now() - started) / 1000).toFixed(2)} s · ${app.model.error ? 'failed' : 'finished'}`;
      }
      endAction(app.model); app.render();
    }
  },

  openSheet(kind) {
    if (app.model.busy) return;
    app.sheet = kind;
    app.sheetState = SHEETS[kind].create();
    app.render();
    SHEETS[kind].onOpen?.(app);
  },

  closeSheet() {
    if (app.model.busy) return;
    app.sheet = null;
    app.sheetState = null;
    app.render();
  },

  async importTransaction() {
    if (app.model.busy || !app.running) return;
    const transactionPath = await invoke('pick_transaction');
    if (transactionPath) await app.perform('depositImport', { transactionPath });
  },

  async qr(value) {
    const svg = await invoke('qr_svg', { value });
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  },

  async copy(text) {
    try { await navigator.clipboard.writeText(text); }
    catch {
      // Older WebKitGTK builds lack the async clipboard API.
      const area = h('textarea', { value: text, class: 'offscreen' });
      document.body.append(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
  },

  render() {
    // Re-rendering replaces the tree; keep focus, caret and scroll positions.
    const focus = focusedControl();
    const scrolls = new Map([...root.querySelectorAll('[data-key]')].map(node => [node.dataset.key, node.scrollTop]));

    const children = [walletView(app)];
    if (app.sheet) {
      // Like a native sheet, the page behind an open dialog takes no focus or clicks.
      children[0].inert = true;
      children.push(modal(SHEETS[app.sheet].render(app)));
    }
    root.replaceChildren(...children);
    document.body.classList.toggle('modal-open', Boolean(app.sheet));

    for (const [key, top] of scrolls) {
      const node = root.querySelector(`[data-key="${CSS.escape(key)}"]`);
      if (node) node.scrollTop = top;
    }
    restoreFocus(focus);
  },
};

const label = node => node.getAttribute('aria-label') ?? node.textContent;

/** Identifies the focused control by key, or by position and label when it has none. */
function focusedControl() {
  const node = document.activeElement;
  if (!node || node === document.body || !root.contains(node)) return null;
  const path = [];
  for (let child = node; child !== root; child = child.parentElement) path.unshift([...child.parentElement.children].indexOf(child));
  return { key: node.dataset.key, path, tag: node.tagName, label: label(node),
    caret: typeof node.selectionStart === 'number' ? [node.selectionStart, node.selectionEnd] : null };
}

function restoreFocus(focus) {
  if (!focus) return;
  let node;
  if (focus.key) node = root.querySelector(`[data-key="${CSS.escape(focus.key)}"]`);
  else {
    node = focus.path.reduce((parent, index) => parent?.children[index], root);
    // Only the same control in the same place: a changed layout drops focus instead of moving it.
    if (node?.tagName !== focus.tag || label(node) !== focus.label) node = null;
  }
  if (!node || node.disabled) return;
  node.focus({ preventScroll: true });
  if (focus.caret && typeof node.setSelectionRange === 'function') node.setSelectionRange(...focus.caret);
}

function modal({ title, content }) {
  const busy = app.model.busy;
  const close = h('button', {
    class: 'close-button', type: 'button', disabled: busy, 'aria-label': 'Close', onClick: () => app.closeSheet(),
  }, icon('close', 12));
  // A disabled fieldset disables every control in the sheet body while busy.
  const body = h('fieldset', { class: 'sheet-body', disabled: busy }, content);
  return h('div', { class: 'overlay' },
    h('section', { class: 'sheet', key: 'sheet', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'sheet-header' }, h('h2', { class: 'title2', text: title }), h('div', { class: 'spacer' }), close),
      body,
      feedback(app.model)));
}

document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && app.sheet) {
    event.preventDefault();
    app.closeSheet();
  }
});

async function start() {
  app.info = await invoke('app_info');
  document.body.classList.add(`platform-${app.info.platform}`);
  await listen('wallet', async ({ payload }) => {
    if (payload.error) {
      applyShellError(app.model, payload.error);
      app.running = await invoke('is_running');
    } else {
      // Most background polls change nothing; skip rebuilding the page for them.
      const before = JSON.stringify(app.model);
      applyEvent(app.model, payload.event, payload.isReply);
      if (JSON.stringify(app.model) === before) return;
    }
    app.render();
  });
  app.render();
  await invoke('start');
  if (app.info.previewScreen && SHEETS[app.info.previewScreen]) app.openSheet(app.info.previewScreen);
  await app.perform('refresh');
}

start();
