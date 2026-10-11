// Shared visual components; the webview counterpart of WalletComponents.swift.
// Text is always assigned as text, never parsed as markup.
import { sats } from './model.js';

export function h(tag, props = {}, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (name === 'class') element.className = value;
    else if (name === 'text') element.textContent = value;
    else if (name === 'key') element.dataset.key = value;
    else if (name.startsWith('on')) element.addEventListener(name.slice(2).toLowerCase(), value);
    else if (name in element && name !== 'list') element[name] = value;
    else element.setAttribute(name, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) if (child !== null && child !== undefined && child !== false) element.append(child);
  return element;
}

const SVG = 'http://www.w3.org/2000/svg';
const ICONS = {
  refresh: ['M13.5 8a5.5 5.5 0 1 1-1.6-3.9', 'M12.2 1.8v2.6H9.6'],
  send: ['M4 12 12 4', 'M5.5 4H12v6.5'],
  receive: ['M12 4 4 12', 'M4 5.5V12h6.5'],
  swap: ['M2.5 5.5h11', 'M5.5 2.5l-3 3 3 3', 'M13.5 10.5h-11', 'M10.5 7.5l3 3-3 3'],
  close: ['M4 4l8 8M12 4l-8 8'],
};

export function icon(name, size = 16) {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('aria-hidden', 'true');
  svg.classList.add('icon');
  for (const d of ICONS[name]) {
    const path = document.createElementNS(SVG, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

export function button(label, { outlined = false, compact = false, disabled = false, onClick, key, extra } = {}) {
  const classes = ['wallet-button', outlined && 'outlined', compact && 'compact', extra].filter(Boolean).join(' ');
  return h('button', { class: classes, disabled, onClick, key, type: 'button' }, label);
}

export function field(label, content) {
  return h('div', { class: 'field' }, h('div', { class: 'caption secondary', text: label }), content);
}

export function textInput({ key, value, placeholder, onInput, disabled }) {
  return h('input', {
    class: 'text-input', key, value, placeholder, disabled, type: 'text',
    autocomplete: 'off', autocorrect: 'off', autocapitalize: 'off', spellcheck: false,
    onInput: event => onInput(event.target.value),
  });
}

/** Segmented control: `options` is a list of [value, label]. */
export function segmented(options, selected, onSelect, label) {
  return h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': label },
    options.map(([value, text]) => h('button', {
      type: 'button', role: 'radio', class: value === selected ? 'segment selected' : 'segment',
      'aria-checked': value === selected ? 'true' : 'false', text,
      onClick: () => { if (value !== selected) onSelect(value); },
    })));
}

export function feedback(model) {
  if (model.busy) {
    return h('div', { class: 'feedback', role: 'status' },
      h('span', { class: 'spinner', 'aria-hidden': 'true' }),
      model.progress ? h('span', { class: 'caption secondary', text: model.progress }) : null);
  }
  if (model.error) return h('div', { class: 'error callout selectable', text: model.error, role: 'alert' });
  return null;
}

export function coinPicker(coins, selection, onSelect) {
  const content = coins.length === 0
    ? h('div', { class: 'secondary empty-coins', text: 'No coins available' })
    : h('div', { class: 'coin-picker' }, h('select', {
      key: 'coin', 'aria-label': 'Coin', onChange: event => onSelect(event.target.value),
    }, coins.map(coin => h('option', {
      value: coin.id, selected: coin.id === selection, text: `${sats(coin.amountSat)} sats · ${coin.id.slice(-6)}`,
    }))));
  return field('Coin', content);
}

export function amountHero(amount) {
  return h('div', { class: 'amount-hero', text: `${sats(amount)} sats` });
}

export function detail(label, value) {
  return field(label, h('div', { class: 'detail selectable', text: value }));
}

export function divider() {
  return h('div', { class: 'divider', role: 'separator' });
}

export function secondaryText(text, className = 'callout') {
  return h('p', { class: `${className} secondary`, text });
}
