// Wallet overview and activity list (WalletView.swift).
import { h, icon, button, feedback, divider } from '../components.js';
import { sats, activityState, showTestSatsCard } from '../model.js';
import { testSatsCard } from './receive.js';

function action(label, iconName, onClick) {
  return h('button', { class: 'wallet-button action', type: 'button', onClick }, icon(iconName), h('span', { text: label }));
}

function activityRow(app, item) {
  const state = activityState(item.state);
  let control = null;
  if (item.state === 'offer') {
    control = button('Accept', { compact: true, disabled: app.model.busy, onClick: () => app.perform('accept', { operation: item.id }) });
  } else if (['failed', 'retry'].includes(item.state)) {
    control = button('Retry', { compact: true, disabled: app.model.busy, onClick: () => app.perform('retry', { operation: item.id }) });
  }
  return h('div', { class: 'activity-row' },
    h('div', { class: 'activity-label' },
      h('div', { class: 'body', text: item.label }),
      state ? h('div', { class: 'caption secondary', text: state }) : null),
    h('div', { class: 'spacer' }),
    h('div', { class: 'body digits', text: `${sats(item.amountSat)} sats` }),
    control);
}

export function walletView(app) {
  const { model, info } = app;
  const busy = model.busy;
  const header = h('div', { class: 'header' },
    h('div', { class: 'brand', text: info.preview ? 'Zark · Preview' : 'Zark' }),
    h('div', { class: 'badge caption', text: 'MutinyNet', title: 'Bitcoin test network. These sats have no real value.' }),
    h('div', { class: 'spacer' }),
    model.snapshot.connected || !model.loaded ? null : h('div', { class: 'caption secondary', text: 'Offline' }),
    h('button', {
      class: 'icon-button', type: 'button', disabled: busy, title: 'Refresh', 'aria-label': 'Refresh',
      onClick: () => app.perform('refresh'),
    }, icon('refresh')));

  const total = h('div', { class: 'total' },
    h('div', { class: 'subheadline secondary', text: 'Total' }),
    h('div', { class: 'balance-line' },
      h('div', { class: 'balance digits', text: sats(model.snapshot.totalSat) }),
      h('div', { class: 'title3 secondary', text: 'sats' })));

  const actions = h('div', { class: 'actions' + (busy ? ' disabled' : '') },
    action('Send', 'send', () => app.openSheet('send')),
    action('Receive', 'receive', () => app.openSheet('receive')),
    action('Swap', 'swap', () => app.openSheet('swap')));
  for (const control of actions.querySelectorAll('button')) control.disabled = busy;

  const review = (model.snapshot.approvals ?? []).length
    ? button('Review swap', { outlined: true, disabled: busy, extra: 'review', onClick: () => app.openSheet('swap') })
    : null;

  let lower;
  if (model.snapshot.activity.length) {
    lower = [
      h('div', { class: 'subheadline secondary activity-title', text: 'Activity' }),
      h('div', { class: 'activity', key: 'activity-scroll' },
        model.snapshot.activity.map(item => [activityRow(app, item), divider()])),
    ];
  } else if (showTestSatsCard(model, info.preview)) {
    lower = h('div', { class: 'home-card' }, testSatsCard(app, busy));
  } else {
    lower = null;
  }

  return h('main', { class: 'wallet' },
    header, total, actions, review,
    h('div', { class: 'caption digits', text: app.lastTiming || '' }),
    app.sheet ? null : h('div', { class: 'home-feedback' }, feedback(model)),
    h('div', { class: 'divider section-divider' }),
    lower);
}
