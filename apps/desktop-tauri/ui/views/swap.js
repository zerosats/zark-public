// Swap sheet: publish or join equal-total multi-coin swaps (SwapView.swift).
import { h, button, segmented, amountHero, divider, secondaryText } from '../components.js';
import { sats, spendableCoins, swapSelection, toggleSwapCoin, MAX_SWAP_COINS } from '../model.js';

export function swapState() {
  return { mode: 'offers', coinIDs: new Set(), offerID: null };
}

function selectionList(app, coins, state, summary) {
  return h('div', { class: 'stack-12' },
    h('div', { class: 'row-between' },
      h('div', { class: 'body', text: `Total: ${sats(summary.total)} sats` }),
      h('div', { class: 'body', text: `Coins: ${summary.selected.length}/${MAX_SWAP_COINS}` })),
    h('div', { class: 'coin-list', key: 'swap-coins' }, coins.map(coin => {
      const checked = state.coinIDs.has(coin.id);
      return h('label', { class: 'checkbox' },
        h('input', {
          type: 'checkbox', checked,
          disabled: !checked && state.coinIDs.size >= MAX_SWAP_COINS,
          onChange: event => { state.coinIDs = toggleSwapCoin(state.coinIDs, coin.id, event.target.checked); app.render(); },
        }),
        h('span', { text: `${sats(coin.amountSat)} sats · ${coin.id.slice(0, 8)}` }));
    })));
}

function offerRow(app, state, coins, offer) {
  const control = offer.own
    ? button('Cancel', { outlined: true, compact: true, onClick: () => app.perform('swapCancel', { offer: offer.id }) })
    : button('Join', {
      compact: true, disabled: coins.length === 0,
      onClick: () => { state.coinIDs = new Set(); state.offerID = offer.id; app.render(); },
    });
  return h('div', { class: 'offer-row' },
    h('div', { class: 'body digits', text: `${sats(offer.amountSat)} sats` }), h('div', { class: 'spacer' }), control);
}

export function swapSheet(app) {
  const state = app.sheetState;
  const { snapshot } = app.model;
  const coins = spendableCoins(snapshot.coins);
  // Selected coins that are no longer spendable drop out (`formIntersection`).
  const ids = new Set(coins.map(coin => coin.id));
  state.coinIDs = new Set([...state.coinIDs].filter(id => ids.has(id)));
  const summary = swapSelection(coins, state.coinIDs);
  const offer = snapshot.offers.find(item => item.id === state.offerID);

  const approvals = (snapshot.approvals ?? []).map(approval => [
    h('div', { class: 'stack-12' },
      h('div', { class: 'body', text: `Send: ${approval.outgoingCount} coins · ${sats(approval.amountSat)} sats` }),
      h('div', { class: 'body', text: `Receive: ${approval.incomingCount} coins · ${sats(approval.amountSat)} sats` }),
      button('Approve', { onClick: () => app.perform('swapApprove', { swap: approval.id }) })),
    divider(),
  ]);

  let body;
  if (state.offerID !== null) {
    body = offer ? [
      amountHero(offer.amountSat),
      selectionList(app, coins, state, summary),
      h('div', { class: 'row-12' },
        button('Back', { outlined: true, onClick: () => { state.offerID = null; app.render(); } }),
        button('Swap', {
          disabled: !summary.valid || summary.total !== offer.amountSat,
          onClick: async () => {
            await app.perform('swapJoin', { offer: state.offerID, coins: [...state.coinIDs].sort() });
            if (app.model.error === null) { state.offerID = null; app.render(); }
          },
        })),
    ] : [
      secondaryText('Offer no longer available', 'body'),
      button('Back', { outlined: true, onClick: () => { state.offerID = null; app.render(); } }),
    ];
  } else {
    let tab;
    if (state.mode === 'create') {
      tab = [
        selectionList(app, coins, state, summary),
        button('Publish', {
          disabled: !summary.valid,
          onClick: async () => {
            await app.perform('swapPublish', { coins: [...state.coinIDs].sort() });
            if (app.model.error === null) { state.mode = 'offers'; state.coinIDs = new Set(); app.render(); }
          },
        }),
      ];
    } else if (snapshot.offers.length === 0) {
      tab = h('div', { class: 'no-offers secondary body', text: 'No offers' });
    } else {
      tab = h('div', { class: 'offer-list', key: 'swap-offers' },
        snapshot.offers.map(item => [offerRow(app, state, coins, item), divider()]));
    }
    body = [
      segmented([['offers', 'Offers'], ['create', 'Create']], state.mode, mode => {
        state.mode = mode;
        state.coinIDs = new Set();
        app.render();
      }, 'Swap'),
      tab,
    ];
  }
  return { title: state.offerID === null ? 'Swap' : 'Confirm swap', content: [approvals, body] };
}
