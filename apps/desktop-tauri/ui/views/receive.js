// Receive sheet: Zark addresses and Bitcoin deposits (ReceiveView.swift).
import { h, button, field, textInput, segmented, secondaryText, divider } from '../components.js';
import { sats, parseInteger, receiveView } from '../model.js';

export function receiveState() {
  return { kind: 'zark', amount: '25000', copied: false, qr: { value: '', src: '' } };
}

/** Runs when the sheet opens and whenever its tab changes (`.task(id: kind)`). */
export function receiveLoad(app) {
  return app.perform('receive', { kind: app.sheetState.kind });
}

export function testSatsCard(app, disabled = false) {
  const amount = sats(app.model.faucetAmountSat);
  return h('div', { class: 'stack-12' },
    h('div', { class: 'headline', text: 'Get free test sats' }),
    secondaryText(`Zark runs on MutinyNet, a Bitcoin test network. Claim ${amount} test sats as your own coin: your wallet proves the deposit and saves its recovery before publishing it. This takes a few minutes.`),
    button(`Get ${amount} test sats`, { disabled, onClick: () => app.perform('testSats') }));
}

function qrImage(app, address) {
  const state = app.sheetState;
  const image = h('img', { class: 'qr', alt: 'Receive address QR code', width: 204, height: 204 });
  if (state.qr.value === address && state.qr.src) {
    image.src = state.qr.src;
  } else {
    state.qr = { value: address, src: '' };
    app.qr(address).then(src => {
      if (state.qr.value !== address) return;
      state.qr.src = src;
      app.render();
    });
  }
  return image;
}

function addressCard(app, address) {
  const state = app.sheetState;
  return h('div', { class: 'address-card' },
    h('div', { class: 'qr-frame' }, qrImage(app, address)),
    h('div', { class: 'address selectable', text: address }),
    button(state.copied ? 'Copied' : 'Copy', {
      outlined: true,
      key: 'copy-address',
      onClick: async () => {
        await app.copy(address);
        state.copied = true;
        app.render();
      },
    }));
}

function zarkTab(app, view) {
  return [
    secondaryText('Share this one-use address with another Zark wallet. Their coin arrives in Activity for you to accept.'),
    view.address ? addressCard(app, view.address)
      : app.model.busy ? null : button('Get address', { onClick: () => receiveLoad(app) }),
  ];
}

function depositTab(app, view) {
  const { model } = app;
  const state = app.sheetState;
  const amount = sats(model.receiveAmountSat ?? 0);
  switch (view.step) {
    case 'resume':
      return h('div', { class: 'stack-12' },
        secondaryText('Your test sats claim was interrupted. Resume to finish saving recovery and publish the deposit.'),
        button('Resume test sats', { onClick: () => app.perform('testSats') }));
    case 'broadcast':
      return h('div', { class: 'stack-6' },
        h('div', { class: 'headline', text: view.fromFaucet ? 'Test sats received' : 'Deposit published' }),
        secondaryText(`${amount} sats are now in your wallet. You can send it once the deposit confirms on MutinyNet.`));
    case 'awaiting_funding':
      return [
        secondaryText(`In your own MutinyNet wallet, pay exactly ${amount} sats to this address. Sign the transaction but do not broadcast it, then import it here.`),
        addressCard(app, view.address),
        button('Import signed transaction', { onClick: () => app.importTransaction() }),
      ];
    case 'ready':
      return [
        secondaryText('Recovery is saved. Publish the deposit to MutinyNet.'),
        button('Broadcast', { onClick: () => app.perform('depositBroadcast') }),
      ];
    default: {
      const amountSat = parseInteger(state.amount);
      const faucet = model.faucetAmountSat > 0;
      return [
        faucet ? testSatsCard(app) : null,
        faucet ? divider() : null,
        h('div', { class: 'stack-12' },
          h('div', { class: 'headline', text: 'Use your own MutinyNet wallet' }),
          field('Amount · sats', textInput({
            key: 'deposit-amount', value: state.amount, placeholder: '25000',
            onInput: value => { state.amount = value; app.render(); },
          })),
          button('Prepare deposit', {
            outlined: faucet,
            disabled: !(amountSat > 0),
            onClick: () => {
              if (amountSat > 0) app.perform('deposit', { amountSat: String(amountSat) });
            },
          })),
      ];
    }
  }
}

export function receiveSheet(app) {
  const state = app.sheetState;
  const view = receiveView(app.model, state.kind);
  return {
    title: 'Receive',
    content: [
      segmented([['zark', 'From Zark'], ['bitcoin', 'Deposit Bitcoin']], state.kind, kind => {
        state.kind = kind;
        state.copied = false;
        app.render();
        receiveLoad(app);
      }, 'Source'),
      state.kind === 'bitcoin' ? depositTab(app, view) : zarkTab(app, view),
    ],
  };
}
