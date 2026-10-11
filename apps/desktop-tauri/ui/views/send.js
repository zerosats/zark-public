// Send sheet: whole-coin Zark transfer or cooperative Bitcoin withdrawal (SendView.swift).
import { h, button, field, textInput, segmented, coinPicker, amountHero, detail } from '../components.js';
import { sats, spendableCoins, sendValidity, sendRequest, parseInteger } from '../model.js';

export function sendState() {
  return { kind: 'zark', address: '', coinID: '', fee: '1000', confirming: false };
}

async function submit(app, form, valid) {
  if (!valid) return;
  const { action, args } = sendRequest(form);
  await app.perform(action, args);
  if (app.model.error === null) app.closeSheet();
}

export function sendSheet(app) {
  const form = app.sheetState;
  const coins = spendableCoins(app.model.snapshot.coins);
  if (!form.coinID && coins.length) form.coinID = coins[0].id;
  const coin = coins.find(item => item.id === form.coinID);
  const valid = sendValidity({ ...form, coin });
  const address = form.address.trim();

  if (form.confirming) {
    const feeSat = parseInteger(form.fee);
    return {
      title: 'Confirm send',
      content: [
        h('div', { class: 'stack-20' },
          amountHero(coin?.amountSat ?? 0),
          detail('To', address),
          form.kind === 'bitcoin' && feeSat !== null && coin ? [
            detail('Fee', `${sats(feeSat)} sats`),
            detail('Receive', `${sats(coin.amountSat - feeSat)} sats`),
          ] : null),
        h('div', { class: 'row-12' },
          button('Back', { outlined: true, onClick: () => { form.confirming = false; app.render(); } }),
          button('Send', { disabled: !valid, onClick: () => submit(app, form, valid) })),
      ],
    };
  }

  return {
    title: 'Send',
    content: [
      segmented([['zark', 'Zark'], ['bitcoin', 'Bitcoin']], form.kind, kind => { form.kind = kind; app.render(); }, 'Network'),
      field('Address', textInput({
        key: 'send-address', value: form.address,
        placeholder: form.kind === 'zark' ? 'Zark address' : 'Bitcoin Taproot address · tb1p…',
        onInput: value => { form.address = value; app.render(); },
      })),
      coinPicker(coins, form.coinID, id => { form.coinID = id; app.render(); }),
      detail('Amount', `${sats(coin?.amountSat ?? 0)} sats`),
      form.kind === 'bitcoin' ? field('Fee · sats', textInput({
        key: 'send-fee', value: form.fee, placeholder: '1000',
        onInput: value => { form.fee = value; app.render(); },
      })) : null,
      button('Continue', { disabled: !valid, onClick: () => { form.confirming = true; app.render(); } }),
    ],
  };
}
