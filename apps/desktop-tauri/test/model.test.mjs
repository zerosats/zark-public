import test from 'node:test';
import assert from 'node:assert/strict';
import {
  initialModel, applyEvent, applyShellError, beginAction, endAction, activityState, parseInteger,
  sendValidity, sendRequest, toggleSwapCoin, swapSelection, receiveView, showTestSatsCard,
} from '../ui/model.js';

test('replies decide the outcome while background errors cannot clear a reply', () => {
  const model = initialModel();
  beginAction(model, 'send');
  assert.equal(model.progress, 'Working…');
  applyEvent(model, { error: 'Relay offline' }, false);
  assert.equal(model.error, 'Relay offline');
  applyEvent(model, { id: 'ui-1' }, true);
  assert.equal(model.error, null);
  applyEvent(model, { progress: 'Proving…', receiveKind: 'bitcoin', faucetAmountSat: 25000 }, false);
  assert.deepEqual([model.progress, model.receiveKind, model.faucetAmountSat], ['Proving…', 'bitcoin', 25000]);
  endAction(model);
  assert.deepEqual([model.busy, model.progress], [false, '']);
  beginAction(model, 'refresh');
  assert.equal(model.progress, '');
  applyShellError(model, 'Wallet stopped. Reopen Zark.');
  assert.deepEqual([model.busy, model.error], [false, 'Wallet stopped. Reopen Zark.']);
});

test('activity states and integer parsing match the native views', () => {
  assert.equal(activityState('offer'), 'Ready to receive');
  assert.equal(activityState('retry'), 'Needs attention');
  assert.equal(activityState('processing'), 'Pending');
  assert.equal(activityState('complete'), null);
  assert.equal(parseInteger(' 25000 '), 25000);
  for (const bad of ['', '1.5', '1e3', '0x10', '25 000']) assert.equal(parseInteger(bad), null);
});

test('send rules: Zark needs a coin and address; Bitcoin also a tb1p address and bounded fee', () => {
  const coin = { id: 'a', amountSat: 25000 };
  assert.equal(sendValidity({ kind: 'zark', address: ' tzark1x ', coin, fee: '' }), true);
  assert.equal(sendValidity({ kind: 'zark', address: '  ', coin, fee: '' }), false);
  assert.equal(sendValidity({ kind: 'zark', address: 'tzark1x', coin: undefined, fee: '' }), false);
  assert.equal(sendValidity({ kind: 'bitcoin', address: 'tb1pdest', coin, fee: '1000' }), true);
  assert.equal(sendValidity({ kind: 'bitcoin', address: 'tb1qdest', coin, fee: '1000' }), false);
  assert.equal(sendValidity({ kind: 'bitcoin', address: 'tb1pdest', coin, fee: '10001' }), false);
  assert.equal(sendValidity({ kind: 'bitcoin', address: 'tb1pdest', coin: { amountSat: 1330 }, fee: '1000' }), false);
  assert.deepEqual(sendRequest({ kind: 'bitcoin', address: ' tb1pdest ', coinID: 'a', fee: '1000' }),
    { action: 'withdraw', args: { coin: 'a', address: 'tb1pdest', feeSat: '1000' } });
  assert.deepEqual(sendRequest({ kind: 'zark', address: 'tzark1x', coinID: 'a', fee: '1000' }),
    { action: 'send', args: { coin: 'a', address: 'tzark1x' } });
});

test('swap selection is limited to five coins and totals only spendable selections', () => {
  let selection = new Set();
  for (const id of ['1', '2', '3', '4', '5', '6']) selection = toggleSwapCoin(selection, id, true);
  assert.deepEqual([...selection], ['1', '2', '3', '4', '5']);
  selection = toggleSwapCoin(selection, '2', false);
  const coins = [{ id: '1', amountSat: 10 }, { id: '3', amountSat: 20 }, { id: '4', amountSat: 30 }];
  assert.deepEqual(swapSelection(coins, selection).total, 60);
  // A selected coin that disappeared invalidates the selection until it is intersected away.
  assert.equal(swapSelection(coins, selection).valid, false);
  assert.equal(swapSelection(coins, new Set(['1', '3'])).valid, true);
});

test('receive tabs show their own phase and interrupted test sats resume', () => {
  const model = initialModel();
  Object.assign(model, { receiveKind: 'bitcoin', receivePhase: 'awaiting_funding', receiveAddress: 'tb1pdep', receiveSource: 'faucet' });
  assert.deepEqual(receiveView(model, 'bitcoin'), { address: 'tb1pdep', phase: 'awaiting_funding', step: 'resume', fromFaucet: true });
  assert.equal(receiveView(model, 'zark').address, '');
  model.receiveSource = 'external';
  assert.equal(receiveView(model, 'bitcoin').step, 'awaiting_funding');
  model.receivePhase = 'creating';
  assert.equal(receiveView(model, 'bitcoin').step, 'start');
  model.receivePhase = 'broadcast';
  assert.equal(receiveView(model, 'bitcoin').step, 'broadcast');
});

test('the home test sats card only shows for an empty real wallet with an available faucet', () => {
  const model = initialModel();
  model.faucetAmountSat = 25000;
  assert.equal(showTestSatsCard(model, false), true);
  assert.equal(showTestSatsCard(model, true), false);
  model.snapshot.totalSat = 1;
  assert.equal(showTestSatsCard(model, false), false);
});
