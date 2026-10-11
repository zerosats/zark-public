// Deposit transitions run inside the controller's serialized action queue.
// Preserve each save before advancing the native journal or exposing its phase.
import path from 'node:path';
import { amount } from './wallet/validation.mjs';
import { writePrivate } from './storage.mjs';
import { FaucetError } from './faucet.mjs';

const MAX_DEPOSIT_HISTORY = 256;

async function prepare(controller, amountSat, source) {
  if (!controller.state.deposit || controller.state.deposit.phase === 'broadcast') {
    controller.state.deposit = { amountSat, phase: 'creating', source };
    await controller.save();
  }
  const d = controller.state.deposit;
  const result = await controller.wallet.createDeposit({ amountSat: d.amountSat });
  d.operationPath = result.operationPath;
  d.address = result.funding_address;
  d.phase = 'awaiting_funding';
  await controller.save();
  return d;
}

export async function createDeposit(controller, args) {
  await prepare(controller, amount(args.amountSat), 'external');
  depositView(controller);
}

export async function importDeposit(controller, args) {
  const d = controller.state.deposit;
  if (!d || !d.address || d.phase !== 'awaiting_funding') throw new Error('No pending deposit');
  const tx = await controller.decodeTransaction(args.transactionPath);
  if (!tx.vin?.length || !tx.vin.every(v => v.txinwitness?.length || v.scriptSig?.hex)) throw new Error('Signed transaction required');
  const outputs = tx.vout.filter(v =>
    v.scriptPubKey?.address === d.address && Math.round(v.value * 1e8) === d.amountSat);
  if (outputs.length !== 1) throw new Error(outputs.length ? 'Ambiguous deposit output' : 'Transaction does not fund this deposit');
  if (!/^[a-f0-9]{64}$/.test(tx.txid ?? '')) throw new Error('Signed transaction required');
  if (d.boundFunding) {
    if (d.boundFunding.txid !== tx.txid || d.boundFunding.vout !== outputs[0].n) throw new Error('Transaction does not fund this deposit');
  } else {
    await controller.wallet.bindDeposit({
      operationPath: d.operationPath,
      transactionPath: args.transactionPath,
      vout: outputs[0].n,
    });
    // Save before advance can freeze a parent nonce. A failed proof resumes
    // advance with the exact bound transaction instead of binding it again.
    d.boundFunding = { txid: tx.txid, vout: outputs[0].n };
    await controller.save();
  }
  const result = await controller.wallet.advance(d.operationPath);
  d.phase = result.recovery_and_activation_saved === true ? 'ready' : 'awaiting_funding';
  await controller.save();
  depositView(controller);
}

export async function broadcastDeposit(controller) {
  const d = controller.state.deposit;
  if (!d || d.phase !== 'ready') throw new Error('No pending deposit');
  await controller.wallet.advance(d.operationPath, { broadcast: true });
  d.phase = 'broadcast';
  controller.state.deposits ??= [];
  if (controller.state.deposits.length >= MAX_DEPOSIT_HISTORY) controller.state.deposits.shift();
  controller.state.deposits.push({ id: path.basename(d.operationPath), amountSat: d.amountSat, source: d.source ?? 'external' });
  await controller.save();
  depositView(controller);
}

/**
 * One-click sponsored deposit: the faucet signs the funding transaction, and
 * this wallet saves recovery (proving) before it broadcasts. Each step is
 * saved, so an interrupted claim resumes where it stopped.
 */
export async function claimTestSats(controller) {
  let d = controller.state.deposit;
  if (d && d.phase !== 'broadcast' && d.source !== 'faucet') throw new Error('Finish the pending deposit first');
  if (!d || d.phase === 'broadcast' || d.phase === 'creating') {
    controller.emit({ progress: 'Preparing deposit…' });
    const offer = await controller.faucet.info();
    if (!offer.available) throw new FaucetError('The test sats faucet is empty or at its daily limit.');
    d = await prepare(controller, offer.amountSat, 'faucet');
  }
  if (d.phase === 'awaiting_funding') {
    if (!d.transactionPath) {
      controller.emit({ progress: 'Requesting test sats…' });
      const hex = await controller.faucet.fund(d.address);
      const file = path.join(controller.home, '.desktop-gui', 'faucet', `${path.basename(d.operationPath)}.hex`);
      await writePrivate(file, `${hex}\n`);
      d.transactionPath = file;
      await controller.save();
    }
    controller.emit({ progress: 'Proving deposit…' });
    await importDeposit(controller, { transactionPath: d.transactionPath });
  }
  if (d.phase === 'ready') {
    controller.emit({ progress: 'Broadcasting…' });
    await broadcastDeposit(controller);
  }
}

export async function faucetOffer(controller) {
  try { return await controller.faucet?.info(); } catch { return undefined; }
}

export function depositView(controller) {
  const d = controller.state.deposit;
  if (d) controller.emit({
    receiveKind: 'bitcoin',
    receiveAddress: d.address ?? '',
    receivePhase: d.phase,
    receiveAmountSat: d.amountSat,
    receiveSource: d.source ?? 'external',
  });
}
