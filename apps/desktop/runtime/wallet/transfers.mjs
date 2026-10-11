import path from 'node:path';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { absolute, inside, digest, sat, textValue, fail } from './validation.mjs';
import { exists, privateDirectory } from './files.mjs';

export function _outgoing(wallet, kind, { coin, address, feeSat }) {
  return wallet._serialize(async () => {
    const id = typeof coin === 'string' ? coin : coin?.id ?? coin?.coin;
    if (!digest(id)) fail('invalid_coin', 'Select a valid wallet coin.');
    textValue(address, 'Destination address', 1024);
    if (kind === 'exit' && (!Number.isSafeInteger(feeSat) || feeSat < 1 || feeSat > 10000)) fail('invalid_fee', 'Withdrawal fee must be 1 to 10,000 satoshis.');
    const view = await wallet._snapshot();
    const currentOwner = view.coins.find(item => item.id === id);
    // A returned coin has a new receiver journal, even when its coin ID is unchanged.
    // Old sender history must not force a new owner to reuse an old operation.
    let entry = wallet.index.operations.findLast(item => item.coin === id && ['send', 'batch-draft', 'exit'].includes(item.kind) && !item.closed && item.lastResult?.aborted !== true && (!currentOwner || item.ownerOperation === currentOwner.ownerOperation));
    if (entry) {
      if (entry.kind !== kind || entry.address !== address || (kind === 'exit' && entry.feeSat !== feeSat)) {
        fail('operation_conflict', 'This coin already has a saved operation with different parameters. Resume that operation.');
      }
    } else {
      const owner = currentOwner ?? await wallet._owner(coin);
      const validated = await wallet._cli('validate-address', ['--address', address]);
      if (validated.valid !== true || validated.kind !== (kind === 'exit' ? 'bitcoin' : 'zark')) fail('invalid_address', 'Destination address has the wrong type for this operation.');
      if (kind === 'exit' && feeSat + 330 >= owner.amountSat) fail('invalid_fee', 'Withdrawal fee leaves too little value.');
      const operationPath = path.join(wallet.stateDirectory, 'operations', `${kind}-${randomUUID()}`);
      entry = { kind, coin: id, ownerOperation: owner.ownerOperation, operationPath, address, feeSat, published: false };
      if (kind !== 'exit') entry.offerPath = path.join(wallet.stateDirectory, 'exports', `${path.basename(operationPath)}.offer`);
      wallet.index.operations.push(entry);
      await wallet._save();
    }
    const args = ['--owner', entry.ownerOperation, '--operation', entry.operationPath, '--to', entry.address];
    if (kind === 'exit') args.push('--fee', String(entry.feeSat));
    else args.push('--output', entry.offerPath);
    return wallet._runSaved(entry, kind, args);
  });
}

export function accept(wallet, { offerPath, coin, transferOperation, invitationPath, batchPath, operationPath, expectedAmountSat }) {
  return wallet._serialize(async () => {
    if (!digest(coin) || !digest(transferOperation)) fail('invalid_offer_context', 'Offer coin and transfer operation must be 32-byte hex values.');
    if (expectedAmountSat !== undefined && !sat(expectedAmountSat)) fail('invalid_amount', 'Expected amount must be a positive number of satoshis.');
    offerPath = absolute(offerPath, 'Encrypted offer');
    invitationPath = absolute(invitationPath, 'Invitation');
    if (!inside(wallet.home, invitationPath)) fail('invalid_invitation', 'Use a receiving invitation belonging to this wallet.');
    await privateDirectory(invitationPath);
    if (await fs.realpath(invitationPath) !== invitationPath) fail('invalid_invitation', 'Invitation must use its canonical path.');
    // Reopen via the CLI to validate the local invitation and pinned deployment.
    await wallet._cli('new-address', ['--directory', invitationPath]);
    if (batchPath) batchPath = absolute(batchPath, 'Batch manifest');
    if (operationPath) operationPath = absolute(operationPath, 'Operation');
    // A public coin/context does not identify a trusted encrypted offer.
    // Explicit message-local paths keep a rejected envelope from occupying
    // every future receive attempt for that public context.
    let entry = wallet.index.operations.find(item => item.kind === 'receive' && (operationPath
      ? item.operationPath === operationPath
      : item.coin === coin && item.transferOperation === transferOperation));
    if (entry) {
      if (entry.coin !== coin || entry.transferOperation !== transferOperation || entry.offerPath !== offerPath || entry.invitationPath !== invitationPath || entry.batchPath !== batchPath || entry.expectedAmountSat !== expectedAmountSat || (operationPath && entry.operationPath !== operationPath)) {
        fail('operation_conflict', 'This incoming transfer already has different frozen parameters. Resume its existing operation.');
      }
    } else {
      operationPath = await wallet._operationPath(operationPath ?? path.join(wallet.stateDirectory, 'operations', `receive-${randomUUID()}`), true);
      if (wallet.index.operations.some(item => item.operationPath === operationPath)) fail('operation_conflict', 'This operation path is already in use.');
      entry = { kind: 'receive', operationPath, coin, transferOperation, invitationPath, offerPath, batchPath, expectedAmountSat, published: await exists(operationPath) };
      wallet.index.operations.push(entry);
      await wallet._save();
    }
    const args = ['--invitation', invitationPath, '--operation', entry.operationPath, '--offer', offerPath, '--coin', coin, '--transfer-operation', transferOperation];
    if (batchPath) args.push('--batch', batchPath);
    if (expectedAmountSat !== undefined) args.push('--expected-amount', String(expectedAmountSat));
    const result = await wallet._runSaved(entry, 'receive', args);
    const invitation = wallet.index.addresses.find(item => item.invitationPath === invitationPath);
    if (invitation) { invitation.used = true; await wallet._save(); }
    return result;
  });
}
