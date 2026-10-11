// Validate and stage a coin offer. The caller saves task/seen state before ACK.
import path from 'node:path';
import { createHash } from 'node:crypto';
import { writePrivateImmutable } from './storage.mjs';
import { RejectedMessage } from './message-errors.mjs';
import { amount } from './wallet/validation.mjs';

const HEX = /^[a-f0-9]{64}$/;

export async function acceptCoinOffer(controller, box, message, key) {
  const p = message.payload;
  if (!HEX.test(p.coin) || !HEX.test(p.transferOperation)
      || typeof p.envelope !== 'string' || !p.envelope.length || p.envelope.length > 2_666_668
      || !Number.isSafeInteger(p.amountSat)) throw new RejectedMessage('Invalid coin offer');
  let amountSat;
  try { amountSat = amount(p.amountSat); } catch { throw new RejectedMessage('Invalid amount'); }
  const swap = controller.state.swaps.find(s => s.id === box.id);
  if ((swap && p.swapId !== swap.offerId) || (!swap && p.swapId)) throw new RejectedMessage('Wrong swap');
  if (swap && (!swap.peer || !swap.manifestPath)) throw new Error('Swap manifest is not yet available');
  if (swap && (swap.peer.coin !== p.coin || amountSat !== swap.amountSat
      || swap.peer.context.slice(200, 264) !== p.transferOperation)) throw new RejectedMessage('Wrong swap offer context');
  if (box.used && box.used !== key) throw new RejectedMessage('Invitation already used');
  if (controller.state.tasks.length >= 1024
      || controller.state.tasks.filter(t => t.invitationId === box.id).length >= 32) throw new RejectedMessage('Incoming offer quota reached');
  const id = createHash('sha256').update(key).digest('hex').slice(0, 32);
  const offerPath = path.join(controller.store.directory, `${id}-offer.bin`);
  const bytes = Buffer.from(p.envelope, 'base64');
  if (bytes.length > 2_000_000 || bytes.toString('base64') !== p.envelope) throw new RejectedMessage('Invalid encoding');
  // Publish an immutable ciphertext file before durably recording/acking it.
  await writePrivateImmutable(offerPath, bytes);
  const parameters = {
    offerPath,
    coin: p.coin,
    transferOperation: p.transferOperation,
    invitationPath: box.invitationPath,
    operationPath: path.join(controller.home, '.desktop', 'operations', `receive-${id}`),
    ...(swap ? { batchPath: swap.manifestPath } : {}),
  };
  if (!controller.state.tasks.some(t => t.id === id)) controller.state.tasks.push({
    id,
    kind: 'receive',
    amountSat,
    coin: p.coin,
    invitationId: box.id,
    messageKey: key,
    ...(swap ? { swapId: swap.id } : {}),
    parameters,
    phase: swap ? 'accepting' : 'offer',
  });
}
