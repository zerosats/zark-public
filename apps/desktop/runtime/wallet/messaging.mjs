import path from 'node:path';
import { createHash, randomUUID, randomBytes } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { readPrivate, writePrivateImmutable } from '../storage.mjs';
import { absolute, inside, fail } from './validation.mjs';
import { exists, privateDirectory } from './files.mjs';

export function mailCrypto(wallet, request) { return wallet._serialize(() => wallet._mailCrypto(request)); }

export async function _mailCrypto(wallet, request) {
  if (request.invitation) {
    const invitation = absolute(request.invitation, 'Invitation');
    if (!inside(wallet.home, invitation) || await fs.realpath(invitation) !== invitation) fail('invalid_invitation', 'Use a receiving invitation belonging to this wallet.');
    await privateDirectory(invitation);
  }
  const directory = await fs.mkdtemp(path.join(wallet.stateDirectory, 'mail-crypto-'));
  try {
    const input = path.join(directory, 'input.json'), output = path.join(directory, 'output.json');
    await writePrivateImmutable(input, JSON.stringify(request));
    await wallet._cli('mail-crypto', ['--input', input, '--output', output]);
    return JSON.parse(await readPrivate(output, 3_000_000));
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
}

export function sealDelivery(wallet, address, message) {
  return wallet._serialize(async () => {
    if (typeof message.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(message.id)) fail('invalid_message', 'Invalid delivery identifier');
    const identity = createHash('sha256').update(JSON.stringify([address, message.id])).digest('hex');
    const digest = createHash('sha256').update(JSON.stringify({ address, message })).digest('hex');
    const directory = path.join(wallet.stateDirectory, 'mail-outbound');
    await privateDirectory(directory, true);
    const file = path.join(directory, `${identity}.json`);
    if (await exists(file)) {
      const prior = JSON.parse(await readPrivate(file, 3_000_000));
      if (prior.version !== 1 || prior.digest !== digest) fail('message_conflict', 'Frozen delivery differs');
      return prior.wire;
    }
    if ((await fs.readdir(directory)).length >= 4096) fail('storage_quota', 'Outgoing message history is full');
    const id = randomBytes(32).toString('hex');
    const { ciphertext } = await wallet._mailCrypto({ op: 'seal', address, id, message: { kind: message.kind, payload: message.payload } });
    const wire = { id, ciphertext, ...(message.ttlMs === undefined ? {} : { ttlMs: message.ttlMs }) };
    await writePrivateImmutable(file, JSON.stringify({ version: 1, digest, wire }));
    return wire;
  });
}

export function newAddress(wallet) {
  return wallet._serialize(async () => {
    // If creation was interrupted, retry exactly the same invitation directory.
    let entry = wallet.index.addresses.find(item => !item.address);
    if (!entry) {
      const id = randomUUID();
      entry = { id, invitationPath: path.join(wallet.stateDirectory, 'invitations', id), published: false };
      wallet.index.addresses.push(entry);
      await wallet._save();
    }
    if (entry.published && !await exists(entry.invitationPath)) fail('missing_invitation', 'The saved invitation is missing. Restore it; do not regenerate it.');
    try {
      const result = await wallet._cli('new-address', ['--directory', entry.invitationPath]);
      if (!result.address) fail('invalid_response', 'The wallet did not return a receiving address.');
      entry.address = result.address;
      entry.published = true;
      await wallet._save();
      const response = { ...result, id: entry.id };
      Object.defineProperty(response, 'invitationPath', { value: entry.invitationPath, enumerable: false });
      return response;
    } catch (error) {
      if (await exists(entry.invitationPath)) { entry.published = true; await wallet._save(); }
      throw error;
    }
  });
}
