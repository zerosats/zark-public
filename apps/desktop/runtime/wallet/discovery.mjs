import path from 'node:path';
import * as fs from 'node:fs/promises';
import { WalletError, digest, sat, fail } from './validation.mjs';
import { readJson, privateDirectory } from './files.mjs';
import { MAX_OUTPUT } from './native-process.mjs';
import { publicResult } from './results.mjs';

export async function _discover(wallet) {
  const found = [];
  let visited = 0;
  const walk = async (directory, depth) => {
    if (++visited > 4096 || depth > 5) fail('scan_limit', 'The wallet home exceeds the operation discovery limit.');
    const entries = await fs.readdir(directory, { withFileTypes: true });
    if (entries.some(entry => entry.name === 'operation.json' && entry.isFile())) { found.push(directory); return; }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      if (entry.name.startsWith('.') && entry.name !== '.desktop') continue;
      if (['proofs', 'verify', 'journal', 'invitations', 'exports'].includes(entry.name)) continue;
      await walk(path.join(directory, entry.name), depth + 1);
    }
  };
  await walk(wallet.home, 0);
  return found.sort();
}

export async function _snapshot(wallet) {
  const config = await readJson(wallet.configPath, false, MAX_OUTPUT);
  const operations = [];
  const candidates = [];
  for (const root of await wallet._discover()) {
    let entry;
    try {
      await privateDirectory(root);
      const metadata = await readJson(path.join(root, 'operation.json'), false, 100_000);
      if (metadata.version !== 10 || metadata.manifest_sha256 !== config.manifest_sha256) continue;
      const kind = metadata.kind?.kind;
      if (!['origin', 'receiver', 'sender', 'exit'].includes(kind)) continue;
      entry = { operationPath: root, operation: root, kind, status: 'initializing', metadataOnly: true, currentOwnershipVerified: false };
      const filename = { origin: 'origin-operation.json', receiver: 'recipient-operation.json', sender: 'sender-operation.json', exit: 'exit-operation.json' }[kind];
      const record = await readJson(path.join(root, 'journal', filename), true);
      if (!record) { operations.push(entry); continue; }
      const coin = digest(record.context?.coin);
      entry.coin = coin;
      if (kind === 'origin' || kind === 'receiver') {
        const recovery = await readJson(path.join(root, 'journal', 'own-recovery', 'recovery-draft.json'), true);
        const amountSat = sat(recovery?.activation_input?.amount) ?? (kind === 'origin' ? sat(record.amount) : null);
        const recoveryAmountSat = sat(recovery?.backing?.amount);
        const outgoing = kind === 'origin' ? record.outgoing : record.stage?.recovery?.outgoing;
        const accepted = kind === 'origin' ? record.funding_broadcast === true && !!record.certificate : record.stage?.recovery?.accepted === true;
        const schemaValid = kind === 'origin' ? record.schema === 'zark-origin' && record.version === 3 : record.schema === 'zark-recipient-operation' && record.version === 3;
        entry.status = outgoing ? (outgoing.kind === 'exit' ? 'withdrawing' : 'outgoing') : accepted ? 'available' : 'pending';
        entry.amountSat = amountSat;
        entry.recoveryAmountSat = recoveryAmountSat;
        if (accepted && !outgoing && schemaValid && coin && amountSat) candidates.push({
          id: coin, coin, amountSat, recoveryAmountSat, ownerOperation: root,
          status: 'available', metadataOnly: true, currentOwnershipVerified: false,
        });
      } else {
        entry.ownerOperation = metadata.kind.owner;
        entry.transferOperation = digest(record.context?.operation);
        if (kind === 'sender') {
          entry.status = record.retired ? 'completed' : record.aborted ? 'aborted' : 'outgoing';
          entry.offerPath = metadata.kind.output;
        } else {
          entry.status = record.terminal ? 'withdrawal_prepared' : 'withdrawing';
          entry.amountSat = sat(record.activation_input?.amount);
        }
      }
      const saved = wallet.index.operations.find(item => item.operationPath === root);
      if (saved?.lastResult) entry.lastResult = publicResult(saved.lastResult);
      if (kind === 'exit' && saved?.lastResult?.transaction_id) entry.status = 'withdrawn';
      operations.push(entry);
    } catch (error) {
      operations.push({ operationPath: root, kind: entry?.kind ?? 'unknown', status: 'unavailable', metadataOnly: true, currentOwnershipVerified: false, error: error instanceof WalletError ? error.code : 'unreadable_state' });
    }
  }
  const counts = new Map();
  for (const coin of candidates) counts.set(coin.id, (counts.get(coin.id) ?? 0) + 1);
  const coins = candidates.filter(coin => counts.get(coin.id) === 1);
  for (const entry of operations) if (entry.status === 'available' && counts.get(entry.coin) > 1) entry.status = 'ambiguous';
  for (const saved of wallet.index.operations) {
    if (!operations.some(item => item.operationPath === saved.operationPath)) operations.push({
      operationPath: saved.operationPath, operation: saved.operationPath, kind: saved.kind,
      status: saved.published ? 'missing' : 'initializing', coin: saved.coin,
      metadataOnly: true, currentOwnershipVerified: false,
    });
  }
  return {
    coins, operations,
    addresses: wallet.index.addresses.filter(item => item.address).map(item => ({ id: item.id, address: item.address, oneUse: true, used: item.used === true })),
    metadataOnly: true, currentOwnershipVerified: false,
    capabilities: { send: true, receive: true, withdraw: true, batchDraft: true, batchManifest: true, publicBatchDraftExport: true, deposit: true },
  };
}

export async function _owner(wallet, coin) {
  const id = typeof coin === 'string' ? coin : coin?.id ?? coin?.coin;
  if (!digest(id)) fail('invalid_coin', 'Select a valid wallet coin.');
  const snapshot = await wallet._snapshot();
  const owner = snapshot.coins.find(item => item.id === id);
  if (!owner) fail('coin_unavailable', 'This coin has no unreserved local owner. Resume its existing operation.');
  return owner;
}
