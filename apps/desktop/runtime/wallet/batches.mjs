import path from 'node:path';
import * as fs from 'node:fs/promises';
import { absolute, fail } from './validation.mjs';
import { exists, privateDirectory } from './files.mjs';

export function pendingBatchDrafts(wallet, slots) {
  return wallet._serialize(async () => {
    if (!Array.isArray(slots) || slots.length > 5) fail('invalid_batch', 'Invalid swap draft set.');
    return wallet.index.operations.filter(e => e.kind === 'batch-draft' && !e.closed && slots.some(s => s.coin === e.coin && s.address === e.address))
      .map(e => ({ coin: e.coin, operationPath: e.operationPath }));
  });
}

export function batchManifestMany(wallet, { drafts, peer, expiresAt, output }) {
  return wallet._serialize(async () => {
    if (!Array.isArray(drafts) || drafts.length < 1 || drafts.length > 5 || new Set(drafts).size !== drafts.length || !Number.isSafeInteger(expiresAt)) fail('invalid_batch', 'Invalid multi-coin manifest.');
    drafts = await Promise.all(drafts.map(draft => wallet._operationPath(draft)));
    peer = absolute(peer, 'Public peer drafts'); output = absolute(output, 'Batch manifest output');
    const terms = { drafts, peer, expiresAt, output };
    const prior = wallet.index.manifests.find(m => m.output === output);
    if (prior && JSON.stringify({ drafts: prior.drafts, peer: prior.peer, expiresAt: prior.expiresAt, output: prior.output }) !== JSON.stringify(terms)) fail('operation_conflict', 'Frozen batch manifest differs.');
    if (prior?.published && !await exists(output)) fail('missing_manifest', 'The saved batch manifest is missing.');
    const saved = prior ?? { ...terms, published: false };
    if (!prior) { wallet.index.manifests.push(saved); await wallet._save(); }
    const result = await wallet._cli('batch-manifest', [...drafts.flatMap(d => ['--draft', d]), '--peer-drafts', peer, '--expires-at', String(expiresAt), '--output', output]);
    saved.published = await exists(output); await wallet._save(); return result;
  });
}

export function swapGroup(wallet, { operationPath, planPath }) {
  return wallet._serialize(async () => {
    operationPath = await wallet._operationPath(operationPath, true); planPath = absolute(planPath, 'Swap plan');
    let entry = wallet.index.operations.find(e => e.operationPath === operationPath);
    if (entry && (entry.kind !== 'swap-group' || entry.planPath !== planPath)) fail('operation_conflict', 'Frozen swap group differs.');
    if (!entry) { entry = { kind: 'swap-group', operationPath, planPath, published: false }; wallet.index.operations.push(entry); await wallet._save(); }
    const initialized = await exists(path.join(operationPath, 'operation.json'));
    const result = await wallet._runSaved(entry, initialized ? 'advance' : 'swap-group', ['--operation', operationPath, ...(initialized ? [] : ['--plan', planPath])]);
    // Register native child journals so snapshot sees newly received coins and
    // remembers outgoing completion; native group controls every readiness.
    for (const child of result.incoming ?? []) {
      if (!wallet.index.operations.some(e => e.operationPath === child.operation)) wallet.index.operations.push({ kind: 'receive', operationPath: child.operation, coin: child.coin, published: true });
    }
    for (const child of result.outgoing ?? []) {
      const outgoing = wallet.index.operations.find(e => e.operationPath === child.operation);
      if (outgoing && child.completed === true) outgoing.closed = true;
    }
    await wallet._save(); return result;
  });
}

export function batchManifest(wallet, { first, second, peer, expiresAt, output }) {
  return wallet._serialize(async () => {
    first = await wallet._operationPath(first);
    if (!!second === !!peer) fail('invalid_batch', 'Provide either a second local operation or a public peer draft.');
    if (second) {
      second = await wallet._operationPath(second);
      if (first === second) fail('invalid_batch', 'A batch requires two distinct drafted operations.');
    }
    if (peer) peer = absolute(peer, 'Public peer draft');
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) fail('invalid_batch', 'Batch expiry must be an integer Unix timestamp.');
    output = absolute(output, 'Batch manifest output');
    await privateDirectory(path.dirname(output));
    if (await fs.realpath(path.dirname(output)) !== path.dirname(output)) fail('unsafe_state', 'Batch output must use its canonical parent path.');
    let saved = wallet.index.manifests.find(item => item.output === output);
    if (saved) {
      if (saved.first !== first || saved.second !== second || saved.peer !== peer || saved.expiresAt !== expiresAt) fail('operation_conflict', 'The batch manifest already has different frozen parameters.');
      if (saved.published && !await exists(output)) fail('missing_manifest', 'The saved batch manifest is missing. Restore it; do not regenerate it.');
    } else {
      saved = { first, second, peer, expiresAt, output, published: await exists(output) };
      wallet.index.manifests.push(saved);
      await wallet._save();
    }
    try {
      const result = await wallet._cli('batch-manifest', ['--first', first, ...(peer ? ['--peer', peer] : ['--second', second]), '--expires-at', String(expiresAt), '--output', output]);
      saved.published = await exists(output);
      await wallet._save();
      return result;
    } catch (error) {
      if (await exists(output)) { saved.published = true; await wallet._save(); }
      throw error;
    }
  });
}
