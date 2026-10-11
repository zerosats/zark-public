import * as fs from 'node:fs/promises';
import path from 'node:path';
import { WalletError, absolute, inside, textValue, fail } from './wallet/validation.mjs';
import { exists, readJson, privateDirectory, writeIndex } from './wallet/files.mjs';
import { processRunner, _cli } from './wallet/native-process.mjs';
import { NativeWorker } from './wallet/native-worker.mjs';
export { WalletError } from './wallet/validation.mjs';
import { _discover, _snapshot, _owner } from './wallet/discovery.mjs';
import { mailCrypto, _mailCrypto, sealDelivery, newAddress } from './wallet/messaging.mjs';
import { _outgoing, accept } from './wallet/transfers.mjs';
import { pendingBatchDrafts, batchManifestMany, swapGroup, batchManifest } from './wallet/batches.mjs';
import { decodeTransaction, createDeposit, bindDeposit } from './wallet/deposits.mjs';

const queues = new Map();

// Serialized native journal access is shared across adapters for the same wallet.
// Public methods retain their saved-operation and output-sanitization contracts.
export class WalletAdapter {
  constructor({ configPath, walletBinary, home, bitcoinCli, fundingDataDir, fundingWallet, runner = processRunner }) {
    this.configPath = absolute(configPath, 'Configuration');
    this.walletBinary = absolute(walletBinary, 'Wallet executable');
    this.home = absolute(home, 'Wallet home');
    this.bitcoinCli = bitcoinCli;
    this.fundingDataDir = fundingDataDir;
    this.fundingWallet = fundingWallet;
    this.nativeWorker = runner === processRunner ? new NativeWorker({ binary: this.walletBinary, config: this.configPath, cwd: this.home }) : null;
    // Only wallet commands use the profile-bound worker. Bitcoin transaction
    // decoding keeps its separate pinned executable and bounded stdin runner.
    this.runner = runner;
    this.walletRunner = this.nativeWorker ? this.nativeWorker.run.bind(this.nativeWorker) : runner;
    this.stateDirectory = path.join(this.home, '.desktop');
    this.indexPath = path.join(this.stateDirectory, 'index.json');
  }
  async _initialize() {
    await privateDirectory(this.home);
    if (await fs.realpath(this.home) !== this.home) fail('unsafe_state', 'Wallet home must use its canonical path.');
    await privateDirectory(this.stateDirectory, true);
    for (const name of ['operations', 'invitations', 'exports']) await privateDirectory(path.join(this.stateDirectory, name), true);
    const saved = await readJson(this.indexPath, true);
    if (saved && (saved.version !== 1 || !Array.isArray(saved.operations) || !Array.isArray(saved.addresses))) {
      fail('invalid_state', 'The desktop wallet index is invalid. Preserve its journal.');
    }
    this.index = saved ?? { version: 1, operations: [], addresses: [], manifests: [] };
    this.index.manifests ??= [];
    if (!saved) await this._save();
  }
  _save() { return writeIndex(this.indexPath, this.index); }
  _serialize(action) {
    const previous = queues.get(this.home) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(async () => { await this._initialize(); return action(); });
    queues.set(this.home, next);
    next.finally(() => { if (queues.get(this.home) === next) queues.delete(this.home); }).catch(() => {});
    return next;
  }
  async _cli(command, args = []) { return _cli(this, command, args); }
  async close() { await this.nativeWorker?.close(); }
  mailCrypto(request) { return mailCrypto(this, request); }
  async _mailCrypto(request) { return _mailCrypto(this, request); }
  sealDelivery(address, message) { return sealDelivery(this, address, message); }
  async _operationPath(value, allowNew = false) {
    const operation = absolute(value, 'Operation');
    if (!inside(this.home, operation) || operation === this.home) fail('invalid_path', 'The operation must belong to this wallet home.');
    if (await fs.realpath(path.dirname(operation)) !== path.dirname(operation)) fail('unsafe_state', 'Operation parent must use its canonical path.');
    await privateDirectory(path.dirname(operation));
    if (await exists(operation)) await privateDirectory(operation);
    else if (!allowNew) fail('missing_operation', 'The saved operation is missing. Restore it; do not recreate its journal.');
    return operation;
  }
  async _discover() { return _discover(this); }
  async _snapshot() { return _snapshot(this); }
  snapshot() { return this._serialize(() => this._snapshot()); }
  newAddress() { return newAddress(this); }
  async _owner(coin) { return _owner(this, coin); }
  async _runSaved(entry, command, args) {
    if (entry.published && !await exists(entry.operationPath)) fail('missing_operation', 'The saved operation is missing. Restore it; do not recreate its journal.');
    try {
      const result = await this._cli(command, args);
      entry.lastResult = result.raw;
      if (result.completed === true || result.aborted === true) entry.closed = true;
      if (entry.kind === 'origin' && command === 'advance' && args.includes('--broadcast') && result.transaction_id) entry.fundingPublished = true;
      entry.published = await exists(entry.operationPath);
      await this._save();
      return { ...result, operationPath: entry.operationPath, operation: entry.operationPath };
    } catch (error) {
      if (await exists(entry.operationPath)) { entry.published = true; await this._save(); }
      if (error instanceof WalletError) error.operationPath = entry.operationPath;
      throw error;
    }
  }
  _outgoing(kind, options) { return _outgoing(this, kind, options); }
  send(options) { return this._outgoing('send', options); }
  withdraw(options) { return this._outgoing('exit', { feeSat: 1000, ...options }); }
  async batchDraft(options) {
    const result = await this._outgoing('batch-draft', options);
    result.publicDraft = { context: result.context, coin: result.coin, revision: result.revision };
    return result;
  }
  pendingBatchDrafts(slots) { return pendingBatchDrafts(this, slots); }
  accept(options) { return accept(this, options); }
  _existing(command, operationPath, extra = []) {
    return this._serialize(async () => {
      operationPath = await this._operationPath(operationPath);
      let entry = this.index.operations.find(item => item.operationPath === operationPath);
      if (!entry) {
        const metadata = await readJson(path.join(operationPath, 'operation.json'), false, 100_000);
        entry = { operationPath, kind: metadata.kind?.kind, published: true };
        this.index.operations.push(entry);
        await this._save();
      }
      return this._runSaved(entry, command, ['--operation', operationPath, ...extra]);
    });
  }
  advance(operationPath, { broadcast = false } = {}) {
    if (typeof broadcast !== 'boolean') return Promise.reject(new WalletError('invalid_input', 'Broadcast must be explicitly true or false.'));
    return this._existing('advance', operationPath, broadcast ? ['--broadcast'] : []);
  }
  complete(operationPath) { return this._existing('complete', operationPath); }
  batchAbort(operationPath) { return this._existing('batch-abort', operationPath); }
  batchSend({ operationPath, manifestPath }) { return this._existing('batch-send', operationPath, ['--manifest', absolute(manifestPath, 'Batch manifest')]); }
  batchManifestMany(options) { return batchManifestMany(this, options); }
  swapGroup(options) { return swapGroup(this, options); }
  swapAbort(operationPath) { return this._existing('swap-abort', operationPath); }
  status(operationPath) {
    return this._serialize(async () => {
      operationPath = await this._operationPath(operationPath);
      const result = await this._cli('status', ['--operation', operationPath]);
      return { ...result, metadata_only: true, current_ownership_verified: false, metadataOnly: true, currentOwnershipVerified: false };
    });
  }
  verifyAssets() { return this._serialize(() => this._cli('verify-assets')); }
  validateAddress(address) {
    return this._serialize(async () => {
      textValue(address, 'Destination address', 1024);
      const result = await this._cli('validate-address', ['--address', address]);
      if (result.valid !== true || !['zark', 'bitcoin'].includes(result.kind)) fail('invalid_address', 'The wallet did not validate this destination address.');
      return result;
    });
  }
  decodeTransaction(transactionPath) { return decodeTransaction(this, transactionPath); }
  createDeposit(options) { return createDeposit(this, options); }
  bindDeposit(options) { return bindDeposit(this, options); }
  batchManifest(options) { return batchManifest(this, options); }
}
