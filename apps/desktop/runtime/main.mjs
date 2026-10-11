import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { configuration, PROTOCOL_VERSION, PROOF_ROLES } from './config.mjs';
import { WalletAdapter } from './wallet.mjs';
import { SignerRelayClient } from '../relay/signer-client.mjs';
import { Controller, safeError } from './controller.mjs';
import { FaucetClient } from './faucet.mjs';
import { lockProfile } from './storage.mjs';
import { timed } from './timing.mjs';

const MAX_REQUEST_BYTES = 16_384;
const MAX_PENDING_OUTPUT = 4_000_000;
const ACTION_ARGS = {
  refresh: [], receive: ['kind'], send: ['coin', 'address'], withdraw: ['coin', 'address', 'feeSat'],
  accept: ['operation'], retry: ['operation'], swapPublish: ['coins'], swapJoin: ['coins', 'offer'], swapApprove: ['swap'],
  swapCancel: ['offer'], deposit: ['amountSat'], depositImport: ['transactionPath'], depositBroadcast: [], testSats: [],
};
const previewSnapshot = {
  totalSat: 50000,
  coins: [{ id: 'a'.repeat(64), amountSat: 25000, ownerOperation: 'preview', status: 'available' },
    { id: 'b'.repeat(64), amountSat: 25000, ownerOperation: 'preview', status: 'available' }],
  offers: [{ id: 'preview-1', amountSat: 25000, own: false }, { id: 'preview-2', amountSat: 50000, own: false }],
  activity: [{ id: 'preview-receive', label: 'Receive', amountSat: 25000, state: 'complete' },
    { id: 'preview-swap', label: 'Swap', amountSat: 25000, state: 'complete' }], connected: true,
};
class InvalidRequest extends Error {
  constructor(id) {
    super('Invalid wallet request');
    if (typeof id === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(id)) this.requestId = id;
  }
}

// Bound each line before buffering/parsing it, and recover at its next newline.
export async function* requestLines(input) {
  let pieces = [];
  let length = 0;
  let oversized = false;
  for await (const chunk of input) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    let offset = 0;
    while (offset < bytes.length) {
      const newline = bytes.indexOf(10, offset);
      const end = newline === -1 ? bytes.length : newline;
      const part = bytes.subarray(offset, end);
      length += part.length;
      if (length > MAX_REQUEST_BYTES) { oversized = true; pieces = []; }
      else if (!oversized) pieces.push(part);
      if (newline === -1) break;
      yield oversized ? null : Buffer.concat(pieces, length).toString('utf8').replace(/\r$/, '');
      pieces = []; length = 0; oversized = false; offset = newline + 1;
    }
  }
  if (length) yield oversized ? null : Buffer.concat(pieces, length).toString('utf8');
}

export function parseRequest(line) {
  if (line === null) throw new InvalidRequest();
  let request;
  try { request = JSON.parse(line); } catch { throw new InvalidRequest(); }
  const invalid = () => new InvalidRequest(request?.id);
  if (!request || typeof request !== 'object' || Array.isArray(request) ||
      typeof request.id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(request.id) ||
      typeof request.action !== 'string' || !Object.hasOwn(ACTION_ARGS, request.action) ||
      !request.args || typeof request.args !== 'object' || Array.isArray(request.args) ||
      Object.keys(request).some(key => !['id', 'action', 'args'].includes(key))) throw invalid();
  const allowed = ACTION_ARGS[request.action];
  if (Object.keys(request.args).length !== allowed.length || Object.keys(request.args).some(key => !allowed.includes(key))) throw invalid();
  for (const [key, value] of Object.entries(request.args)) {
    if (key === 'coins') {
      if (!Array.isArray(value) || value.length < 1 || value.length > 5 || new Set(value).size !== value.length || !value.every(id => typeof id === 'string' && /^[a-f0-9]{64}$/.test(id))) throw invalid();
      continue;
    }
    if (key === 'kind' && !['zark', 'bitcoin'].includes(value)) throw invalid();
    if (['feeSat', 'amountSat'].includes(key)) {
      if (!((typeof value === 'string' && /^[0-9]{1,16}$/.test(value)) || (typeof value === 'number' && Number.isSafeInteger(value) && value > 0))) throw invalid();
    } else if (typeof value !== 'string' || !value || value.length > (key === 'transactionPath' ? 4096 : 1024) || /[\x00-\x1f\x7f]/.test(value)) throw invalid();
  }
  return request;
}

export async function runBackend({
  input = process.stdin, output = process.stdout, env = process.env, signals = process,
  dependencies = {},
} = {}) {
  let release, timer, controller, startupError, wallet;
  let stopping = false;
  let ticking = false;
  const preview = env.ZARK_PREVIEW === '1';
  const stop = () => {
    stopping = true;
    if (timer) clearInterval(timer);
    input.destroy();
  };
  const emit = message => {
    if (output.destroyed || !output.writable) return;
    const encoded = `${JSON.stringify(message)}\n`;
    if (Buffer.byteLength(encoded) + output.writableLength > MAX_PENDING_OUTPUT) { stop(); return; }
    output.write(encoded);
  };
  for (const signal of ['SIGINT', 'SIGTERM']) signals.on(signal, stop);
  output.on('error', stop);
  try {
    if (!preview) {
      try {
        const config = await (dependencies.configuration ?? configuration)(env);
        release = await (dependencies.lockProfile ?? lockProfile)(path.join(config.home, '.desktop-gui'));
        wallet = dependencies.wallet ?? new WalletAdapter(config);
        const verified = await wallet.verifyAssets();
        if (!/^[a-f0-9]{64}$/.test(config.deployment ?? '') || verified.deployment !== config.deployment || verified.verified !== true || verified.version !== PROTOCOL_VERSION || verified.proof_roles !== PROOF_ROLES) throw new Error('Wrong deployment');
        if (!stopping) {
          controller = dependencies.controller ?? new Controller({ wallet, home: config.home, relay: new SignerRelayClient(config.endpoint, wallet), emit,
            decodeTransaction: file => wallet.decodeTransaction(file), faucet: await FaucetClient.load() });
          await controller.initialize();
          // At most one polling tick may be queued behind a long native action.
          timer = setInterval(async () => {
            if (ticking || stopping) return;
            ticking = true;
            try { await controller.tick(); } catch (error) { emit({ error: safeError(error) }); }
            finally { ticking = false; }
          }, 5000);
        }
      } catch (error) {
        startupError = safeError(error);
        controller = undefined;
        emit({ error: startupError });
        await wallet?.close?.();
        await release?.(); release = undefined;
      }
    }
    if (!stopping) {
      for await (const line of requestLines(input)) {
        if (stopping) break;
        let request;
        try {
          request = parseRequest(line);
          if (preview) {
            emit({ id: request.id, snapshot: previewSnapshot, ...(request.action !== 'refresh' ? { error: 'Preview only' } : {}) });
          } else {
            if (!controller) throw new Error('Wallet unavailable');
            const phase = request.action === 'send' ? 'action_send' : request.action === 'accept' ? 'action_receive' : '';
            await timed(phase, () => controller.action(request.action, request.args));
            emit({ id: request.id });
          }
        } catch (error) { emit({ id: request?.id ?? error.requestId, error: error instanceof InvalidRequest ? error.message : safeError(error) }); }
      }
    }
  } catch (error) {
    if (!stopping) { emit({ error: safeError(error) }); startupError = true; }
  } finally {
    stopping = true;
    if (timer) clearInterval(timer);
    // SIGTERM/EOF closes admission, but the already-authorized saved native step
    // drains before its profile lock is released, including prover children.
    if (controller) await controller.tail;
    await wallet?.close?.();
    await release?.();
    for (const signal of ['SIGINT', 'SIGTERM']) signals.off(signal, stop);
    output.off('error', stop);
  }
  return startupError ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runBackend();
}
