import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WalletAdapter } from './wallet.mjs';

const directory = path.dirname(fileURLToPath(import.meta.url));
const COIN = '11'.repeat(32);
const TRANSFER = '22'.repeat(32);
const MANIFEST = '33'.repeat(32);
const DEPLOYMENT = '44'.repeat(32);
const PRIVATE_MARKER = 'do-not-return-secret';

test('native swap group preserves exact child results and never calls individual receive', async t => {
  const calls = [];
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    calls.push(args[2]);
    const operation = await operationFromArgs(args, 'swap_group');
    return response({ operation, completed: false, incoming: [{ operation: path.join(home, '.desktop', 'operations', 'incoming'), coin: COIN, accepted: false, recovery_saved: false, secret: PRIVATE_MARKER }], outgoing: [{ operation: path.join(home, 'sender'), completed: false, secret: PRIVATE_MARKER }] });
  });
  await adapter.snapshot();
  const operationPath = path.join(home, '.desktop', 'operations', 'group'), planPath = path.join(home, 'plan.json');
  await json(planPath, { version: 1 });
  const result = await adapter.swapGroup({ operationPath, planPath });
  assert.equal(result.incoming.length, 1); assert.equal(result.outgoing.length, 1);
  assert.equal(result.completed, false); assert.ok(!JSON.stringify(result).includes(PRIVATE_MARKER));
  assert.deepEqual(calls, ['swap-group']);
  await fs.rm(planPath);
  await adapter.swapGroup({ operationPath, planPath });
  assert.deepEqual(calls, ['swap-group', 'advance']);
  await assert.rejects(adapter.swapGroup({ operationPath, planPath: path.join(home, 'changed.json') }), { code: 'operation_conflict' });
});

test('delivery ciphertext is frozen across restarts and changed retries never encrypt again', async t => {
  let encryptions = 0;
  const { home, adapter, settings } = await fixture(t, async (_binary, args) => {
    assert.equal(args[2], 'mail-crypto');
    const input = JSON.parse(await fs.readFile(arg(args, '--input')));
    assert.equal(input.op, 'seal');
    encryptions++;
    await json(arg(args, '--output'), { ciphertext: 'ab'.repeat(100) });
    return response({ completed: true });
  });
  const message = { id: 'private-logical-id', kind: 'coin', payload: { coin: COIN, amountSat: 50000 } };
  const first = await adapter.sealDelivery('tzark1example', message);
  assert.match(first.id, /^[a-f0-9]{64}$/);
  assert.notEqual(first.id, message.id);
  const restarted = new WalletAdapter(settings);
  assert.deepEqual(await restarted.sealDelivery('tzark1example', message), first);
  await assert.rejects(restarted.sealDelivery('tzark1example', { ...message, payload: { amountSat: 2 } }), e => e.code === 'message_conflict');
  assert.equal(encryptions, 1);
  assert.ok(!(await fs.readdir(path.join(home, '.desktop'))).some(name => name.startsWith('mail-crypto-')));
});

async function json(file, data) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  await fs.writeFile(file, JSON.stringify(data), { mode: 0o600 });
}
function response(result = {}) { return { code: 0, stdout: JSON.stringify({ api_version: 1, ok: true, result }), stderr: '' }; }
const arg = (args, name) => args[args.indexOf(name) + 1];
async function fixture(t, runner = async () => response(), validateRunner = async (_binary, args) => response({ valid: true, kind: arg(args, '--address').startsWith('tb1') ? 'bitcoin' : 'zark' })) {
  const home = await fs.mkdtemp(path.join(directory, '.wallet-test-'));
  await fs.chmod(home, 0o700);
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const configPath = path.join(home, 'wallet.json');
  await json(configPath, { version: 10, manifest_sha256: MANIFEST });
  const settings = { home, configPath, walletBinary: '/test/bin/zark-wallet', runner: (binary, args, options) => (args[2] === 'validate-address' ? validateRunner : runner)(binary, args, options) };
  return { home, adapter: new WalletAdapter(settings), settings };
}
async function owner(home, { name = 'origin', coin = COIN, kind = 'origin', outgoing = null, accepted = true, amount = 25000 } = {}) {
  const operation = path.join(home, name);
  await json(path.join(operation, 'operation.json'), {
    version: 10, deployment: DEPLOYMENT, manifest_sha256: MANIFEST,
    kind: { kind, ...(kind === 'origin' ? { amount, activation_fee: 1000, recovery_fee: 1000 } : { coin, invitation: '/hidden/invitation', transfer_operation: TRANSFER }) },
  });
  await json(path.join(operation, 'journal', kind === 'origin' ? 'origin-operation.json' : 'recipient-operation.json'), {
    schema: kind === 'origin' ? 'zark-origin' : 'zark-recipient-operation',
    version: 3,
    context: { coin: [...Buffer.from(coin, 'hex')], operation: [...Buffer.from(TRANSFER, 'hex')] },
    amount, funding_broadcast: accepted, certificate: accepted ? { proof: PRIVATE_MARKER } : null,
    outgoing, stage: { phase: 'draft_frozen', recovery: { accepted, outgoing, payout: PRIVATE_MARKER } },
    offer: PRIVATE_MARKER, user: PRIVATE_MARKER, session: PRIVATE_MARKER,
  });
  await json(path.join(operation, 'journal', 'own-recovery', 'recovery-draft.json'), {
    activation_input: { amount }, backing: { amount: amount - 1000 }, user_secret: PRIVATE_MARKER,
  });
  return operation;
}
async function operationFromArgs(args, kind = 'sender') {
  const operation = arg(args, '--operation');
  await json(path.join(operation, 'operation.json'), { version: 10, manifest_sha256: MANIFEST, kind: { kind } });
  return operation;
}

test('snapshot discovers gross-deposit owner amounts without exposing secrets or invoking CLI', async t => {
  const { home, adapter } = await fixture(t, () => { throw new Error('snapshot must not invoke CLI'); });
  const root = await owner(home);
  await owner(home, { name: 'recipient', kind: 'receiver', coin: '55'.repeat(32) });
  await owner(home, { name: 'old-owner', coin: '66'.repeat(32), outgoing: { kind: 'transfer', directory: '/hidden/outgoing' } });
  await owner(home, { name: 'withdrawn-owner', coin: '77'.repeat(32), outgoing: { kind: 'exit', directory: '/hidden/exit' } });
  await owner(home, { name: 'pending', coin: '88'.repeat(32), accepted: false });
  const result = await adapter.snapshot();
  assert.equal(result.coins.length, 2);
  assert.equal(result.coins.find(coin => coin.id === COIN).ownerOperation, root);
  assert.ok(result.coins.every(coin => coin.amountSat === 25000 && coin.recoveryAmountSat === 24000 && coin.status === 'available'));
  assert.equal(result.metadataOnly, true);
  assert.equal(result.currentOwnershipVerified, false);
  assert.ok(!JSON.stringify(result).includes(PRIVATE_MARKER));
  assert.ok(!JSON.stringify(result).includes('invitation'));
  assert.equal((await fs.stat(path.join(home, '.desktop'))).mode & 0o777, 0o700);
  assert.equal((await fs.stat(path.join(home, '.desktop', 'index.json'))).mode & 0o777, 0o600);
  const indexPath = path.join(home, '.desktop', 'index.json');
  const index = JSON.parse(await fs.readFile(indexPath));
  index.operations.push({ kind: 'origin', operationPath: root, lastResult: { phase: 'accepted', secret: PRIVATE_MARKER } });
  await json(indexPath, index);
  const restored = await adapter.snapshot();
  const operation = restored.operations.find(item => item.operationPath === root);
  assert.equal(operation.status, 'available');
  assert.deepEqual(operation.lastResult, { phase: 'accepted' });
  assert.ok(!JSON.stringify(restored).includes(PRIVATE_MARKER));
});

test('only current origin journals are offered as spendable coins', async t => {
  const { home, adapter } = await fixture(t);
  await owner(home);
  const old = await owner(home, { name: 'old-schema', coin: '55'.repeat(32) });
  const file = path.join(old, 'journal', 'origin-operation.json');
  const record = JSON.parse(await fs.readFile(file, 'utf8'));
  record.version = 2;
  await json(file, record);
  const result = await adapter.snapshot();
  assert.deepEqual(result.coins.map(coin => coin.id), [COIN]);
  assert.ok(result.operations.some(operation => operation.operationPath === old));
});

test('ambiguous duplicate local owners and unsafe journals are never spendable', async t => {
  const { home, adapter } = await fixture(t);
  await owner(home);
  await owner(home, { name: 'duplicate', kind: 'receiver' });
  const bad = await owner(home, { name: 'unsafe', coin: '55'.repeat(32) });
  await fs.chmod(path.join(bad, 'journal', 'origin-operation.json'), 0o644);
  const result = await adapter.snapshot();
  assert.deepEqual(result.coins, []);
  assert.equal(result.operations.filter(item => item.status === 'ambiguous').length, 2);
  assert.equal(result.operations.find(item => item.operationPath === bad).status, 'unavailable');
});

test('send persists exact arguments and resumes after restart with no shell or broadcast', async t => {
  const calls = [];
  const { home, adapter, settings } = await fixture(t, async (binary, args, options) => {
    calls.push({ binary, args, options });
    const operation = await operationFromArgs(args);
    return response({ operation, offer: arg(args, '--output'), coin: COIN, transfer_operation: TRANSFER });
  });
  const origin = await owner(home);
  const first = await adapter.send({ coin: COIN, address: 'tzark1recipient' });
  const second = await new WalletAdapter(settings).send({ coin: COIN, address: 'tzark1recipient' });
  assert.equal(first.operationPath, second.operationPath);
  assert.equal(first.offerPath, second.offerPath);
  assert.deepEqual(calls[0].args, calls[1].args);
  assert.equal(arg(calls[0].args, '--owner'), origin);
  assert.equal(calls[0].args[2], 'send');
  assert.equal(calls[0].options.shell, false);
  assert.ok(!calls[0].args.includes('--broadcast'));
  assert.equal(first.transferOperation, TRANSFER);
  await assert.rejects(adapter.send({ coin: COIN, address: 'tzark1different' }), { code: 'operation_conflict' });
  assert.equal(calls.length, 2);
});

test('CLI failure keeps a resumable operation and strips native error/stdout/stderr secrets', async t => {
  const calls = [];
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    calls.push(args);
    await operationFromArgs(args);
    if (calls.length === 1) return { code: 1, stdout: JSON.stringify({ api_version: 1, ok: false, error: { message: PRIVATE_MARKER } }), stderr: PRIVATE_MARKER };
    return response({ operation: arg(args, '--operation'), coin: COIN, private_key: PRIVATE_MARKER });
  });
  await owner(home);
  await assert.rejects(adapter.send({ coin: COIN, address: 'tzark1recipient' }), error => {
    assert.equal(error.code, 'operation_failed');
    assert.ok(error.operationPath);
    assert.ok(!String(error).includes(PRIVATE_MARKER));
    assert.ok(!JSON.stringify(error).includes(PRIVATE_MARKER));
    return true;
  });
  const result = await adapter.send({ coin: COIN, address: 'tzark1recipient' });
  assert.deepEqual(calls[0], calls[1]);
  assert.ok(!JSON.stringify(result).includes(PRIVATE_MARKER));
});

test('native authorization and expected-amount errors become fixed actionable text without secrets', async t => {
  let nativeMessage = `remote command unauthorized: ${PRIVATE_MARKER}`;
  const { adapter } = await fixture(t, async () => ({ code: 1, stdout: JSON.stringify({ api_version: 1, ok: false, error: { message: nativeMessage } }), stderr: PRIVATE_MARKER }));
  await assert.rejects(adapter.verifyAssets(), error => {
    assert.equal(error.code, 'signer_unauthorized');
    assert.equal(error.message, 'Signer authorization required');
    assert.ok(!JSON.stringify(error).includes(PRIVATE_MARKER));
    return true;
  });
  nativeMessage = 'received coin amount differs from expected amount';
  await assert.rejects(adapter.verifyAssets(), { code: 'amount_mismatch', message: 'Coin amount does not match' });
  nativeMessage = 'deposit lacks required confirmations';
  await assert.rejects(adapter.verifyAssets(), { code: 'awaiting_confirmation', message: 'Waiting for a Bitcoin confirmation.' });
  nativeMessage += `: ${PRIVATE_MARKER}`;
  await assert.rejects(adapter.verifyAssets(), { code: 'operation_failed' });
});

test('a published operation missing on resume is never regenerated', async t => {
  let calls = 0;
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    calls++;
    await operationFromArgs(args);
    return response({ operation: arg(args, '--operation'), coin: COIN });
  });
  await owner(home);
  const result = await adapter.send({ coin: COIN, address: 'tzark1recipient' });
  await fs.rename(result.operationPath, `${result.operationPath}-preserved`);
  await assert.rejects(adapter.send({ coin: COIN, address: 'tzark1recipient' }), { code: 'missing_operation' });
  assert.equal(calls, 1);
});

test('wallet mutations are serialized across adapter instances', async t => {
  let active = 0;
  let peak = 0;
  const { adapter, settings } = await fixture(t, async (_binary, args) => {
    active++;
    peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, 20));
    const invitation = arg(args, '--directory');
    await fs.mkdir(invitation, { mode: 0o700 });
    active--;
    return response({ address: `tzark1${path.basename(invitation)}`, directory: invitation, one_use: true });
  });
  const result = await Promise.all([adapter.newAddress(), new WalletAdapter(settings).newAddress()]);
  assert.equal(peak, 1);
  assert.notEqual(result[0].address, result[1].address);
  assert.ok(result[0].invitationPath);
  assert.ok(!JSON.stringify(result[0]).includes('invitation'));
  assert.ok(!JSON.stringify(result[0]).includes('directory'));
});

test('withdraw prepares only and broadcasting requires explicit true', async t => {
  const calls = [];
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    calls.push(args);
    await operationFromArgs(args, 'exit');
    return response({ operation: arg(args, '--operation'), signature_status: 'released_terminal', broadcast: false });
  });
  await owner(home);
  const result = await adapter.withdraw({ coin: COIN, address: 'tb1pwithdraw', feeSat: 1000 });
  assert.equal(calls[0][2], 'exit');
  assert.ok(!calls[0].includes('--broadcast'));
  await adapter.advance(result.operationPath);
  assert.ok(!calls[1].includes('--broadcast'));
  await adapter.advance(result.operationPath, { broadcast: true });
  assert.ok(calls[2].includes('--broadcast'));
  await assert.rejects(adapter.advance(result.operationPath, { broadcast: 'true' }), { code: 'invalid_input' });
});

test('accept validates a locally owned invitation via CLI, freezes context and passes expected gross amount', async t => {
  const calls = [];
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    calls.push(args);
    if (args[2] === 'new-address') return response({ address: 'tzark1verified', directory: arg(args, '--directory'), one_use: true });
    await operationFromArgs(args, 'receiver');
    return response({ operation: arg(args, '--operation'), coin: COIN, phase: 'Accepted', accepted: true, recovery_saved: true });
  });
  const invitationPath = path.join(home, 'invitation');
  await fs.mkdir(invitationPath, { mode: 0o700 });
  const input = { invitationPath, offerPath: path.join(home, 'received.offer'), coin: COIN, transferOperation: TRANSFER, expectedAmountSat: 25000 };
  const result = await adapter.accept(input);
  assert.equal(calls[0][2], 'new-address');
  assert.equal(calls[1][2], 'receive');
  assert.equal(arg(calls[1], '--expected-amount'), '25000');
  assert.equal(arg(calls[1], '--transfer-operation'), TRANSFER);
  assert.equal(result.accepted, true);
  assert.equal(result.raw.accepted, true);
  assert.equal(result.recovery_saved, true);
  assert.ok(!JSON.stringify(result).includes(invitationPath));
  await assert.rejects(adapter.accept({ ...input, expectedAmountSat: 24000 }), { code: 'operation_conflict' });
});

test('deposit preparation and binding reuse frozen state and never implicitly broadcast', async t => {
  const calls = [];
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    calls.push(args);
    await operationFromArgs(args, 'origin');
    return response({ operation: arg(args, '--operation'), funding_address: 'tb1pfunding', transaction_id: args[2] === 'origin-bind' ? TRANSFER : null });
  });
  const created = await adapter.createDeposit({ amountSat: 25000 });
  await adapter.bindDeposit({ operationPath: created.operationPath, transactionPath: path.join(home, 'funding.hex'), vout: 1 });
  const resumed = await adapter.createDeposit({ amountSat: 25000 });
  assert.equal(created.operationPath, resumed.operationPath);
  assert.equal(calls[0][2], 'origin-create');
  assert.equal(calls[1][2], 'origin-bind');
  assert.ok(calls.every(args => !args.includes('--broadcast')));
  await assert.rejects(adapter.bindDeposit({ operationPath: created.operationPath, transactionPath: path.join(home, 'other.hex'), vout: 1 }), { code: 'operation_conflict' });
});

test('a rejected envelope cannot occupy all explicit receive operations for its public context', async t => {
  const receiveCalls = [];
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    if (args[2] === 'new-address') return response({ address: 'tzark1verified', one_use: true });
    receiveCalls.push(args);
    await operationFromArgs(args, 'receiver');
    if (receiveCalls.length === 1) return { code: 1, stdout: JSON.stringify({ api_version: 1, ok: false, error: { message: 'invalid envelope' } }) };
    return response({ operation: arg(args, '--operation'), accepted: true });
  });
  const invitationPath = path.join(home, 'invitation');
  await fs.mkdir(invitationPath, { mode: 0o700 });
  const input = { invitationPath, coin: COIN, transferOperation: TRANSFER, expectedAmountSat: 25000 };
  const rejected = { ...input, offerPath: path.join(home, 'bad.offer'), operationPath: path.join(home, 'bad-receive') };
  await assert.rejects(adapter.accept(rejected), { code: 'operation_failed' });
  const accepted = await adapter.accept({ ...input, offerPath: path.join(home, 'good.offer'), operationPath: path.join(home, 'good-receive') });
  assert.equal(accepted.accepted, true);
  assert.equal(receiveCalls.length, 2);
  await assert.rejects(adapter.accept({ ...rejected, offerPath: path.join(home, 'good.offer') }), { code: 'operation_conflict' });
  assert.equal(receiveCalls.length, 2);
});

test('public batch draft includes only portable fields and manifest resumes exactly', async t => {
  const calls = [];
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    calls.push(args);
    if (args[2] === 'batch-manifest') {
      await json(arg(args, '--output'), { public: true });
      return response({ manifest: arg(args, '--output'), batch: DEPLOYMENT, digest: MANIFEST, members: [COIN, TRANSFER] });
    }
    await operationFromArgs(args);
    return response({ operation: arg(args, '--operation'), context: 'abcdef', coin: COIN, revision: 3, next_action: 'Continue batch.' });
  });
  await owner(home);
  const draft = await adapter.batchDraft({ coin: COIN, address: 'tzark1peer' });
  assert.deepEqual(draft.publicDraft, { context: 'abcdef', coin: COIN, revision: 3 });
  const input = { first: draft.operationPath, peer: path.join(home, 'peer.json'), expiresAt: 1234567890, output: path.join(home, '.desktop', 'exports', 'batch.json') };
  await adapter.batchManifest(input);
  await adapter.batchManifest(input);
  assert.deepEqual(calls[1], calls[2]);
  assert.ok(calls[1].includes('--peer'));
  assert.ok(!calls[1].includes('--second'));
  await fs.rename(input.output, `${input.output}.preserved`);
  await assert.rejects(adapter.batchManifest(input), { code: 'missing_manifest' });
});

test('capped process output and symlinked index fail closed', async t => {
  const { adapter, home } = await fixture(t, async () => ({ stdout: 'x'.repeat(1024 * 1024 + 1), stderr: '' }));
  await assert.rejects(adapter.newAddress(), { code: 'output_limit' });
  const index = path.join(home, '.desktop', 'index.json');
  const preserved = `${index}.preserved`;
  await fs.rename(index, preserved);
  await fs.symlink(preserved, index);
  await assert.rejects(adapter.snapshot(), { code: 'invalid_state' });
});

test('a coin returning to a new owner journal receives a fresh outgoing operation', async t => {
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    if (args[2] === 'complete') return response({ operation: arg(args, '--operation'), completed: true });
    await operationFromArgs(args);
    return response({ operation: arg(args, '--operation'), coin: COIN });
  });
  await owner(home);
  const first = await adapter.send({ coin: COIN, address: 'tzark1first' });
  await adapter.complete(first.operationPath);
  await owner(home, { outgoing: { kind: 'transfer', directory: path.join(first.operationPath, 'journal') } });
  const newOwner = await owner(home, { kind: 'receiver', name: 'returned' });
  const second = await adapter.send({ coin: COIN, address: 'tzark1second' });
  assert.notEqual(first.operationPath, second.operationPath);
  const index = JSON.parse(await fs.readFile(path.join(home, '.desktop', 'index.json'), 'utf8'));
  assert.equal(index.operations.find(item => item.operationPath === second.operationPath).ownerOperation, newOwner);
});

test('verify-assets preserves verification metadata and does not broadcast', async t => {
  const { adapter } = await fixture(t, async (_binary, args) => {
    assert.equal(args[2], 'verify-assets');
    assert.ok(!args.includes('--broadcast'));
    return response({ verified: true, version: 10, deployment: DEPLOYMENT, proof_roles: 6 });
  });
  const result = await adapter.verifyAssets();
  assert.equal(result.verified, true);
  assert.equal(result.proof_roles, 6);
});

test('address validation happens before freezing an outgoing intent', async t => {
  let valid = false, validations = 0, sends = 0;
  const { home, adapter } = await fixture(t, async (_binary, args) => {
    sends++;
    await operationFromArgs(args);
    return response({ operation: arg(args, '--operation'), coin: COIN });
  }, async () => {
    validations++;
    if (!valid) return { code: 1, stdout: JSON.stringify({ api_version: 1, ok: false, error: { message: 'invalid address' } }) };
    return response({ valid: true, kind: 'zark' });
  });
  await owner(home);
  await assert.rejects(adapter.send({ coin: COIN, address: 'bad-address' }), { code: 'operation_failed' });
  assert.equal(sends, 0);
  assert.deepEqual(JSON.parse(await fs.readFile(path.join(home, '.desktop/index.json'))).operations, []);
  valid = true;
  const checked = await adapter.validateAddress('tzark1correct');
  assert.equal(checked.valid, true); assert.equal(checked.kind, 'zark');
  await adapter.send({ coin: COIN, address: 'tzark1correct' });
  await adapter.send({ coin: COIN, address: 'tzark1correct' });
  assert.equal(sends, 2);
  assert.equal(validations, 3); // invalid new, explicit read-only check, valid new; retry reuses intent.
});

test('funding transaction decoding pins bitcoin-cli and uses only read-only RPC with bounded stdin', async t => {
  const calls = [];
  const { home, adapter, settings } = await fixture(t, async (binary, args, options) => {
    calls.push({ binary, args, options });
    return { code: 0, stdout: JSON.stringify({
      txid: TRANSFER, private_key: PRIVATE_MARKER,
      vin: [{ txid: COIN, vout: 0, txinwitness: ['signature'], private_key: PRIVATE_MARKER }],
      vout: [{ value: 0.00025, n: 1, scriptPubKey: { address: 'tb1pfunding', hex: '5120', type: 'witness_v1_taproot' } }],
    }), stderr: '' };
  });
  const binary = path.join(home, 'bitcoin-cli');
  const executable = Buffer.from('test executable');
  await fs.writeFile(binary, executable, { mode: 0o700 });
  await json(settings.configPath, {
    version: 10, manifest_sha256: MANIFEST,
    bitcoin_cli_sha256: createHash('sha256').update(executable).digest('hex'),
    chain: { bitcoin_cli: binary, datadir: path.join(home, 'chain'), rpc_cookie: path.join(home, 'chain', '.cookie'), rpc_port: 12345, deployment: { network: 'custom_signet' } },
  });
  const transaction = path.join(home, 'funding.hex');
  await fs.writeFile(transaction, 'aabbcc\n', { mode: 0o600 });
  const result = await adapter.decodeTransaction(transaction);
  assert.equal(calls[0].binary, binary);
  assert.ok(calls[0].args.includes('decoderawtransaction'));
  assert.ok(calls[0].args.includes('-stdin'));
  assert.ok(calls[0].args.includes('-rpcconnect=127.0.0.1'));
  assert.ok(!calls[0].args.includes('aabbcc'));
  assert.equal(calls[0].options.input, 'aabbcc\n');
  assert.equal(calls[0].options.timeout, 15000);
  assert.equal(result.vout[0].scriptPubKey.address, 'tb1pfunding');
  assert.ok(!JSON.stringify(result).includes(PRIVATE_MARKER));
  await fs.writeFile(binary, 'modified executable');
  await assert.rejects(adapter.decodeTransaction(transaction), { code: 'asset_mismatch' });
  assert.equal(calls.length, 1);
});
