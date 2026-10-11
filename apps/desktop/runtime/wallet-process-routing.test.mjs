import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { WalletAdapter } from './wallet.mjs';

// Exercise the default adapter with actual child processes: injecting a runner
// disables the persistent worker and would miss a worker/bitcoin-cli mix-up.
test('default adapter decodes funding outside its persistent wallet worker', async t => {
  const scratch = fileURLToPath(new URL('../../../work/desktop-process-routing/', import.meta.url));
  await fs.mkdir(scratch, { recursive: true, mode: 0o700 });
  const home = await fs.mkdtemp(path.join(scratch, 'wallet-'));
  await fs.chmod(home, 0o700);
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const configPath = path.join(home, 'wallet.json');
  const walletBinary = path.join(home, 'wallet.cjs');
  const bitcoinCli = path.join(home, 'bitcoin-cli.cjs');
  const executable = script => `#!${process.execPath}\n${script}\n`;
  await fs.writeFile(walletBinary, executable(`
    const assert = require('node:assert/strict');
    assert.deepEqual(process.argv.slice(2), ['--config', ${JSON.stringify(configPath)}, 'worker']);
    process.stdout.write(JSON.stringify({ worker_version: 1, ready: true }) + '\\n');
    require('node:readline').createInterface({ input: process.stdin }).on('line', line => {
      const request = JSON.parse(line);
      assert.deepEqual(request.args, ['verify-assets']);
      process.stdout.write(JSON.stringify({ worker_version: 1, id: request.id,
        response: { api_version: 1, ok: true, result: { verified: true, revision: process.pid } } }) + '\\n');
    });
  `), { mode: 0o700 });
  const decoder = executable(`
    const assert = require('node:assert/strict');
    assert.deepEqual(process.argv.slice(2), ['-signet', ${JSON.stringify(`-datadir=${path.join(home, 'chain')}`)},
      '-rpcport=12345', '-rpcconnect=127.0.0.1', '-rpcclienttimeout=10', '-stdin', 'decoderawtransaction']);
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => input += chunk);
    process.stdin.on('end', () => {
      assert.equal(input, 'aabbcc\\n');
      process.stdout.write(JSON.stringify({ txid: '${'11'.repeat(32)}',
        vin: [{ txinwitness: ['synthetic-signature'] }],
        vout: [{ value: 0.00025, n: 0, scriptPubKey: { address: 'tb1psynthetic' } }] }));
    });
  `);
  await fs.writeFile(bitcoinCli, decoder, { mode: 0o700 });
  await fs.writeFile(configPath, JSON.stringify({
    bitcoin_cli_sha256: createHash('sha256').update(decoder).digest('hex'),
    chain: { bitcoin_cli: bitcoinCli, datadir: path.join(home, 'chain'), rpc_port: 12345,
      deployment: { network: 'custom_signet' } },
  }), { mode: 0o600 });
  const transaction = path.join(home, 'funding.hex');
  await fs.writeFile(transaction, 'aabbcc\n', { mode: 0o600 });
  const wallet = new WalletAdapter({ home, configPath, walletBinary, bitcoinCli });
  t.after(() => wallet.close());
  const first = await wallet.verifyAssets();
  assert.equal(first.verified, true);
  assert.ok(Number.isSafeInteger(first.revision));
  const decoded = await wallet.decodeTransaction(transaction);
  assert.equal(decoded.vout[0].scriptPubKey.address, 'tb1psynthetic');
  assert.deepEqual(decoded.vin[0].txinwitness, ['synthetic-signature']);
  const second = await wallet.verifyAssets();
  assert.equal(second.revision, first.revision);
  // An explicit retry still decodes the same saved funding bytes and leaves
  // the existing worker usable; it must not create another faucet claim.
  assert.deepEqual(await wallet.decodeTransaction(transaction), decoded);
});
