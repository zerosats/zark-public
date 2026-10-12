// Fresh-checkout runtime regression: no signer requests or faucet claims.
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, readFile } from 'node:fs/promises';
import { ensureSourceRuntime, run } from '../apps/desktop/runtime/source-runtime.mjs';
import { setup } from '../apps/desktop/runtime/setup.mjs';
import { FaucetClient } from '../apps/desktop/runtime/faucet.mjs';

const output = path.resolve(process.argv[2] ?? 'work/source-launch-check');
await mkdir(path.dirname(output), { recursive: true });
await mkdir(output, { mode: 0o700 }); // An existing directory is not a fresh test.
const binary = path.resolve(process.env.ZARK_WALLET_BINARY ?? 'target/debug/zark-wallet');
const env = { ...process.env, ZARK_RUNTIME_CACHE: path.join(output, 'runtime'),
  ZARK_DESKTOP_BASE: path.join(output, 'wallets'), ZARK_PROFILE: 'source-check', ZARK_WALLET_BINARY: binary };
delete env.ZARK_ASSET_SOURCE; delete env.ZARK_TRUSTED_RUNTIME;
const ready = await ensureSourceRuntime(env);
const faucet = await FaucetClient.load(ready.ZARK_TRUSTED_RUNTIME);
assert.ok(faucet.gateway.address && faucet.certificate.length, 'Faucet settings must come from the selected runtime');
const first = await setup(ready, { prebuiltDirectory: ready.ZARK_ASSET_SOURCE, checkConnections: false });
const config = await readFile(first.sourceConfigPath);
const warm = await ensureSourceRuntime(env, { download() { throw new Error('Warm launch tried to download again'); } });
const second = await setup(warm, { prebuiltDirectory: warm.ZARK_ASSET_SOURCE, checkConnections: false });
assert.deepEqual(await readFile(second.sourceConfigPath), config, 'Relaunch must preserve the frozen wallet');
await run(binary, ['--help'], { stdio: 'ignore' });
for (const name of ['nargo', 'bb', 'bitcoin-cli-core-30.2']) {
  await run(path.join(ready.ZARK_ASSET_SOURCE, 'tools', name), ['--version'], { stdio: 'ignore' });
}
console.log('PASS: empty-cache download, authenticated native runtime, fresh source wallet setup and offline cache reuse. No server requests.');
