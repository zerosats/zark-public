import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { ensureSourceRuntime } from './source-runtime.mjs';

const sha = data => createHash('sha256').update(data).digest('hex');
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'zark-source-runtime-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const deployment = 'd'.repeat(64), archive = Buffer.from('qualified release');
  const pins = { version: 10, deployment, suite: 'a'.repeat(64), manifest_sha256: 'b'.repeat(64), certificate_sha256: 'c'.repeat(64), bitcoin_cli_sha256: 'e'.repeat(64) };
  const inventory = { prebuilt_required: true, fast_runtime: { platform: 'linux-arm64' }, files: [{ path: 'tools/prover', sha256: sha('prover') }] };
  const trust = { 'public-deployment-pins.json': JSON.stringify(pins), 'asset-hashes.json': JSON.stringify(inventory) };
  const release = { deployment, trust: {}, platforms: { 'linux-arm64': { asset: 'runtime.AppImage', sha256: sha(archive), trust: Object.fromEntries(Object.entries(trust).map(([k, v]) => [k, sha(v)])) } } };
  let downloads = 0, extractions = 0;
  const options = { platform: 'linux-arm64', home: root, release, log() {},
    async download(file) { downloads++; await writeFile(file, archive); },
    async unpack(_archive, _stage, destination) {
      extractions++;
      await mkdir(path.join(destination, 'trust'), { recursive: true });
      await mkdir(path.join(destination, 'prebuilt/tools'), { recursive: true });
      for (const [name, bytes] of Object.entries(trust)) await writeFile(path.join(destination, 'trust', name), bytes);
      await writeFile(path.join(destination, 'prebuilt/tools/prover'), 'prover');
    } };
  const env = { ZARK_RUNTIME_CACHE: path.join(root, 'empty-cache'), XDG_DATA_HOME: path.join(root, 'data') };
  return { root, env, options, release, trust, counts: () => ({ downloads, extractions }) };
}
test('empty cache imports a verified runtime; next launch is offline and preserves profile selection', async t => {
  const f = await fixture(t);
  const first = await ensureSourceRuntime(f.env, f.options);
  assert.ok(first.ZARK_DESKTOP_BASE.endsWith('/deployments/' + f.release.deployment));
  const again = await ensureSourceRuntime({ ...f.env, ZARK_DESKTOP_BASE: '/explicit-wallet-location' }, { ...f.options, download() { throw new Error('must not download'); } });
  assert.equal(first.ZARK_ASSET_SOURCE, again.ZARK_ASSET_SOURCE);
  assert.equal(again.ZARK_DESKTOP_BASE, '/explicit-wallet-location');
  assert.deepEqual(f.counts(), { downloads: 1, extractions: 1 });
});
test('rejects a wrong archive before executing its extractor; retry can succeed', async t => {
  const f = await fixture(t);
  await assert.rejects(ensureSourceRuntime(f.env, { ...f.options, download: file => writeFile(file, 'wrong release') }), /checksum mismatch/);
  assert.equal(f.counts().extractions, 0);
  await ensureSourceRuntime(f.env, f.options);
});
test('rejects altered cached tools and trust without changing wallet state', async t => {
  const f = await fixture(t);
  const ready = await ensureSourceRuntime(f.env, f.options);
  const file = path.join(ready.ZARK_ASSET_SOURCE, 'tools/prover');
  await writeFile(file, 'tampered');
  await assert.rejects(ensureSourceRuntime(f.env, f.options), /checksum mismatch/);
  await writeFile(file, 'prover');
  await writeFile(path.join(ready.ZARK_TRUSTED_RUNTIME, 'public-deployment-pins.json'), JSON.stringify({ version: 10 }));
  await assert.rejects(ensureSourceRuntime(f.env, f.options), /checksum mismatch/);
});
test('an interrupted import is not published as a usable runtime', async t => {
  const f = await fixture(t);
  await assert.rejects(ensureSourceRuntime(f.env, { ...f.options, unpack() { throw new Error('interrupted'); } }), /interrupted/);
  await ensureSourceRuntime(f.env, f.options);
});
test('explicit operator trust remains supported and a partial override is explained', async t => {
  const f = await fixture(t);
  const ready = await ensureSourceRuntime(f.env, f.options);
  assert.deepEqual(await ensureSourceRuntime(ready, { ...f.options, download() { throw new Error('not used'); } }), ready);
  await assert.rejects(ensureSourceRuntime({ ZARK_ASSET_SOURCE: '/custom' }, f.options), /also requires ZARK_TRUSTED_RUNTIME/);
});
test('every supported platform has a fixed archive and trust inventory', async () => {
  const release = JSON.parse(await readFile(new URL('../../../runtime/desktop-release.json', import.meta.url)));
  assert.deepEqual(Object.keys(release.platforms).sort(), ['darwin-arm64', 'linux-arm64', 'linux-x64']);
  for (const target of Object.values(release.platforms)) {
    for (const digest of [target.sha256, target.trust['asset-hashes.json'], target.trust['public-deployment-pins.json']]) assert.match(digest, /^[a-f0-9]{64}$/);
  }
});
