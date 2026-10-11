import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setup } from './setup.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(path.dirname(fileURLToPath(import.meta.url)), '.setup-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'bundle'), trust = path.join(root, 'trust');
  const base = path.join(root, 'profiles'), datadir = path.join(root, 'bitcoin');
  await Promise.all([fs.mkdir(source), fs.mkdir(trust), fs.mkdir(datadir, { mode: 0o700 })]);
  await fs.writeFile(path.join(datadir, '.cookie'), 'synthetic-cookie', { mode: 0o600 });
  const cert = path.join(source, 'certificate.pem'), key = path.join(root, 'key.pem');
  const opensslConfig = path.join(root, 'openssl.cnf');
  await fs.writeFile(opensslConfig, '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=signer.internal\n');
  execFileSync('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', opensslConfig, '-keyout', key, '-out', cert], { stdio: 'ignore' });
  const suite = '11'.repeat(32);
  const manifestBytes = Buffer.from('{"synthetic":true}');
  const files = [
    ['certificate.pem', await fs.readFile(cert)],
    ['suite/suite-manifest.json', manifestBytes],
    ['tools/bb', Buffer.from('fake bb')],
    ['tools/bitcoin-cli-core-30.2', Buffer.from('fake bitcoin cli')],
    ['tools/nargo', Buffer.from('fake nargo')],
    ['crs/bn254_g1.dat', Buffer.from('fake crs')],
    ['crs/bn254_g1_compressed.dat', Buffer.from('fake compressed crs')],
  ];
  for (const [name, bytes] of files) {
    const file = path.join(source, name);
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, bytes, { mode: name.startsWith('tools/') ? 0o700 : 0o600 });
  }
  const nargo = 'bigcurve = { path = "/synthetic/work/deps/noir_bigcurve" }\n';
  const nargoPath = path.join(source, 'circuits/relations/Nargo.toml');
  await fs.mkdir(path.dirname(nargoPath), { recursive: true });
  await fs.writeFile(nargoPath, nargo);
  const pins = { version: 10, deployment: '22'.repeat(32), suite,
    manifest_sha256: sha(manifestBytes),
    certificate_sha256: sha(new X509Certificate(await fs.readFile(cert)).raw),
    bitcoin_cli_sha256: sha(files.find(([name]) => name === 'tools/bitcoin-cli-core-30.2')[1]) };
  await fs.writeFile(path.join(trust, 'public-deployment-pins.json'), JSON.stringify(pins));
  await fs.writeFile(path.join(trust, 'deployment.json'), JSON.stringify({ protocol_version: 10, signer_protocol_version: 5, suite, network: 'custom_signet' }));
  await fs.writeFile(path.join(trust, 'asset-hashes.json'), JSON.stringify({ version: 1,
    files: [...files.map(([name, bytes]) => ({ path: name, sha256: sha(bytes) })),
      { path: 'circuits/relations/Nargo.toml', sha256: sha('bigcurve = { path = "../../deps/noir_bigcurve" }\n'), source_sha256: sha(nargo), rewrite: 'deps' }], programs: [] }));
  await fs.copyFile(cert, path.join(trust, 'public-chain-certificate.pem'));
  await fs.writeFile(path.join(trust, 'public-services.json'), JSON.stringify({ version: 1,
    signer_address: '127.0.0.1:17448', chain_address: '127.0.0.1:17449',
    chain_server_name: 'chain.internal', chain_certificate_sha256: pins.certificate_sha256 }));
  const env = { ZARK_PROFILE: 'alice', ZARK_DESKTOP_BASE: base, ZARK_ASSET_SOURCE: source,
    ZARK_BITCOIN_DATADIR: datadir, ZARK_WALLET_BINARY: path.join(source, 'tools/bitcoin-cli-core-30.2') };
  const options = { homeDirectory: root, trustedDirectory: trust,
    // These synthetic ordinary-tool hashes model the native Mac manifest.
    // Linux release substitutions are exercised separately in platform.test.mjs.
    platform: 'darwin-arm64', circuitSourceDirectory: path.join(source, 'circuits'), checkConnections: false };
  return { root, source, trust, base, datadir, pins, env, options };
}

async function admitSignedTools(f) {
  const file = path.join(f.trust, 'asset-hashes.json');
  const previous = await fs.readFile(file);
  const hash = sha(previous);
  await fs.writeFile(path.join(f.trust, `asset-hashes-${hash}.json`), previous);
  const current = JSON.parse(previous);
  for (const name of ['tools/nargo', 'tools/bb']) {
    const bytes = Buffer.from(`signed ${name}`);
    await fs.writeFile(path.join(f.source, name), bytes);
    current.files.find(entry => entry.path === name).sha256 = sha(bytes);
  }
  current.asset_revision = sha(JSON.stringify(current.files));
  current.previous_asset_manifests = [hash];
  await fs.writeFile(file, JSON.stringify(current));
  return { current, hash };
}

test('signed tool updates preserve frozen wallets and isolate new profiles in the same base', async t => {
  const f = await fixture(t);
  const alice = await setup(f.env, f.options);
  const frozen = await fs.readFile(alice.sourceConfigPath);
  const oldConfig = JSON.parse(frozen);
  const pending = path.join(alice.home, 'pending-proof.fixture');
  await fs.writeFile(pending, 'preserve this pending operation', { mode: 0o600 });
  const { current } = await admitSignedTools(f);
  await setup(f.env, f.options);
  const bob = await setup({ ...f.env, ZARK_PROFILE: 'bob' }, f.options);
  const newConfig = JSON.parse(await fs.readFile(bob.sourceConfigPath));
  assert.ok(newConfig.nargo.path.includes(`/revisions/${current.asset_revision}/`));
  assert.notEqual(newConfig.nargo.path, oldConfig.nargo.path);
  assert.equal(await fs.readFile(newConfig.nargo.path, 'utf8'), 'signed tools/nargo');
  assert.equal(await fs.readFile(oldConfig.nargo.path, 'utf8'), 'fake nargo');
  await setup(f.env, f.options);
  await setup({ ...f.env, ZARK_PROFILE: 'bob' }, f.options);
  assert.deepEqual(await fs.readFile(alice.sourceConfigPath), frozen);
  assert.equal(await fs.readFile(pending, 'utf8'), 'preserve this pending operation');
});

test('signed updates reject altered admission history and corrupted legacy tools', async t => {
  const f = await fixture(t);
  const alice = await setup(f.env, f.options);
  const config = JSON.parse(await fs.readFile(alice.sourceConfigPath));
  const { hash } = await admitSignedTools(f);
  const historyFile = path.join(f.trust, `asset-hashes-${hash}.json`);
  const history = await fs.readFile(historyFile);
  await fs.appendFile(historyFile, ' ');
  await assert.rejects(setup(f.env, f.options), /Previous asset manifest hash mismatch/);
  await fs.writeFile(historyFile, history);
  await fs.writeFile(config.nargo.path, 'modified cached executable');
  await assert.rejects(setup(f.env, f.options), /Cached asset hash mismatch/);
});

test('signed updates refuse to invent tool compatibility for an unknown frozen path', async t => {
  const f = await fixture(t);
  const alice = await setup(f.env, f.options);
  const config = JSON.parse(await fs.readFile(alice.sourceConfigPath));
  await admitSignedTools(f);
  config.manifest = path.join(f.base, 'unknown/suite-manifest.json');
  await fs.writeFile(alice.sourceConfigPath, JSON.stringify(config));
  await assert.rejects(setup(f.env, f.options), /No admitted tools match this frozen wallet/);
});

test('first launch creates private profiles; repeat launch reuses frozen state and assets', async t => {
  const f = await fixture(t);
  const alice = await setup(f.env, f.options);
  const original = await fs.readFile(alice.sourceConfigPath);
  assert.equal((await fs.stat(alice.home)).mode & 0o777, 0o700);
  assert.equal((await fs.stat(alice.sourceConfigPath)).mode & 0o777, 0o600);
  assert.equal(await fs.readFile(path.join(f.base, 'assets', f.pins.suite, 'circuits/relations/Nargo.toml'), 'utf8'),
    'bigcurve = { path = "../../deps/noir_bigcurve" }\n');
  await fs.mkdir(path.join(alice.home, '.desktop'), { mode: 0o700 });
  await fs.writeFile(path.join(alice.home, '.desktop', 'journal'), 'keep', { mode: 0o600 });
  await setup(f.env, f.options);
  assert.deepEqual(await fs.readFile(alice.sourceConfigPath), original);
  assert.equal(await fs.readFile(path.join(alice.home, '.desktop', 'journal'), 'utf8'), 'keep');
  const bob = await setup({ ...f.env, ZARK_PROFILE: 'bob' }, f.options);
  assert.notEqual(alice.home, bob.home);
  assert.deepEqual(await fs.readFile(bob.sourceConfigPath), original);
});

test('fresh v10 setup freezes the pinned local executor, prover and helper', async t => {
  const f = await fixture(t);
  const manifestPath = path.join(f.trust, 'asset-hashes.json');
  const manifest = JSON.parse(await fs.readFile(manifestPath));
  const names = ['tools/noir-execute-fast-gzip', 'tools/bb-cap15', 'tools/zark-fast-helper', 'tools/python/bin/python3'];
  for (const name of names) {
    const bytes = Buffer.from(`synthetic ${name}`);
    await fs.mkdir(path.dirname(path.join(f.source, name)), { recursive: true });
    await fs.writeFile(path.join(f.source, name), bytes);
    manifest.files.push({ path: name, sha256: sha(bytes) });
  }
  manifest.fast_runtime = { platform: f.options.platform, executor: names[0],
    prover: names[1], helper: names[2], python: names[3], witness_threads: 8, prove_threads: 16, verify_threads: 8,
    extended_native_hints: true };
  await fs.writeFile(manifestPath, JSON.stringify(manifest));
  const result = await setup(f.env, f.options);
  const saved = await fs.readFile(result.sourceConfigPath);
  const runtime = JSON.parse(saved).fast_runtime;
  assert.deepEqual(Object.keys(runtime).sort(),
    ['executor', 'extended_native_hints', 'helper', 'prove_threads', 'prover', 'verify_threads', 'witness_threads']);
  assert.equal(runtime.extended_native_hints, true);
  assert.equal(runtime.prove_threads, 16);
  assert.equal(runtime.helper.sha256, manifest.files.find(e => e.path === names[2]).sha256);
  assert.ok(runtime.helper.path.endsWith(names[2]));
  await setup(f.env, f.options);
  assert.deepEqual(await fs.readFile(result.sourceConfigPath), saved);
  manifest.fast_runtime.extended_native_hints = 'true';
  await fs.writeFile(manifestPath, JSON.stringify(manifest));
  await assert.rejects(setup({ ...f.env, ZARK_PROFILE: 'bad-hints' }, f.options), /Invalid extended native hints/);
  assert.deepEqual(await fs.readFile(result.sourceConfigPath), saved);
});

test('a frozen profile pinning the retired Python helper is named and left untouched', async t => {
  const f = await fixture(t);
  const manifestPath = path.join(f.trust, 'asset-hashes.json');
  const manifest = JSON.parse(await fs.readFile(manifestPath));
  const names = ['tools/noir-execute-fast-gzip', 'tools/bb-cap15', 'tools/zark-fast-helper'];
  for (const name of names) {
    const bytes = Buffer.from(`synthetic ${name}`);
    await fs.writeFile(path.join(f.source, name), bytes);
    manifest.files.push({ path: name, sha256: sha(bytes) });
  }
  manifest.fast_runtime = { platform: f.options.platform, executor: names[0],
    prover: names[1], helper: names[2], witness_threads: 8, prove_threads: 16, verify_threads: 8 };
  await fs.writeFile(manifestPath, JSON.stringify(manifest));
  const result = await setup(f.env, f.options);
  // Recreate what the Python-helper build froze: no helper binary was installed.
  const config = JSON.parse(await fs.readFile(result.sourceConfigPath));
  const { helper, ...runtime } = config.fast_runtime;
  config.fast_runtime = { ...runtime, python: helper, python_assets: {},
    helper_directory: path.join(f.base, 'assets', f.pins.suite, 'runtime/fast-prover/helper'), helper_sha256: {} };
  await fs.writeFile(result.sourceConfigPath, JSON.stringify(config));
  const frozen = await fs.readFile(result.sourceConfigPath);
  const installed = path.join(f.base, 'assets', f.pins.suite, names[2]);
  await fs.unlink(installed);
  const pending = path.join(result.home, 'pending-proof.json');
  await fs.writeFile(pending, 'pending operation', { mode: 0o600 });
  await assert.rejects(setup(f.env, f.options), /retired Python fast-prover helper/);
  assert.deepEqual(await fs.readFile(result.sourceConfigPath), frozen);
  assert.equal(await fs.readFile(pending, 'utf8'), 'pending operation');
  await assert.rejects(fs.access(installed), /ENOENT/);
});

test('v9 setup leaves existing wallet state untouched and requires a separate deployment', async t => {
  const f = await fixture(t);
  await fs.mkdir(path.join(f.base, 'alice'), { recursive: true, mode: 0o700 });
  const state = path.join(f.base, 'alice', 'pending.json');
  await fs.writeFile(state, 'existing v9 pending operation', { mode: 0o600 });
  await fs.writeFile(path.join(f.trust, 'public-deployment-pins.json'), JSON.stringify({ ...f.pins, version: 9 }));
  await assert.rejects(setup(f.env, f.options), /fresh deployment and profile/);
  assert.equal(await fs.readFile(state, 'utf8'), 'existing v9 pending operation');
  await assert.rejects(fs.access(path.join(f.base, 'alice', 'wallet.json')), /ENOENT/);
});

test('interrupted setup resumes only after the missing authenticated asset arrives', async t => {
  const f = await fixture(t);
  const missing = path.join(f.source, 'tools/nargo');
  const bytes = await fs.readFile(missing);
  await fs.unlink(missing);
  await assert.rejects(setup(f.env, f.options), /Missing bundle asset/);
  await assert.rejects(fs.access(path.join(f.base, 'alice', 'wallet.json')), /ENOENT/);
  await fs.writeFile(missing, bytes);
  await setup(f.env, f.options);
});

test('tampered assets, certificate, deployment pins and profile configuration fail closed', async t => {
  const f = await fixture(t);
  await setup(f.env, f.options);
  const cachedTool = path.join(f.base, 'assets', f.pins.suite, 'tools/nargo');
  await fs.writeFile(cachedTool, 'tampered');
  await assert.rejects(setup(f.env, f.options), /Cached asset hash mismatch/);
  await fs.writeFile(cachedTool, 'fake nargo');
  const certificate = path.join(f.base, 'certificate.pem');
  const certBytes = await fs.readFile(certificate);
  await fs.writeFile(certificate, 'tampered certificate');
  await assert.rejects(setup(f.env, f.options), /Cached asset hash mismatch/);
  await fs.writeFile(certificate, certBytes);
  const pinFile = path.join(f.base, 'deployment-pins.json');
  const pinBytes = await fs.readFile(pinFile);
  await fs.writeFile(pinFile, JSON.stringify({ ...f.pins, deployment: 'ff'.repeat(32) }));
  await assert.rejects(setup(f.env, f.options), /deployment pins do not match/);
  await fs.writeFile(pinFile, pinBytes);
  const wallet = path.join(f.base, 'alice/wallet.json');
  const config = JSON.parse(await fs.readFile(wallet));
  config.deployment.suite = 'ff'.repeat(32);
  await fs.writeFile(wallet, JSON.stringify(config));
  await assert.rejects(setup(f.env, f.options), /does not match/);
});

test('missing service connections are reported after durable first setup', async t => {
  const f = await fixture(t);
  await assert.rejects(setup({ ...f.env, ZARK_SIGNER_ADDRESS: '127.0.0.1:1' }, { ...f.options, checkConnections: true }), /Signer unavailable/);
  await fs.access(path.join(f.base, 'alice/wallet.json'));
});

test('first setup accepts private Bitcoin CLI config auth and rejects exposed cookies', async t => {
  const f = await fixture(t);
  const cookie = path.join(f.datadir, '.cookie');
  await fs.chmod(cookie, 0o644);
  await assert.rejects(setup(f.env, f.options), /credential file must be private/);
  await fs.unlink(cookie);
  await fs.writeFile(path.join(f.datadir, 'bitcoin.conf'), 'synthetic config', { mode: 0o600 });
  await setup(f.env, f.options);
  const config = JSON.parse(await fs.readFile(path.join(f.base, 'alice/wallet.json')));
  assert.equal(config.chain.rpc_cookie, null);
});

test('public first launch creates separate frozen local bridge credentials for Alice and Bob', async t => {
  const f = await fixture(t);
  const { ZARK_BITCOIN_DATADIR, ...remote } = f.env;
  const alice = await setup(remote, f.options);
  const aliceConfig = JSON.parse(await fs.readFile(alice.sourceConfigPath));
  const aliceBridge = JSON.parse(await fs.readFile(path.join(f.base, 'bridge/alice/bridge.json')));
  const aliceCookie = await fs.readFile(aliceBridge.cookie_file);
  assert.equal(aliceConfig.endpoint.address, '127.0.0.1:17448');
  assert.equal(aliceConfig.chain.rpc_port, aliceBridge.port);
  assert.equal(aliceConfig.chain.rpc_cookie, aliceBridge.cookie_file);
  assert.equal((await fs.stat(aliceBridge.cookie_file)).mode & 0o777, 0o600);
  await setup(remote, f.options);
  assert.deepEqual(await fs.readFile(aliceBridge.cookie_file), aliceCookie);
  const bob = await setup({ ...remote, ZARK_PROFILE: 'bob' }, f.options);
  const bobConfig = JSON.parse(await fs.readFile(bob.sourceConfigPath));
  assert.notEqual(bobConfig.chain.rpc_port, aliceConfig.chain.rpc_port);
  assert.notEqual(bobConfig.chain.rpc_cookie, aliceConfig.chain.rpc_cookie);
  assert.notDeepEqual(await fs.readFile(bobConfig.chain.rpc_cookie), aliceCookie);
});

test('legacy base pins and profile stay frozen when a new profile uses the portable CLI', async t => {
  const f = await fixture(t);
  const alice = await setup(f.env, f.options);
  const legacyHash = '02f2a18a00117ab2c5a144530804901be709f7c77444cd13e19daed21b7d2389';
  const oldCli = path.join(f.base, 'assets', f.pins.suite, 'tools/bitcoin-cli');
  await fs.writeFile(oldCli, 'synthetic old executable', { mode: 0o700 });
  const oldConfig = JSON.parse(await fs.readFile(alice.sourceConfigPath));
  oldConfig.bitcoin_cli_sha256 = legacyHash;
  oldConfig.chain.bitcoin_cli = oldCli;
  await fs.rm(path.join(alice.home, '.desktop-gui'), { recursive: true });
  await fs.writeFile(alice.sourceConfigPath, JSON.stringify(oldConfig));
  const oldPins = { ...f.pins, bitcoin_cli_sha256: legacyHash };
  const basePinFile = path.join(f.base, 'deployment-pins.json');
  await fs.writeFile(basePinFile, JSON.stringify(oldPins));
  await fs.unlink(path.join(f.base, 'assets', f.pins.suite, 'tools/bitcoin-cli-core-30.2'));
  await setup(f.env, f.options);
  assert.deepEqual(JSON.parse(await fs.readFile(alice.sourceConfigPath)), oldConfig);
  assert.deepEqual(JSON.parse(await fs.readFile(basePinFile)), oldPins);
  const bob = await setup({ ...f.env, ZARK_PROFILE: 'bob' }, f.options);
  const bobConfig = JSON.parse(await fs.readFile(bob.sourceConfigPath));
  assert.equal(bobConfig.bitcoin_cli_sha256, f.pins.bitcoin_cli_sha256);
  assert.equal(bobConfig.chain.bitcoin_cli, path.join(f.base, 'assets', f.pins.suite, 'tools/bitcoin-cli-core-30.2'));
  assert.deepEqual(JSON.parse(await fs.readFile(basePinFile)), oldPins);
});

test('a release installs precompiled circuits only when every file matches its pin', async t => {
  const f = await fixture(t);
  const manifest = JSON.parse(await fs.readFile(path.join(f.trust, 'asset-hashes.json'), 'utf8'));
  manifest.programs = [{ role: 'deposit_authorization', directory: 'private-deposit-authorize', artifact: 'private_deposit_authorize.json' }];
  manifest.prebuilt_required = true;
  const built = {
    'circuits/private-deposit-authorize/target/private_deposit_authorize.json': '{"compiled":true}',
    'suite/deposit_authorization/circuit.json': '{"compiled":true}',
    'suite/deposit_authorization/vk': 'verification key',
    'suite/deposit_authorization/vk.json': '{"vk":true}',
  };
  manifest.files.push(...Object.entries(built).map(([name, bytes]) => ({ path: name, sha256: sha(bytes) })));
  await fs.writeFile(path.join(f.trust, 'asset-hashes.json'), JSON.stringify(manifest));
  await assert.rejects(setup(f.env, f.options), /complete bundled circuits/);
  const prebuilt = path.join(f.root, 'prebuilt');
  for (const [name, bytes] of Object.entries(built)) {
    await fs.mkdir(path.dirname(path.join(prebuilt, name)), { recursive: true });
    await fs.writeFile(path.join(prebuilt, name), bytes);
  }
  // The synthetic tools cannot compile, so success proves nothing was rebuilt.
  await fs.writeFile(path.join(prebuilt, 'suite/deposit_authorization/vk'), 'tampered key');
  await assert.rejects(setup(f.env, { ...f.options, prebuiltDirectory: prebuilt }), /hash mismatch/);
  await fs.writeFile(path.join(prebuilt, 'suite/deposit_authorization/vk'), built['suite/deposit_authorization/vk']);
  const progress = [];
  await setup(f.env, { ...f.options, prebuiltDirectory: prebuilt, onProgress: message => progress.push(message) });
  assert.ok(progress.includes('Installed precompiled deposit_authorization'));
  const installed = path.join(f.base, 'assets', f.pins.suite, 'suite/deposit_authorization/vk');
  assert.equal(await fs.readFile(installed, 'utf8'), 'verification key');
});
