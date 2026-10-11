import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { configuration, validateConfiguration } from './config.mjs';

const SUITE = '11'.repeat(32);
const PINS = { version: 10, deployment: '22'.repeat(32), suite: SUITE, manifest_sha256: '33'.repeat(32), certificate_sha256: 'bb048f2df9549c2b39385346c6869691bae6dee7584ae5c685e3b1dac760d7bd', bitcoin_cli_sha256: '02f2a18a00117ab2c5a144530804901be709f7c77444cd13e19daed21b7d2389' };

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(path.dirname(fileURLToPath(import.meta.url)), '.config-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const base = path.join(root, 'Library/Application Support/Zark');
  const home = path.join(base, 'alice');
  await fs.mkdir(home, { recursive: true, mode: 0o700 });
  const binary = path.join(root, 'fake-binary');
  await fs.writeFile(binary, 'fixture only', { mode: 0o700 });
  const bitcoinLink = path.join(root, 'bitcoin-cli');
  await fs.symlink(binary, bitcoinLink);
  const chainHome = path.join(path.dirname(base), 'mutinynet/bitcoin-rpc');
  const deployment = { suite: SUITE, network: 'custom_signet', protocol_version: 10, signer_protocol_version: 5 };
  const config = { version: 10, deployment, manifest_sha256: PINS.manifest_sha256,
    endpoint: { address: '127.0.0.1:7448', server_name: 'signer.internal', certificate_sha256: 'bb048f2df9549c2b39385346c6869691bae6dee7584ae5c685e3b1dac760d7bd', ca_certificate: path.join(base, 'certificate.pem'), credential_file: path.join(home, 'signer-token') },
    chain: { deployment: { ...deployment }, bitcoin_cli: bitcoinLink, datadir: chainHome, rpc_cookie: path.join(chainHome, '.cookie'), rpc_port: 38332 },
    bitcoin_cli_sha256: '02f2a18a00117ab2c5a144530804901be709f7c77444cd13e19daed21b7d2389',
  };
  await fs.writeFile(path.join(base, 'deployment-pins.json'), JSON.stringify(PINS), { mode: 0o600 });
  const source = path.join(home, 'wallet.json');
  await fs.writeFile(source, JSON.stringify(config), { mode: 0o600 });
  return { root, home, base, pins: PINS, config, source, binary, env: { ZARK_PROFILE: 'alice', ZARK_DESKTOP_BASE: base, ZARK_WALLET_BINARY: binary } };
}

test('configuration freezes private copy without changing source and resolves pinned Bitcoin executable', async t => {
  const data = await fixture(t);
  const original = await fs.readFile(data.source);
  const loaded = await configuration(data.env, { homeDirectory: data.root });
  assert.notEqual(loaded.configPath, data.source);
  assert.equal(loaded.sourceConfigPath, data.source);
  assert.equal(loaded.bitcoinCli, data.binary);
  assert.deepEqual(await fs.readFile(loaded.configPath), original);
  assert.deepEqual(await fs.readFile(data.source), original);
  assert.equal((await fs.stat(loaded.configPath)).mode & 0o777, 0o600);
  assert.equal((await fs.stat(path.dirname(loaded.configPath))).mode & 0o777, 0o700);
  assert.equal(loaded.config, undefined);
  await configuration(data.env, { homeDirectory: data.root });
  await fs.writeFile(data.source, `${JSON.stringify(data.config)}\n`, { mode: 0o600 });
  await assert.rejects(configuration(data.env, { homeDirectory: data.root }), /Frozen wallet input differs/);
  assert.deepEqual(await fs.readFile(loaded.configPath), original);
});

test('configuration rejects endpoint, credential profile, chain, and executable-pin drift', async t => {
  const { config, base, home } = await fixture(t);
  validateConfiguration(config, { base, home, pins: PINS });
  for (const change of [
    c => { c.endpoint.address = 'bad address'; },
    c => { c.endpoint.credential_file = path.join(base, 'bob', 'signer-token'); },
    c => { c.endpoint.certificate_sha256 = '00'.repeat(32); },
    c => { c.chain.rpc_cookie = '/other/.cookie'; },
    c => { c.chain.deployment.network = 'regtest'; },
    c => { c.bitcoin_cli_sha256 = '00'.repeat(32); },
  ]) {
    const altered = structuredClone(config); change(altered);
    assert.throws(() => validateConfiguration(altered, { base, home, pins: PINS }), /does not match/);
  }
});

test('public signer configuration needs no token file and keeps deployment and TLS pins', async t => {
  const data = await fixture(t);
  delete data.config.endpoint.credential_file;
  await fs.writeFile(data.source, JSON.stringify(data.config), { mode: 0o600 });
  const loaded = await configuration(data.env, { homeDirectory: data.root });
  assert.equal(JSON.parse(await fs.readFile(loaded.configPath)).endpoint.credential_file, undefined);
  data.config.endpoint.certificate_sha256 = '00'.repeat(32);
  assert.throws(() => validateConfiguration(data.config, data), /does not match/);
});

test('new portable Bitcoin CLI may share an existing base with frozen legacy pins', async t => {
  const data = await fixture(t);
  data.config.bitcoin_cli_sha256 = '6c8024645f1f5eeb6f1f93f9f790771c322eb077eed4d5b3ff76e5a7be8bf1c2';
  validateConfiguration(data.config, { base: data.base, home: data.home, pins: data.pins });
});

test('configuration rejects unsafe source mode, oversized configuration, and unlisted profiles', async t => {
  const data = await fixture(t);
  await fs.chmod(data.source, 0o644);
  await assert.rejects(configuration(data.env, { homeDirectory: data.root }), /Invalid private wallet file/);
  await fs.chmod(data.source, 0o600);
  await fs.writeFile(data.source, Buffer.alloc(1_000_001));
  await assert.rejects(configuration(data.env, { homeDirectory: data.root }), /Invalid private wallet file/);
  await assert.rejects(configuration({ ...data.env, ZARK_PROFILE: '../bob' }, { homeDirectory: data.root }), /Invalid wallet profile name/);
});
