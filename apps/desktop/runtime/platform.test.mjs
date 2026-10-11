import test from 'node:test';
import assert from 'node:assert/strict';
import { PLATFORMS, BITCOIN_CLI, platformKey, platformManifest, platformPins, defaultDataDirectory } from './platform.mjs';

const sampleManifest = { programs: [], files: [
  ...Object.entries(PLATFORMS['darwin-arm64'].releases).map(([path, value]) => ({ path, sha256: value.sha256 })),
  { path: 'tools/nargo', sha256: '33'.repeat(32) },
  { path: 'tools/bb', sha256: '44'.repeat(32) },
  { path: 'suite/deposit_authorization/circuit.json', sha256: '11'.repeat(32) },
] };
const samplePins = { version: 10, suite: '22'.repeat(32),
  bitcoin_cli_sha256: PLATFORMS['darwin-arm64'].releases[BITCOIN_CLI].sha256 };


test('only qualified platforms are accepted', () => {
  assert.equal(platformKey('darwin', 'arm64'), 'darwin-arm64');
  assert.equal(platformKey('linux', 'x64'), 'linux-x64');
  assert.equal(platformKey('linux', 'arm64'), 'linux-arm64');
  assert.throws(() => platformKey('darwin', 'x64'), /not darwin-x64/);
  assert.throws(() => platformKey('win32', 'x64'), /not win32-x64/);
});

test('Apple Silicon keeps the checked-in asset and deployment pins unchanged', async () => {
  const manifest = structuredClone(sampleManifest);
  const pins = structuredClone(samplePins);
  const mac = platformManifest(manifest, 'darwin-arm64');
  assert.deepEqual(mac.files.map(({ path, sha256 }) => ({ path, sha256 })), manifest.files.map(({ path, sha256 }) => ({ path, sha256 })));
  assert.deepEqual(platformPins(pins, 'darwin-arm64'), pins);
  // The Mac release download must produce exactly the checked-in binary.
  const cli = manifest.files.find(entry => entry.path === BITCOIN_CLI);
  assert.equal(PLATFORMS['darwin-arm64'].releases[BITCOIN_CLI].sha256, cli.sha256);
  assert.equal(pins.bitcoin_cli_sha256, cli.sha256);
});

test('Linux substitutes only its three release tools and shares every other pin', async () => {
  const manifest = structuredClone(sampleManifest);
  const pins = structuredClone(samplePins);
  for (const key of ['linux-x64', 'linux-arm64']) {
    const linux = platformManifest(manifest, key);
    const changed = linux.files.filter((entry, index) => entry.sha256 !== manifest.files[index].sha256).map(entry => entry.path).sort();
    assert.deepEqual(changed, ['tools/bb', BITCOIN_CLI, 'tools/nargo'].sort());
    for (const entry of linux.files.filter(item => item.release)) {
      assert.match(entry.release.url, /^https:\/\/(github\.com|bitcoincore\.org)\//);
      assert.equal(entry.sha256, entry.release.sha256);
    }
    assert.equal(linux.programs, manifest.programs);
    const linuxPins = platformPins(pins, key);
    assert.deepEqual(Object.keys(linuxPins), Object.keys(pins));
    assert.equal(linuxPins.bitcoin_cli_sha256, PLATFORMS[key].releases[BITCOIN_CLI].sha256);
    assert.equal(linuxPins.suite, pins.suite);
  }
});

test('profiles live in Application Support on macOS and XDG data on Linux', () => {
  assert.equal(defaultDataDirectory('/Users/a', {}, 'darwin'), '/Users/a/Library/Application Support/Zark');
  assert.equal(defaultDataDirectory('/home/a', {}, 'linux'), '/home/a/.local/share/zark');
  assert.equal(defaultDataDirectory('/home/a', { XDG_DATA_HOME: '/data' }, 'linux'), '/data/zark');
  assert.equal(defaultDataDirectory('/home/a', { XDG_DATA_HOME: 'relative' }, 'linux'), '/home/a/.local/share/zark');
});

test('fast bundles retain their admitted tools and reject another CPU or OS', () => {
  for (const key of Object.keys(PLATFORMS)) {
    const manifest = { fast_runtime: { platform: key }, files: [
      { path: 'tools/bb', sha256: 'ab'.repeat(32) },
      { path: 'tools/nargo', sha256: 'cd'.repeat(32) },
    ] };
    assert.deepEqual(platformManifest(manifest, key), manifest);
    for (const other of Object.keys(PLATFORMS).filter(value => value !== key)) {
      assert.throws(() => platformManifest(manifest, other), /has not been qualified/);
    }
  }
});
