import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { buildSourceAssets } from './source-build.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const canonical = '/zark/circuits';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'zark-source-build-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const assets = path.join(root, 'assets');
  async function save(name, bytes, mode = 0o600) {
    const file = path.join(assets, name);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, bytes, { mode });
  }
  const circuitSource = Buffer.from('[package]\nname = "sample"\n');
  const programSource = Buffer.from('fn main() {}\n');
  const dependencySource = Buffer.from('[package]\nname = "noir-lib"\n');
  await save('circuits/sample/Nargo.toml', circuitSource);
  await save('circuits/sample/src/main.nr', programSource);
  await save('deps/noir-lib/Nargo.toml', dependencySource);
  await save('crs/bn254_g1.dat', 'synthetic CRS');
  await save('crs/bn254_g1_compressed.dat', 'synthetic compressed CRS');
  await save('tools/nargo', `#!/bin/sh\nmkdir -p target\nprintf '{"file_map":{"1":{"path":"%s/src/main.nr"}},"bytecode":"synthetic"}' "$PWD" > target/sample.json\n`, 0o700);
  await save('tools/bb', `#!/bin/sh\nformat=binary\nwhile [ "$#" -gt 0 ]; do\n  case "$1" in\n    -o) out=$2; shift 2;;\n    --output_format) format=$2; shift 2;;\n    *) shift;;\n  esac\ndone\nif [ "$format" = binary ]; then printf 'synthetic-vk' > "$out/vk"; else printf '{"hash":"0x01"}' > "$out/vk.json"; fi\n`, 0o700);
  const artifact = Buffer.from(JSON.stringify({ file_map: { 1: { path: `${canonical}/sample/src/main.nr` } }, bytecode: 'synthetic' }));
  const vk = Buffer.from('synthetic-vk'), metadata = Buffer.from('{"hash":"0x01"}');
  const manifest = { files: [
    { path: 'circuits/sample/Nargo.toml', sha256: sha(circuitSource) },
    { path: 'circuits/sample/src/main.nr', sha256: sha(programSource) },
    { path: 'deps/noir-lib/Nargo.toml', sha256: sha(dependencySource) },
    { path: 'crs/bn254_g1.dat', sha256: sha('synthetic CRS') },
    { path: 'crs/bn254_g1_compressed.dat', sha256: sha('synthetic compressed CRS') },
    { path: 'circuits/sample/target/sample.json', sha256: sha(artifact) },
    { path: 'suite/deposit_authorization/circuit.json', sha256: sha(artifact) },
    { path: 'suite/deposit_authorization/vk', sha256: sha(vk) },
    { path: 'suite/deposit_authorization/vk.json', sha256: sha(metadata) },
  ], programs: [{ role: 'deposit_authorization', directory: 'sample', artifact: 'sample.json' }] };
  const suite = { roles: [{ role: 'deposit_authorization', compiled_artifact_sha256: sha(artifact),
    vk_sha256: sha(vk), metadata_sha256: sha(metadata) }] };
  await save('suite/suite-manifest.json', JSON.stringify(suite));
  const installBuilt = async (entry, source) => {
    const destination = path.join(assets, entry.path);
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
  };
  return { assets, manifest, installBuilt, artifact, vk, metadata };
}

async function fastFixture(t) {
  const f = await fixture(t);
  const python = 'tools/python/bin/python3';
  const script = `#!/bin/sh
test "$1" = '-I' && test "$2" = '-S' && test "$3" = '-B' || exit 3
while [ "$#" -gt 0 ]; do
  case "$1" in --output) out=$2; shift 2;; *) shift;; esac
done
mkdir -p "$out/suite/deposit_authorization"
printf '%s' '${f.artifact.toString()}' > "$out/suite/deposit_authorization/circuit.json"
printf '%s' '${f.vk.toString()}' > "$out/suite/deposit_authorization/vk"
printf '%s' '${f.metadata.toString()}' > "$out/suite/deposit_authorization/vk.json"
`;
  const recipe = 'scripts/build-fast-prover-suite.py';
  for (const [name, bytes] of [[python, script], [recipe, 'authenticated synthetic recipe']]) {
    await mkdir(path.dirname(path.join(f.assets, name)), { recursive: true });
    await writeFile(path.join(f.assets, name), bytes, { mode: 0o700 });
    f.manifest.files.push({ path: name, sha256: sha(bytes) });
  }
  f.manifest.fast_runtime = { python };
  return f;
}

test('v10 source fallback authenticates its recipe and installs only exact derived artifacts', async t => {
  const f = await fastFixture(t);
  await buildSourceAssets({ ...f, roles: ['deposit_authorization'] });
  assert.deepEqual(await readFile(path.join(f.assets, 'suite/deposit_authorization/circuit.json')), f.artifact);
  assert.deepEqual(await readFile(path.join(f.assets, 'suite/deposit_authorization/vk')), f.vk);
  assert.equal((await readdir(f.assets)).some(name => name.startsWith('.fast-source-build-')), false);
});

test('v10 source fallback rejects an altered recipe before executing or installing output', async t => {
  const f = await fastFixture(t);
  await writeFile(path.join(f.assets, 'scripts/build-fast-prover-suite.py'), 'changed');
  await assert.rejects(buildSourceAssets({ ...f, roles: ['deposit_authorization'] }), /differs from deployed pin/);
  await assert.rejects(readFile(path.join(f.assets, 'suite/deposit_authorization/vk')), /ENOENT/);
});

test('local source build normalizes only debug paths and installs pinned circuits and keys', async t => {
  const f = await fixture(t);
  await buildSourceAssets({ ...f, roles: ['deposit_authorization'] });
  for (const entry of f.manifest.files.filter(item => item.path.includes('/target/') || item.path.startsWith('suite/'))) {
    assert.equal(sha(await readFile(path.join(f.assets, entry.path))), entry.sha256);
  }
  assert.equal((await readdir(f.assets)).some(name => name.startsWith('.source-build-')), false);
});

test('changed source fails before any deployed artifact is installed', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.assets, 'circuits/sample/src/main.nr'), 'changed source');
  await assert.rejects(buildSourceAssets({ ...f, roles: ['deposit_authorization'] }), /differs from deployed pin/);
  await assert.rejects(readFile(path.join(f.assets, 'suite/deposit_authorization/vk')), /ENOENT/);
  assert.equal((await readdir(f.assets)).some(name => name.startsWith('.source-build-')), false);
});

test('a locally generated key with the wrong deployed hash is never installed', async t => {
  const f = await fixture(t);
  const bb = path.join(f.assets, 'tools/bb');
  await writeFile(bb, (await readFile(bb, 'utf8')).replace('synthetic-vk', 'changed-vk'));
  await assert.rejects(buildSourceAssets({ ...f, roles: ['deposit_authorization'] }), /differs from deployed pin/);
  await assert.rejects(readFile(path.join(f.assets, 'suite/deposit_authorization/vk')), /ENOENT/);
});
