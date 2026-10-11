// Rebuild the deployed circuits and verification keys from authenticated source.
// The historical absolute paths below are inert Noir debug labels baked into
// the deployed artifact hashes. They are never used to locate files on this Mac.
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { constants } from 'node:fs';
import { copyFile, mkdir, mkdtemp, open, readFile, realpath, rm, writeFile } from 'node:fs/promises';

const run = promisify(execFile);
const canonicalCircuitRoot = '/zark/circuits';
const canonicalDependencyRoot = '/zark/deps';
const hex = /^[a-f0-9]{64}$/;
const segment = /^[a-z][a-z0-9_-]*$/;
const artifactName = /^[a-z][a-z0-9_]*\.json$/;
const MAX_ARTIFACT = 64 * 1024 * 1024;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

async function checkedFile(file, expected, limit = MAX_ARTIFACT) {
  if (!hex.test(expected)) throw new Error('Invalid compiled asset pin');
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error(`Invalid compiled asset: ${file}`);
    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    while (offset < stat.size) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, stat.size - offset), offset);
      if (!bytesRead) throw new Error(`Compiled asset changed while reading: ${file}`);
      digest.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    if (digest.digest('hex') !== expected) throw new Error(`Locally built asset differs from deployed pin: ${file}`);
  } finally { await handle.close(); }
}

async function copySource(source, destination, expected) {
  await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  await copyFile(source, destination);
  await checkedFile(destination, expected);
}

function canonicalDebugPath(value, stage) {
  const source = [
    [path.join(stage, 'circuits'), canonicalCircuitRoot],
    [path.join(stage, 'deps'), canonicalDependencyRoot],
  ];
  for (const [root, canonical] of source) {
    if (value.startsWith(root + path.sep)) return canonical + value.slice(root.length);
  }
  if (path.isAbsolute(value)) throw new Error('Compiled circuit refers to an unexpected source path');
  return value;
}

async function canonicalizeArtifact(file, stage, expected) {
  const bytes = await readFile(file);
  if (bytes.length > MAX_ARTIFACT) throw new Error('Compiled circuit exceeds limit');
  const artifact = JSON.parse(bytes.toString('utf8'));
  if (!artifact.file_map || typeof artifact.file_map !== 'object' || Array.isArray(artifact.file_map)) {
    throw new Error('Compiled circuit has no source map');
  }
  for (const entry of Object.values(artifact.file_map)) {
    if (typeof entry?.path !== 'string') throw new Error('Invalid compiled circuit source path');
    entry.path = canonicalDebugPath(entry.path, stage);
  }
  const canonical = Buffer.from(JSON.stringify(artifact));
  // Check the exact deployed bytes before Barretenberg sees this circuit.
  if (sha(canonical) !== expected) throw new Error('Locally compiled circuit differs from deployed suite');
  await writeFile(file, canonical, { mode: 0o600 });
}

function entryFor(manifest, name) {
  const entry = manifest.files.find(item => item.path === name);
  if (!entry || !hex.test(entry.sha256)) throw new Error(`Missing compiled asset pin: ${name}`);
  return entry;
}

export function builtAssetPaths(manifest) {
  if (!Array.isArray(manifest.programs)) throw new Error('Invalid prover program list');
  const output = new Map();
  for (const program of manifest.programs) {
    if (!segment.test(program.role ?? '') || !segment.test(program.directory ?? '') ||
        !artifactName.test(program.artifact ?? '') || output.has(program.role)) {
      throw new Error('Invalid prover program');
    }
    output.set(program.role, [
      `circuits/${program.directory}/target/${program.artifact}`,
      `suite/${program.role}/circuit.json`,
      `suite/${program.role}/vk`,
      `suite/${program.role}/vk.json`,
    ]);
  }
  return output;
}

export async function buildSourceAssets({ manifest, assets, roles, installBuilt, onProgress = () => {} }) {
  if (manifest.fast_runtime) return buildFastSourceAssets({ manifest, assets, roles, installBuilt, onProgress });
  const outputs = builtAssetPaths(manifest);
  const suite = JSON.parse(await readFile(path.join(assets, 'suite/suite-manifest.json'), 'utf8'));
  if (!Array.isArray(suite.roles) || suite.roles.length !== outputs.size) throw new Error('Qualified suite role mismatch');
  const pins = new Map(suite.roles.map(role => [role.role, role]));
  if (pins.size !== outputs.size) throw new Error('Duplicate qualified suite role');
  const stage = await mkdtemp(path.join(assets, '.source-build-'));
  try {
    const realStage = await realpath(stage);
    for (const entry of manifest.files) {
      if (entry.path.startsWith('deps/') ||
          (entry.path.startsWith('circuits/') && !entry.path.includes('/target/'))) {
        await copySource(path.join(assets, entry.path), path.join(stage, entry.path), entry.sha256);
      }
    }
    for (const role of roles) {
      onProgress(`Compiling ${role} and its verification key from source (${roles.indexOf(role) + 1}/${roles.length})`);
      const names = outputs.get(role);
      const program = manifest.programs.find(item => item.role === role);
      const pin = pins.get(role);
      if (!names || !pin || pin.compiled_artifact_sha256 !== entryFor(manifest, names[0]).sha256 ||
          pin.vk_sha256 !== entryFor(manifest, names[2]).sha256 ||
          pin.metadata_sha256 !== entryFor(manifest, names[3]).sha256 ||
          pin.compiled_artifact_sha256 !== entryFor(manifest, names[1]).sha256) {
        throw new Error(`Qualified suite pin mismatch: ${role}`);
      }
      const circuit = path.join(stage, names[0]);
      await run(path.join(assets, 'tools/nargo'), ['compile', '--force'], {
        cwd: path.join(stage, 'circuits', program.directory), timeout: 20 * 60_000, maxBuffer: 1_000_000,
      });
      await canonicalizeArtifact(circuit, realStage, pin.compiled_artifact_sha256);
      const keyDirectory = path.join(stage, 'suite', role);
      await mkdir(keyDirectory, { recursive: true, mode: 0o700 });
      const bb = path.join(assets, 'tools/bb');
      const args = ['write_vk', '-b', circuit, '-o', keyDirectory, '-t', 'noir-recursive',
        '-c', path.join(assets, 'crs')];
      // The two authenticated CRS files are installed before this call; BB must
      // not be allowed to establish trust by downloading missing CRS itself.
      for (const name of ['bn254_g1.dat', 'bn254_g1_compressed.dat']) {
        const crs = entryFor(manifest, `crs/${name}`);
        await checkedFile(path.join(assets, crs.path), crs.sha256, 512 * 1024 * 1024);
      }
      await run(bb, [...args, '--output_format', 'binary'], { timeout: 10 * 60_000, maxBuffer: 1_000_000 });
      await run(bb, [...args, '--output_format', 'json'], { timeout: 10 * 60_000, maxBuffer: 1_000_000 });
      const sources = [circuit, circuit, path.join(keyDirectory, 'vk'), path.join(keyDirectory, 'vk.json')];
      for (let index = 0; index < names.length; index += 1) {
        const entry = entryFor(manifest, names[index]);
        await checkedFile(sources[index], entry.sha256);
        await installBuilt(entry, sources[index]);
      }
      onProgress(`Verified locally built ${role} against the deployed suite`);
    }
  } finally { await rm(stage, { recursive: true, force: true }); }
}

async function buildFastSourceAssets({ manifest, assets, roles, installBuilt, onProgress }) {
  const outputs = builtAssetPaths(manifest);
  const generated = new Set([...outputs.values()].flat());
  const python = manifest.fast_runtime.python;
  if (!/^tools\/[A-Za-z0-9_./-]+$/.test(python) || python.split('/').some(p => !p || p === '.' || p === '..')) {
    throw new Error('Invalid source-build Python path');
  }
  // Authenticate scripts, maintained sources, tools and CRS before executing
  // the source recipe. Compiled files are checked after derivation and VK build.
  for (const entry of manifest.files) {
    if (entry.path !== 'certificate.pem' && !generated.has(entry.path)) {
      await checkedFile(path.join(assets, entry.path), entry.sha256, 512 * 1024 * 1024);
    }
  }
  const stage = await mkdtemp(path.join(assets, '.fast-source-build-'));
  try {
    onProgress('Rebuilding and verifying the complete v10 circuit suite');
    await run(path.join(assets, python), ['-I', '-S', '-B', path.join(assets, 'scripts/build-fast-prover-suite.py'),
      '--nargo', path.join(assets, 'tools/nargo'), '--bb', path.join(assets, 'tools/bb'),
      '--crs', path.join(assets, 'crs'), '--output', path.join(stage, 'rebuilt')],
    { timeout: 60 * 60_000, maxBuffer: 1_000_000 });
    for (const role of roles) {
      const names = outputs.get(role);
      if (!names) throw new Error('Unknown v10 role');
      const directory = path.join(stage, 'rebuilt/suite', role);
      for (const [index, source] of ['circuit.json', 'circuit.json', 'vk', 'vk.json'].entries()) {
        const entry = entryFor(manifest, names[index]);
        await checkedFile(path.join(directory, source), entry.sha256);
        await installBuilt(entry, path.join(directory, source));
      }
    }
  } finally { await rm(stage, { recursive: true, force: true }); }
}
