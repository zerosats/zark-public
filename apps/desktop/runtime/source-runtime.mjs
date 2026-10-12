// Bootstrap source launches from an explicitly pinned, platform-matched release.
// Only public trust files and proving assets are imported; the wallet and UI are
// always built from this checkout. No downloaded JavaScript is executed.
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, rename, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { platformKey, defaultDataDirectory } from './platform.mjs';
import { checkCheckout } from './check-checkout.mjs';

const releaseFile = fileURLToPath(new URL('../../../runtime/desktop-release.json', import.meta.url));
const hex = /^[a-f0-9]{64}$/;
export async function fileHash(file) {
  const stat = await lstat(file);
  if (!stat.isFile()) throw new Error(`Expected a regular runtime file: ${file}`);
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(file)) hash.update(bytes);
  return hash.digest('hex');
}
async function checkFile(file, expected) {
  if (!hex.test(expected) || await fileHash(file) !== expected) {
    throw new Error(`Runtime checksum mismatch: ${file}. Remove this runtime cache and retry; keep wallet data.`);
  }
}
export function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'inherit', ...options });
    const interrupt = signal => child.kill(signal);
    const term = () => interrupt('SIGTERM'), int = () => interrupt('SIGINT');
    process.on('SIGTERM', term); process.on('SIGINT', int);
    const cleanup = () => { process.off('SIGTERM', term); process.off('SIGINT', int); };
    child.once('error', error => { cleanup(); reject(error); });
    child.once('exit', (code, signal) => {
      cleanup();
      if (code === 0) resolve();
      else reject(new Error(`${command} ${args[0] ?? ''} failed (${signal ?? code})`));
    });
  });
}
function safeRelative(name) {
  if (!/^[A-Za-z0-9_./-]+$/.test(name) || name.startsWith('/') || name.split('/').some(p => !p || p === '.' || p === '..')) {
    throw new Error('Invalid path in runtime inventory');
  }
  return name;
}
export async function verifyRuntime(directory, release, platform) {
  const runtime = path.join(directory, 'trust');
  const selected = release.platforms[platform];
  if (!selected?.trust?.['asset-hashes.json'] || !selected.trust['public-deployment-pins.json']) {
    throw new Error(`Missing runtime trust pins for ${platform}`);
  }
  for (const [name, digest] of Object.entries({ ...release.trust, ...selected.trust })) {
    await checkFile(path.join(runtime, safeRelative(name)), digest);
  }
  const pins = JSON.parse(await readFile(path.join(runtime, 'public-deployment-pins.json')));
  if (pins.deployment !== release.deployment) throw new Error('Release deployment does not match checkout');
  await checkCheckout({ ZARK_TRUSTED_RUNTIME: runtime });
  const inventory = JSON.parse(await readFile(path.join(runtime, 'asset-hashes.json')));
  if (inventory.fast_runtime?.platform !== platform || inventory.prebuilt_required !== true) {
    throw new Error('Release runtime does not match this platform');
  }
  for (const digest of inventory.previous_asset_manifests ?? []) {
    if (!hex.test(digest)) throw new Error('Invalid historical inventory pin');
    await checkFile(path.join(runtime, `asset-hashes-${digest}.json`), digest);
  }
  for (const entry of inventory.files) {
    await checkFile(path.join(directory, 'prebuilt', safeRelative(entry.path)), entry.sha256);
  }
  return { runtime, assets: path.join(directory, 'prebuilt'), deployment: pins.deployment };
}
async function importApp(app, destination, release, platform) {
  const runtime = path.join(app, 'apps/desktop/runtime');
  const trust = path.join(destination, 'trust');
  await mkdir(trust, { recursive: true, mode: 0o700 });
  for (const name of Object.keys({ ...release.trust, ...release.platforms[platform].trust })) {
    await copyFile(path.join(runtime, name), path.join(trust, name));
  }
  // Authenticate the inventory before allowing it to select any other files.
  await checkFile(path.join(trust, 'asset-hashes.json'), release.platforms[platform].trust['asset-hashes.json']);
  const inventory = JSON.parse(await readFile(path.join(trust, 'asset-hashes.json')));
  for (const digest of inventory.previous_asset_manifests ?? []) {
    if (!hex.test(digest)) throw new Error('Invalid historical inventory pin');
    const name = `asset-hashes-${digest}.json`;
    await copyFile(path.join(runtime, name), path.join(trust, name));
  }
  for (const entry of inventory.files) {
    const relative = safeRelative(entry.path);
    const target = path.join(destination, 'prebuilt', relative);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await copyFile(path.join(app, 'prebuilt', relative), target);
    await chmod(target, relative.startsWith('tools/') ? 0o700 : 0o600);
  }
}
async function extract(archive, stage, destination, release, platform) {
  if (platform === 'darwin-arm64') {
    const mount = path.join(stage, 'mount');
    await mkdir(mount);
    await run('hdiutil', ['attach', '-readonly', '-nobrowse', '-mountpoint', mount, archive], { stdio: 'ignore' });
    try { await importApp(path.join(mount, 'Zark.app/Contents/Resources/app'), destination, release, platform); }
    finally { await run('hdiutil', ['detach', mount], { stdio: 'ignore' }); }
  } else {
    await chmod(archive, 0o700);
    await run(archive, ['--appimage-extract'], { cwd: stage, stdio: 'ignore' });
    await importApp(path.join(stage, 'squashfs-root/usr/lib/Zark/app'), destination, release, platform);
  }
}
export async function ensureSourceRuntime(env = process.env, {
  platform = platformKey(), home = os.homedir(),
  release, download, unpack = extract, log = message => console.error(message),
} = {}) {
  if (env.ZARK_TRUSTED_RUNTIME) {
    await checkCheckout(env);
    return { ...env };
  }
  if (env.ZARK_ASSET_SOURCE) throw new Error('A custom ZARK_ASSET_SOURCE also requires ZARK_TRUSTED_RUNTIME. Unset both for automatic setup.');
  release ??= JSON.parse(await readFile(releaseFile));
  const selected = release.platforms[platform];
  if (!selected || !hex.test(selected.sha256)) throw new Error(`No qualified release for ${platform}`);
  const defaultCache = process.platform === 'darwin'
    ? path.join(home, 'Library/Caches/Zark/source-runtime')
    : path.join(env.XDG_CACHE_HOME || path.join(home, '.cache'), 'zark/source-runtime');
  const cache = env.ZARK_RUNTIME_CACHE ?? defaultCache;
  if (!path.isAbsolute(cache)) throw new Error('ZARK_RUNTIME_CACHE must be absolute');
  const directory = path.join(cache, selected.sha256);
  let exists = false;
  try { await lstat(directory); exists = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!exists) {
    await mkdir(cache, { recursive: true, mode: 0o700 });
    const stage = await mkdtemp(path.join(cache, '.download-'));
    try {
      const archive = path.join(stage, selected.asset);
      log(`Preparing Zark for ${platform}: downloading the pinned runtime (about 600 MB, once).`);
      if (download) await download(archive);
      else {
        try {
          await run('gh', ['release', 'download', release.tag, '--repo', release.repository, '--pattern', selected.asset, '--dir', stage], { env });
        } catch (error) {
          throw new Error('Cannot download the runtime. Install GitHub CLI and run "gh auth login" with an account that can access ' + release.repository + '. Then retry. ' + error.message);
        }
      }
      await checkFile(archive, selected.sha256);
      log('Verified release checksum. Installing the runtime.');
      const prepared = path.join(stage, 'runtime');
      await unpack(archive, stage, prepared, release, platform);
      await verifyRuntime(prepared, release, platform);
      try { await rename(prepared, directory); }
      catch (error) { if (!['EEXIST', 'ENOTEMPTY'].includes(error.code)) throw error; }
    } finally { await rm(stage, { recursive: true, force: true }); }
  }
  const ready = await verifyRuntime(directory, release, platform);
  return { ...env, ZARK_TRUSTED_RUNTIME: ready.runtime, ZARK_ASSET_SOURCE: ready.assets,
    ZARK_DESKTOP_BASE: env.ZARK_DESKTOP_BASE ?? path.join(defaultDataDirectory(home, env), 'deployments', ready.deployment) };
}
