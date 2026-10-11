import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { createHash, X509Certificate, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { access, lstat, open, readFile, readdir, unlink } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { privateDirectory, readPrivate, writePrivateImmutable } from './storage.mjs';
import { configuration, validatePins, PROTOCOL_VERSION } from './config.mjs';
import { publicService, downloadPublicAsset } from './public-download.mjs';
import { builtAssetPaths, buildSourceAssets } from './source-build.mjs';
import { BITCOIN_CLI, platformKey, platformPins, defaultDataDirectory } from './platform.mjs';
import { downloadRelease } from './release-download.mjs';
import { resolveAssetSet } from './asset-set.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const hex = /^[a-f0-9]{64}$/;
const profileName = /^[a-z][a-z0-9_-]{0,31}$/;
const legacyBitcoinCliSha256 = '02f2a18a00117ab2c5a144530804901be709f7c77444cd13e19daed21b7d2389';
const retiredFastRuntimeKeys = ['python', 'python_assets', 'helper_directory', 'helper_sha256'];
const trusted = async (directory, name) => JSON.parse(await readFile(path.join(directory, name), 'utf8'));

function matchingProfilePins(saved, checkout) {
  // Existing profiles froze the first Mac CLI hash. Keep their config and binary
  // unchanged while new profiles select the macOS 13 compatible CLI.
  return saved && Object.keys(saved).length === Object.keys(checkout).length &&
    Object.keys(checkout).every(key => key === 'bitcoin_cli_sha256'
      ? saved[key] === checkout[key] || saved[key] === legacyBitcoinCliSha256
      : saved[key] === checkout[key]);
}

async function requirePrivateRpcFile(file) {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid())) {
    throw new Error(`Bitcoin RPC credential file must be private and owned: ${file}`);
  }
}

async function digest(file, limit = 512 * 1024 * 1024) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error(`Invalid public asset: ${file}`);
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (!bytesRead) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
      if (position > limit) throw new Error(`Public asset exceeds limit: ${file}`);
    }
    if (position !== stat.size) throw new Error(`Public asset changed while reading: ${file}`);
    return hash.digest('hex');
  } finally { await handle.close(); }
}

async function install(source, destination, expected, executable = false, sourceExpected = expected, rewrite) {
  if (!hex.test(expected)) throw new Error('Invalid checked-in asset hash');
  try {
    await lstat(destination);
    if (await digest(destination) !== expected) throw new Error(`Cached asset hash mismatch: ${destination}`);
    if (executable) await access(destination, constants.X_OK).catch(() => { throw new Error(`Cached tool is not executable: ${destination}`); });
    return;
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  await privateDirectory(path.dirname(destination));
  let downloaded;
  if (typeof source === 'function') { downloaded = await source(); source = downloaded; }
  if (!source) throw new Error(`Missing authenticated asset ${destination}; set ZARK_ASSET_SOURCE to the operator-provided bundle`);
  const temporary = `${destination}.${randomBytes(8).toString('hex')}.tmp`;
  const input = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    .catch(async error => { if (downloaded) await unlink(downloaded).catch(() => {}); if (error.code === 'ENOENT') throw new Error(`Missing bundle asset: ${source}`); throw error; });
  try {
    const stat = await input.stat();
    if (!stat.isFile() || stat.size > 512 * 1024 * 1024) throw new Error(`Invalid bundle asset: ${source}`);
    const output = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, executable ? 0o700 : 0o600);
    try {
      if (rewrite === 'deps') {
        if (stat.size > 64 * 1024) throw new Error(`Nargo manifest exceeds limit: ${source}`);
        const original = await input.readFile();
        if (createHash('sha256').update(original).digest('hex') !== sourceExpected) throw new Error(`Bundle asset hash mismatch: ${source}`);
        const relocated = Buffer.from(original.toString('utf8').replace(/path = "(?:[^"]*\/work\/deps|\.\.\/vendor)\/(noir-bignum|noir_bigcurve|poseidon)"/g,
          (_, name) => `path = "../../deps/${name}"`));
        if (createHash('sha256').update(relocated).digest('hex') !== expected) throw new Error(`Relocated Nargo manifest hash mismatch: ${source}`);
        await output.writeFile(relocated);
      } else {
        const hash = createHash('sha256');
        const buffer = Buffer.allocUnsafe(1024 * 1024);
        let position = 0;
        while (true) {
          const { bytesRead } = await input.read(buffer, 0, buffer.length, position);
          if (!bytesRead) break;
          hash.update(buffer.subarray(0, bytesRead));
          let written = 0;
          while (written < bytesRead) {
            const result = await output.write(buffer, written, bytesRead - written);
            if (!result.bytesWritten) throw new Error(`Could not copy bundle asset: ${source}`);
            written += result.bytesWritten;
          }
          position += bytesRead;
          if (position > 512 * 1024 * 1024) throw new Error(`Bundle asset exceeds limit: ${source}`);
        }
        if (position !== stat.size || hash.digest('hex') !== expected) throw new Error(`Bundle asset hash mismatch: ${source}`);
      }
      await output.sync();
    } finally { await output.close(); }
    try { await (await import('node:fs/promises')).link(temporary, destination); }
    catch (error) {
      if (error.code !== 'EEXIST' || await digest(destination) !== expected) throw error;
    }
    const directory = await open(path.dirname(destination), constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  } finally {
    await input.close();
    await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
    if (downloaded) await unlink(downloaded).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}

async function reachable(address, label) {
  const index = address.lastIndexOf(':');
  const host = address.slice(0, index), port = Number(address.slice(index + 1));
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`Invalid ${label} address`);
  await new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    socket.setTimeout(2500);
    socket.once('connect', () => { socket.destroy(); resolve(); });
    socket.once('error', () => reject(new Error(`${label} unavailable at ${address}`)));
    socket.once('timeout', () => { socket.destroy(); reject(new Error(`${label} unavailable at ${address}`)); });
  });
}

async function privateBridge(base, profile, services) {
  const directory = path.join(base, 'bridge', profile);
  await privateDirectory(directory);
  const cookieFile = path.join(directory, '.cookie');
  try {
    const current = await readPrivate(cookieFile, 512);
    if (!/^__cookie__:[A-Za-z0-9_-]{40,100}\n?$/.test(current.toString('utf8'))) throw new Error('Invalid local Bitcoin RPC cookie');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await writePrivateImmutable(cookieFile, Buffer.from(`__cookie__:${randomBytes(48).toString('base64url')}\n`));
  }
  const port = 40000 + createHash('sha256').update(profile).digest().readUInt16BE(0) % 20000;
  const config = { version: 1, port, cookie_file: cookieFile,
    address: services.service.chain_address,
    server_name: services.service.chain_server_name,
    certificate_sha256: services.service.chain_certificate_sha256 };
  await writePrivateImmutable(path.join(directory, 'bridge.json'), Buffer.from(JSON.stringify(config)));
  return { directory, cookieFile, port };
}

/**
 * Installs each role's compiled circuit and verification keys. A packaged app
 * may carry them precompiled: every file must match its checked-in pin (a
 * mismatch fails closed). Otherwise, or for roles it lacks, they are compiled
 * from source and must match the same pins.
 */
async function ensureBuiltAssets(manifest, assets, onProgress, prebuiltDirectory) {
  const outputs = builtAssetPaths(manifest);
  const entries = new Map(manifest.files.map(entry => [entry.path, entry]));
  const missingRoles = [];
  for (const [role, names] of outputs) {
    let missing = false;
    for (const name of names) {
      const entry = entries.get(name);
      if (!entry) throw new Error(`Missing compiled asset pin: ${name}`);
      const destination = path.join(assets, name);
      try {
        if (await digest(destination) !== entry.sha256) throw new Error(`Cached asset hash mismatch: ${destination}`);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        missing = true;
      }
    }
    if (missing) missingRoles.push(role);
  }
  for (const role of prebuiltDirectory ? [...missingRoles] : []) {
    const names = outputs.get(role);
    const present = await Promise.all(names.map(name => access(path.join(prebuiltDirectory, name)).then(() => true, () => false)));
    if (!present.every(Boolean)) continue;
    for (const name of names) await install(path.join(prebuiltDirectory, name), path.join(assets, name), entries.get(name).sha256);
    onProgress(`Installed precompiled ${role}`);
    missingRoles.splice(missingRoles.indexOf(role), 1);
  }
  if (missingRoles.length && manifest.prebuilt_required === true) {
    throw new Error('This app needs its complete bundled circuits. Download the app again; existing wallet data is preserved.');
  }
  if (missingRoles.length) await buildSourceAssets({ manifest, assets, roles: missingRoles, onProgress,
    installBuilt: (entry, source) => install(source, path.join(assets, entry.path), entry.sha256) });
}

export async function setup(env = process.env, { homeDirectory = os.homedir(), checkConnections = true,
  trustedDirectory = env.ZARK_TRUSTED_RUNTIME ?? root, circuitSourceDirectory = path.resolve(root, '../../../circuits'),
  prebuiltDirectory, platform = platformKey(), onProgress = () => {} } = {}) {
  const profile = env.ZARK_PROFILE ?? 'alice';
  if (!profileName.test(profile)) throw new Error('Invalid wallet profile name');
  const base = env.ZARK_DESKTOP_BASE ?? defaultDataDirectory(homeDirectory, env);
  if (!path.isAbsolute(base)) throw new Error('ZARK_DESKTOP_BASE must be absolute');
  const home = path.join(base, profile);
  // The Bitcoin CLI pin is this platform's official binary; other pins are shared.
  const pins = platformPins(await trusted(trustedDirectory, 'public-deployment-pins.json'), platform);
  validatePins(pins);
  await privateDirectory(base);
  const basePinFile = path.join(base, 'deployment-pins.json');
  let savedPins;
  try { savedPins = JSON.parse((await readPrivate(basePinFile, 16_384)).toString('utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (savedPins && !matchingProfilePins(savedPins, pins)) throw new Error('Profile deployment pins do not match this wallet checkout');
  let existing = false;
  try { await access(path.join(home, 'wallet.json')); existing = true; }
  catch { /* First launch. */ }
  const profileConfig = existing
    ? JSON.parse((await readPrivate(path.join(home, 'wallet.json'), 1_000_000)).toString('utf8')) : undefined;
  const { manifest, directory: assetDirectory } = await resolveAssetSet({
    base, suite: pins.suite, trustedDirectory, platform, profileConfig });
  if (!existing) {
    const source = env.ZARK_ASSET_SOURCE;
    if (source && !path.isAbsolute(source)) throw new Error('ZARK_ASSET_SOURCE must be absolute');
    const services = await publicService(trustedDirectory);
    if (manifest.version !== 1 || !Array.isArray(manifest.files) || manifest.files.length < 1) throw new Error('Invalid checked-in asset list');
    const assets = assetDirectory;
    await privateDirectory(assets);
    onProgress('Provisioning authenticated wallet inputs');
    const built = new Set([...builtAssetPaths(manifest).values()].flat());
    for (const entry of manifest.files) {
      if (!/^[A-Za-z0-9_./-]+$/.test(entry.path) || entry.path.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Invalid checked-in asset path');
      if (built.has(entry.path)) continue;
      const destination = entry.path === 'certificate.pem' ? path.join(base, 'certificate.pem') : path.join(assets, entry.path);
      const assetSource = entry.path.startsWith('circuits/')
        ? path.join(circuitSourceDirectory, entry.path.slice('circuits/'.length))
        : source ? path.join(source, entry.path)
          : entry.release ? () => downloadRelease(entry.release, base) : () => downloadPublicAsset(entry, base, services);
      const sourceHash = entry.path.startsWith('circuits/')
        ? entry.checkout_sha256 ?? entry.source_sha256 : entry.source_sha256;
      await install(assetSource, destination, entry.sha256, entry.path.startsWith('tools/'), sourceHash, entry.rewrite);
    }
    onProgress('Authenticated inputs ready');
    await ensureBuiltAssets(manifest, assets, onProgress, prebuiltDirectory);
    const certificate = new X509Certificate(await readFile(path.join(base, 'certificate.pem')));
    if (createHash('sha256').update(certificate.raw).digest('hex') !== pins.certificate_sha256) throw new Error('Signer certificate pin mismatch');
    const programs = manifest.programs.map(program => ({ role: program.role,
      directory: path.join(assets, 'circuits', program.directory),
      artifact: path.join(assets, 'circuits', program.directory, 'target', program.artifact) }));
    await writePrivateImmutable(path.join(assets, 'programs.json'), Buffer.from(JSON.stringify(programs)));
    let dataDirectory = env.ZARK_BITCOIN_DATADIR;
    let cookie, rpcPort;
    if (dataDirectory) {
      if (!path.isAbsolute(dataDirectory)) throw new Error('ZARK_BITCOIN_DATADIR must be absolute');
      const cookiePath = env.ZARK_BITCOIN_RPC_COOKIE ?? path.join(dataDirectory, '.cookie');
      if (!path.isAbsolute(cookiePath) || cookiePath !== path.join(dataDirectory, '.cookie')) throw new Error('Bitcoin RPC cookie must be in ZARK_BITCOIN_DATADIR');
      cookie = cookiePath;
      try { await requirePrivateRpcFile(cookiePath); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        if (env.ZARK_BITCOIN_RPC_COOKIE) throw new Error(`Missing Bitcoin RPC cookie: ${cookiePath}`);
        const bitcoinConfig = path.join(dataDirectory, 'bitcoin.conf');
        await requirePrivateRpcFile(bitcoinConfig).catch(error => {
          if (error.code === 'ENOENT') throw new Error(`Missing Bitcoin RPC cookie or private bitcoin.conf in ${dataDirectory}`);
          throw error;
        });
        cookie = null;
      }
      rpcPort = Number(env.ZARK_BITCOIN_RPC_PORT ?? 38332);
    } else {
      const bridge = await privateBridge(base, profile, services);
      dataDirectory = bridge.directory;
      cookie = bridge.cookieFile;
      rpcPort = bridge.port;
    }
    if (!Number.isInteger(rpcPort) || rpcPort < 1 || rpcPort > 65535) throw new Error('Invalid Bitcoin RPC port');
    const deployment = await trusted(trustedDirectory, 'deployment.json');
    if (deployment.protocol_version !== PROTOCOL_VERSION || deployment.signer_protocol_version !== 5 || deployment.suite !== pins.suite) throw new Error('Checked-in deployment mismatch');
    const config = { version: PROTOCOL_VERSION, deployment, manifest: path.join(assets, 'suite/suite-manifest.json'),
      programs: path.join(assets, 'programs.json'),
      nargo: { path: path.join(assets, 'tools/nargo'), sha256: manifest.files.find(e => e.path === 'tools/nargo').sha256 },
      bb: { path: path.join(assets, 'tools/bb'), sha256: manifest.files.find(e => e.path === 'tools/bb').sha256 },
      crs: path.join(assets, 'crs'), manifest_sha256: pins.manifest_sha256,
      crs_sha256: Object.fromEntries(manifest.files.filter(e => e.path.startsWith('crs/')).map(e => [path.basename(e.path), e.sha256])),
      bitcoin_cli_sha256: pins.bitcoin_cli_sha256,
      endpoint: { address: env.ZARK_SIGNER_ADDRESS ?? (env.ZARK_BITCOIN_DATADIR ? '127.0.0.1:7448' : services.service.signer_address), server_name: 'signer.internal', ca_certificate: path.join(base, 'certificate.pem'), certificate_sha256: pins.certificate_sha256, timeout_secs: 180 },
      chain: { deployment, bitcoin_cli: path.join(assets, BITCOIN_CLI), datadir: dataDirectory, rpc_cookie: cookie, rpc_port: rpcPort, minimum_confirmations: 1 } };
    if (manifest.fast_runtime) {
      const runtime = manifest.fast_runtime;
      const tool = name => {
        if (!/^tools\/[A-Za-z0-9_./-]+$/.test(name) || name.split('/').some(p => !p || p === '.' || p === '..')) throw new Error('Invalid fast runtime tool');
        const entry = manifest.files.find(e => e.path === name);
        if (!entry || !hex.test(entry.sha256)) throw new Error('Missing fast runtime tool pin');
        return { path: path.join(assets, name), sha256: entry.sha256 };
      };
      config.fast_runtime = { executor: tool(runtime.executor), prover: tool(runtime.prover), helper: tool(runtime.helper),
        witness_threads: runtime.witness_threads, prove_threads: runtime.prove_threads, verify_threads: runtime.verify_threads };
      if (Object.hasOwn(runtime, 'extended_native_hints')) {
        if (typeof runtime.extended_native_hints !== 'boolean') throw new Error('Invalid extended native hints setting');
        config.fast_runtime.extended_native_hints = runtime.extended_native_hints;
      }
    }
    if (!savedPins) {
      await writePrivateImmutable(basePinFile, Buffer.from(JSON.stringify(pins)));
      savedPins = pins;
    }
    await privateDirectory(home);
    if ((await readdir(home)).length !== 0) throw new Error('Existing profile directory has no wallet.json; preserve and inspect its state');
    await writePrivateImmutable(path.join(home, 'wallet.json'), Buffer.from(JSON.stringify(config)));
  }
  if (!savedPins) savedPins = JSON.parse((await readPrivate(basePinFile, 16_384)).toString('utf8'));
  if (!matchingProfilePins(savedPins, pins)) throw new Error('Profile deployment pins do not match this wallet checkout');
  if (existing) {
    // wallet.json is frozen and pending proofs are bound to its runtime, so a
    // profile pinning the retired Python helper is never rewritten here.
    const runtime = profileConfig.fast_runtime ?? {};
    if (retiredFastRuntimeKeys.some(key => Object.hasOwn(runtime, key))) {
      throw new Error('This profile pins the retired Python fast-prover helper. Keep it and its pending proofs with the wallet build that created it, or use a new ZARK_DESKTOP_BASE and profile for this runtime.');
    }
    try {
      await lstat(assetDirectory);
      const built = new Set([...builtAssetPaths(manifest).values()].flat());
      for (const entry of manifest.files) {
        if (built.has(entry.path)) continue;
        if (entry.path === BITCOIN_CLI && profileConfig.bitcoin_cli_sha256 === legacyBitcoinCliSha256) continue;
        const destination = entry.path === 'certificate.pem' ? path.join(base, 'certificate.pem') : path.join(assetDirectory, entry.path);
        await install(undefined, destination, entry.sha256, entry.path.startsWith('tools/'));
      }
      await ensureBuiltAssets(manifest, assetDirectory, onProgress, prebuiltDirectory);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const certificate = new X509Certificate(await readFile(path.join(base, 'certificate.pem')));
  if (createHash('sha256').update(certificate.raw).digest('hex') !== pins.certificate_sha256) throw new Error('Signer certificate pin mismatch');
  const resolved = await configuration({ ...env, ZARK_DESKTOP_BASE: base },
    { homeDirectory, portableBitcoinCliSha256: pins.bitcoin_cli_sha256 });
  if (checkConnections) {
    const config = JSON.parse(await readFile(resolved.configPath));
    await reachable(config.endpoint.address, 'Signer');
    const bridgeFile = path.join(base, 'bridge', profile, 'bridge.json');
    let remote = false;
    try { await access(bridgeFile); remote = true; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (remote) {
      const services = await publicService(trustedDirectory);
      const bridge = JSON.parse((await readPrivate(bridgeFile, 16_384)).toString('utf8'));
      if (bridge.address !== services.service.chain_address || bridge.certificate_sha256 !== services.service.chain_certificate_sha256 ||
          bridge.port !== config.chain.rpc_port || bridge.cookie_file !== config.chain.rpc_cookie) throw new Error('Frozen Bitcoin bridge mismatch');
      await reachable(bridge.address, 'Bitcoin gateway');
    } else await reachable(`127.0.0.1:${config.chain.rpc_port}`, 'Bitcoin RPC');
  }
  return resolved;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await setup(process.env, { onProgress: message => console.error(`Zark setup: ${message}`) });
    process.stdout.write(`${JSON.stringify({ base: result.base, home: result.home, configPath: result.configPath })}\n`);
  } catch (error) { console.error(`Zark setup: ${error.message}`); process.exitCode = 1; }
}
