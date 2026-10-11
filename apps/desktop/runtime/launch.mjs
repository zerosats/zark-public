import { trustedRuntimeDirectory } from './trust.mjs';
import { spawn } from 'node:child_process';
import { readFile, access } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readPrivate } from './storage.mjs';
import { startBridge } from './chain-bridge.mjs';


/**
 * Starts the profile's frozen local Bitcoin bridge, if it has one, after
 * checking it still matches the wallet and the pinned public gateway.
 */
export async function startProfileBridge(home) {
  const bridgeFile = path.join(path.dirname(home), 'bridge', path.basename(home), 'bridge.json');
  let bridge;
  let hasBridge = false;
  try { await access(bridgeFile, constants.F_OK); hasBridge = true; }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (hasBridge) {
    const [frozen, wallet, services] = await Promise.all([
      readPrivate(bridgeFile, 16_384).then(bytes => JSON.parse(bytes.toString('utf8'))),
      readPrivate(path.join(home, 'wallet.json'), 1_000_000).then(bytes => JSON.parse(bytes.toString('utf8'))),
      readFile(path.join(trustedRuntimeDirectory(), 'public-services.json'), 'utf8').then(JSON.parse),
    ]);
    if (frozen.address !== services.chain_address ||
        frozen.server_name !== services.chain_server_name ||
        frozen.certificate_sha256 !== services.chain_certificate_sha256 ||
        wallet.chain?.rpc_port !== frozen.port || wallet.chain?.rpc_cookie !== frozen.cookie_file ||
        wallet.chain?.datadir !== path.dirname(frozen.cookie_file)) {
      throw new Error('Frozen Bitcoin bridge does not match the wallet deployment');
    }
    bridge = await startBridge(bridgeFile, path.join(trustedRuntimeDirectory(), 'public-chain-certificate.pem'));
  }
  return bridge;
}

export async function launch(gui, home, env = process.env) {
  if (!path.isAbsolute(gui) || !path.isAbsolute(home) || env.ZARK_PREVIEW === '1') {
    throw new Error('Invalid native wallet launch');
  }
  const bridge = await startProfileBridge(home);
  try {
    const child = spawn(gui, [], { stdio: 'inherit', env });
    const forward = signal => { if (!child.killed) child.kill(signal); };
    process.on('SIGINT', forward);
    process.on('SIGTERM', forward);
    try {
      const result = await new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', (code, signal) => resolve({ code, signal }));
      });
      if (result.signal) process.exitCode = 128 + (result.signal === 'SIGINT' ? 2 : 15);
      else process.exitCode = result.code ?? 1;
    } finally {
      process.off('SIGINT', forward);
      process.off('SIGTERM', forward);
    }
  } finally {
    if (bridge) await new Promise(resolve => bridge.close(resolve));
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  launch(process.argv[2], process.argv[3]).catch(error => {
    console.error(`Zark launch: ${error.message}`);
    process.exitCode = 1;
  });
}
