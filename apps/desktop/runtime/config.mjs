import os from 'node:os';
import path from 'node:path';
import { access, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { readPrivate, writePrivateImmutable } from './storage.mjs';
import { defaultDataDirectory } from './platform.mjs';

export const PROTOCOL_VERSION = 10;
export const PROOF_ROLES = 6;
const DEFAULT_WALLET = fileURLToPath(new URL('../../../target/release/zark-wallet', import.meta.url));
const PROFILE = /^[a-z][a-z0-9_-]{0,31}$/;
const PORTABLE_BITCOIN_CLI_SHA256 = '6c8024645f1f5eeb6f1f93f9f790771c322eb077eed4d5b3ff76e5a7be8bf1c2';

export function validatePins(pins) {
  if (pins?.version === 9) throw new Error('This v10 wallet requires a fresh deployment and profile. Keep the v9 application for existing coins and pending operations.');
  const hashes = ['deployment', 'suite', 'manifest_sha256', 'certificate_sha256', 'bitcoin_cli_sha256'];
  if (pins?.version !== PROTOCOL_VERSION || hashes.some(key => !/^[a-f0-9]{64}$/.test(pins[key] ?? '') || /^0+$/.test(pins[key]))) {
    throw new Error('Invalid deployment pins');
  }
}

export function validateConfiguration(config, { base, home, pins, portableBitcoinCliSha256 = PORTABLE_BITCOIN_CLI_SHA256 }) {
  validatePins(pins);
  const sameDeployment = config.chain?.deployment && config.deployment &&
    Object.keys(config.deployment).every(key => config.chain.deployment[key] === config.deployment[key]) &&
    Object.keys(config.chain.deployment).length === Object.keys(config.deployment).length;
  const endpoint = config.endpoint;
  const chain = config.chain;
  const signer = /^(.*):(\d{1,5})$/.exec(endpoint?.address ?? '');
  const validSigner = signer && isIP(signer[1]) === 4 && Number(signer[2]) >= 1 && Number(signer[2]) <= 65535;
  if (config.version !== PROTOCOL_VERSION || config.deployment?.protocol_version !== PROTOCOL_VERSION ||
      config.deployment?.signer_protocol_version !== 5 || config.deployment?.suite !== pins.suite ||
      config.manifest_sha256 !== pins.manifest_sha256 ||
      !validSigner || endpoint?.server_name !== 'signer.internal' ||
      endpoint?.certificate_sha256 !== pins.certificate_sha256 ||
      endpoint?.ca_certificate !== path.join(base, 'certificate.pem') ||
      (endpoint?.credential_file != null && endpoint.credential_file !== path.join(home, 'signer-token')) ||
      !Number.isInteger(chain?.rpc_port) || chain.rpc_port < 1 || chain.rpc_port > 65535 ||
      !path.isAbsolute(chain?.datadir ?? '') ||
      (chain?.rpc_cookie != null && chain.rpc_cookie !== path.join(chain.datadir, '.cookie')) ||
      ![pins.bitcoin_cli_sha256, portableBitcoinCliSha256].includes(config.bitcoin_cli_sha256) ||
      config.deployment?.network !== 'custom_signet' || !sameDeployment ||
      !path.isAbsolute(chain?.bitcoin_cli ?? '')) {
    throw new Error('Wallet does not match the configured MutinyNet deployment');
  }
}

export async function configuration(env = process.env, { homeDirectory = os.homedir(),
  portableBitcoinCliSha256 = PORTABLE_BITCOIN_CLI_SHA256 } = {}) {
  const profile = env.ZARK_PROFILE ?? 'alice';
  if (!PROFILE.test(profile)) throw new Error('Invalid wallet profile name');
  const base = env.ZARK_DESKTOP_BASE ?? defaultDataDirectory(homeDirectory, env);
  if (!path.isAbsolute(base) || base.includes('\0')) throw new Error('Wallet directory must be absolute');
  const home = path.join(base, profile);
  const sourceConfigPath = path.join(home, 'wallet.json');
  const bytes = await readPrivate(sourceConfigPath, 1_000_000);
  let config;
  try { config = JSON.parse(bytes.toString('utf8')); }
  catch { throw new Error('Invalid private wallet configuration'); }
  const pinBytes = await readPrivate(path.join(base, 'deployment-pins.json'), 16_384);
  let pins;
  try { pins = JSON.parse(pinBytes.toString('utf8')); }
  catch { throw new Error('Invalid deployment pins'); }
  validateConfiguration(config, { base, home, pins, portableBitcoinCliSha256 });
  const walletBinary = env.ZARK_WALLET_BINARY ?? DEFAULT_WALLET;
  if (!path.isAbsolute(walletBinary) || walletBinary.includes('\0')) throw new Error('Wallet executable must use an absolute local path');
  await access(walletBinary, constants.X_OK);
  const bitcoinCli = await realpath(config.chain.bitcoin_cli);
  const configPath = path.join(home, '.desktop-gui', 'wallet.json');
  // Existing wallet inputs are immutable: a changed profile or pin file fails closed.
  await writePrivateImmutable(configPath, bytes);
  await writePrivateImmutable(path.join(home, '.desktop-gui', 'deployment-pins.json'), pinBytes);
  bytes.fill(0);
  return { home, configPath, sourceConfigPath, walletBinary, bitcoinCli, profile, base, endpoint: config.endpoint, deployment: pins.deployment };
}
