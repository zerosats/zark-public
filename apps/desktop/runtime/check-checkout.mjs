import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROTOCOL_VERSION, validatePins } from './config.mjs';
import { trustedRuntimeDirectory } from './trust.mjs';

export function checkoutCompatibility(pins, protocol = PROTOCOL_VERSION) {
  if (pins?.version === protocol) return;
  throw new Error(`This checkout builds protocol v${protocol}, but the selected deployment is protocol v${pins?.version ?? 'unknown'}. Use matching deployment settings and a fresh wallet profile.`);
}

export async function checkCheckout(env = process.env) {
  let pins;
  try { pins = JSON.parse(await readFile(path.join(trustedRuntimeDirectory(env), 'public-deployment-pins.json'), 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') throw new Error('No deployment selected. Set ZARK_TRUSTED_RUNTIME and ZARK_ASSET_SOURCE to a qualified release bundle; see docs/building.md.');
    throw error;
  }
  checkoutCompatibility(pins);
  validatePins(pins);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try { await checkCheckout(); }
  catch (error) { console.error(`Zark desktop: ${error.message}`); process.exitCode = 1; }
}
