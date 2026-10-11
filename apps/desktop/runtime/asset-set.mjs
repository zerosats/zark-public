import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { platformManifest } from './platform.mjs';

const hex = /^[a-f0-9]{64}$/;

function directory(base, suite, manifest) {
  const root = path.join(base, 'assets', suite);
  if (manifest.asset_revision == null) return root;
  if (!hex.test(manifest.asset_revision)) throw new Error('Invalid asset revision');
  return path.join(root, 'revisions', manifest.asset_revision);
}

/** Signing changes tool bytes. Existing wallets keep their exact admitted tools. */
export async function resolveAssetSet({ base, suite, trustedDirectory, platform, profileConfig }) {
  const current = platformManifest(JSON.parse(await readFile(path.join(trustedDirectory, 'asset-hashes.json'), 'utf8')), platform);
  const result = manifest => ({ manifest, directory: directory(base, suite, manifest) });
  if (current.asset_revision == null || !profileConfig ||
      profileConfig.manifest === path.join(directory(base, suite, current), 'suite/suite-manifest.json')) {
    return result(current);
  }
  // History is admitted by the signed package, never learned from a wallet or cache.
  for (const hash of current.previous_asset_manifests ?? []) {
    if (!hex.test(hash)) throw new Error('Invalid previous asset manifest pin');
    const bytes = await readFile(path.join(trustedDirectory, `asset-hashes-${hash}.json`));
    if (createHash('sha256').update(bytes).digest('hex') !== hash) {
      throw new Error('Previous asset manifest hash mismatch');
    }
    const previous = platformManifest(JSON.parse(bytes), platform);
    if (profileConfig.manifest === path.join(directory(base, suite, previous), 'suite/suite-manifest.json')) {
      return result(previous);
    }
  }
  throw new Error('No admitted tools match this frozen wallet; preserve its original application and state');
}
