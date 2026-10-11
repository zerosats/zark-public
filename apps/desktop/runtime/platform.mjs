// Per-platform wallet tools and data location.
//
// Apple Silicon Macs keep the gateway-hosted Nargo and Barretenberg binaries
// listed in asset-hashes.json (byte-identical to the official releases below).
// Linux uses the same Noir 1.0.0-beta.25 and Barretenberg 5.2.0 releases for its
// CPU. Every tool comes from its official archive with both the archive and the
// extracted binary pinned here; downloads cannot choose their own hashes. Setup
// still requires every locally compiled circuit and verification key to match
// the deployed suite, so a tool that compiles differently fails closed.
import path from 'node:path';

const NOIR = 'https://github.com/noir-lang/noir/releases/download/v1.0.0-beta.25';
const BARRETENBERG = 'https://github.com/AztecProtocol/aztec-packages/releases/download/v5.2.0';
const BITCOIN = 'https://bitcoincore.org/bin/bitcoin-core-30.2';

export const BITCOIN_CLI = 'tools/bitcoin-cli-core-30.2';

const release = (url, archive_sha256, member, sha256) => ({ url, archive_sha256, member, sha256 });

export const PLATFORMS = {
  // The checked-in asset list and deployment pins describe this platform.
  'darwin-arm64': {
    native: true,
    rustTarget: 'aarch64-apple-darwin',
    releases: {
      [BITCOIN_CLI]: release(`${BITCOIN}/bitcoin-30.2-arm64-apple-darwin.tar.gz`,
        'c2ecab62891de22228043815cb6211549a32272be3d5d052ff19847d3420bd10', 'bitcoin-30.2/bin/bitcoin-cli',
        '6c8024645f1f5eeb6f1f93f9f790771c322eb077eed4d5b3ff76e5a7be8bf1c2'),
    },
  },
  'linux-x64': {
    rustTarget: 'x86_64-unknown-linux-gnu',
    releases: {
      'tools/nargo': release(`${NOIR}/nargo-x86_64-unknown-linux-gnu.tar.gz`,
        'bf3410ab94933a4aebd1f988b67ae974c6c227f9456ed0f1e4a3716bb8a30fe9', 'nargo',
        'b22dbfac734182440ca92647c8b97a5bc59e099bf5f0602782dbabdca1d98325'),
      'tools/bb': release(`${BARRETENBERG}/barretenberg-amd64-linux.tar.gz`,
        '17ab8476961728cdc5c69b6c4ff427c9092cef11d1e0b0166929a0417dfa7cfb', 'bb',
        'fc9279e32471e036827c911ec9f8106ade987aec91d3e9a55cf4d33ebfb6f2cf'),
      [BITCOIN_CLI]: release(`${BITCOIN}/bitcoin-30.2-x86_64-linux-gnu.tar.gz`,
        '6aa7bb4feb699c4c6262dd23e4004191f6df7f373b5d5978b5bcdd4bb72f75d8', 'bitcoin-30.2/bin/bitcoin-cli',
        '2f4a391973d399d47de0c103ea99ed59355f597f6d32884200c00b40a1b8829c'),
    },
  },
  'linux-arm64': {
    rustTarget: 'aarch64-unknown-linux-gnu',
    releases: {
      'tools/nargo': release(`${NOIR}/nargo-aarch64-unknown-linux-gnu.tar.gz`,
        '4e86553af99e87c047bae40f1315234709e8d815f6158f3b8a00bf68f512a2b7', 'nargo',
        '4521c6afb49681f3c656abcce73fedbb0791e9541554563a7c35c719046f4f4d'),
      'tools/bb': release(`${BARRETENBERG}/barretenberg-arm64-linux.tar.gz`,
        '5bdc0552865428ea50d81f4da25b5aa372f45cce33baa0419cbddcd532bdbf30', 'bb',
        '779fc77ae0beedeca990699d9a4bf7b95fc9abececd0316615c8e0d251cda6cb'),
      [BITCOIN_CLI]: release(`${BITCOIN}/bitcoin-30.2-aarch64-linux-gnu.tar.gz`,
        '73e76c14edc79808a0511c744d102ffbb494807ee90cbcba176568243254b532', 'bitcoin-30.2/bin/bitcoin-cli',
        '84f49c0d3ddc2b763e9d2fa32e52f6816cc2159f0779bdfb4f6df7f6c3d00ab9'),
    },
  },
};

export function platformKey(platform = process.platform, arch = process.arch) {
  const key = `${platform}-${arch}`;
  if (!Object.hasOwn(PLATFORMS, key)) {
    throw new Error(`Zark wallet tools are qualified for Apple Silicon macOS and x86-64/arm64 Linux, not ${key}`);
  }
  return key;
}

/**
 * The checked-in asset list with this platform's release tools. On the native
 * platform the checked-in hashes stay authoritative and only the download
 * source is attached; elsewhere the platform's pinned binaries replace them.
 */
export function platformManifest(manifest, key = platformKey()) {
  if (manifest.fast_runtime && manifest.fast_runtime.platform !== key) {
    throw new Error(`Fast proving runtime has not been qualified for ${key}`);
  }
  // A fast bundle already admits this platform's exact tools. Substituting
  // ordinary release hashes here can silently select a different verifier.
  if (manifest.fast_runtime) return manifest;
  const { native, releases } = PLATFORMS[key];
  const files = manifest.files.map(entry => {
    if (!Object.hasOwn(releases, entry.path)) return entry;
    return native ? { ...entry, release: releases[entry.path] }
      : { path: entry.path, sha256: releases[entry.path].sha256, release: releases[entry.path] };
  });
  return { ...manifest, files };
}

/** Deployment pins whose Bitcoin CLI hash is this platform's official binary. */
export function platformPins(pins, key = platformKey()) {
  return PLATFORMS[key].native ? pins : { ...pins, bitcoin_cli_sha256: PLATFORMS[key].releases[BITCOIN_CLI].sha256 };
}

/** Default private profile base: Application Support on macOS, XDG data on Linux. */
export function defaultDataDirectory(homeDirectory, env = process.env, platform = process.platform) {
  if (platform === 'darwin') return path.join(homeDirectory, 'Library/Application Support/Zark');
  const xdg = env.XDG_DATA_HOME && path.isAbsolute(env.XDG_DATA_HOME) ? env.XDG_DATA_HOME : path.join(homeDirectory, '.local/share');
  return path.join(xdg, 'zark');
}
