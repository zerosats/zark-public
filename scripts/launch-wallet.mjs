#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureSourceRuntime, run } from '../apps/desktop/runtime/source-runtime.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
try {
  if (Number(process.versions.node.split('.')[0]) < 20) throw new Error('Node.js 20 or newer is required.');
  const profile = process.argv[2] ?? 'alice';
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(profile)) throw new Error('Use a profile name of 1–32 lowercase letters, digits, underscores or hyphens, starting with a letter.');
  const env = await ensureSourceRuntime();
  const target = path.resolve(root, env.CARGO_TARGET_DIR ?? 'target');
  Object.assign(env, { ZARK_PROFILE: profile, ZARK_NODE: process.execPath,
    ZARK_DESKTOP_RUNTIME: path.join(root, 'apps/desktop/runtime/app.mjs'),
    CARGO_TARGET_DIR: target, CARGO_BUILD_JOBS: env.CARGO_BUILD_JOBS ?? '2',
    ZARK_WALLET_BINARY: path.join(target, 'release/zark-wallet') });
  console.error('Building the wallet and desktop window from this checkout.');
  await run('cargo', ['+1.95.0', 'build', '--release', '--locked', '-p', 'zark-wallet', '--bins'], { cwd: root, env });
  const shellTarget = path.join(target, 'desktop-tauri');
  await run('cargo', ['+1.95.0', 'build', '--release', '--locked', '--manifest-path', path.join(root, 'apps/desktop-tauri/Cargo.toml'), '--target-dir', shellTarget], { cwd: root, env });
  console.error(`Opening Zark (${profile}).`);
  await run(path.join(shellTarget, 'release/zark-desktop'), [], { cwd: root, env });
} catch (error) {
  console.error(`Zark: ${error.message}`);
  process.exitCode = 1;
}
