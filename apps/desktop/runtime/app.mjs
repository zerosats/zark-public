// Desktop entry point: authenticate assets, initialize the profile, and start its bridge.
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MIN_NODE = 20;
const emit = message => process.stdout.write(`${JSON.stringify(message)}\n`);

/** After a setup failure, answer each queued window request with the reason. */
async function refuseRequests(message) {
  const { requestLines } = await import('./main.mjs');
  for await (const line of requestLines(process.stdin)) {
    let id;
    try { id = JSON.parse(line).id; } catch { id = undefined; }
    emit({ ...(typeof id === 'string' ? { id } : {}), error: message, progress: '' });
  }
}

async function start() {
  if (Number(process.versions.node.split('.')[0]) < MIN_NODE) {
    const message = `Zark needs Node.js ${MIN_NODE} or newer (found ${process.versions.node}). Install it from nodejs.org and reopen Zark.`;
    emit({ error: message });
    return refuseRequests(message);
  }
  const { setup } = await import('./setup.mjs');
  const { startProfileBridge } = await import('./launch.mjs');
  const { runBackend } = await import('./main.mjs');
  const env = { ...process.env, ZARK_PROFILE: process.env.ZARK_PROFILE ?? 'wallet' };
  // Releases carry the compiled circuits; setup verifies them against the pins.
  const prebuilt = fileURLToPath(new URL('../../../prebuilt', import.meta.url));
  const prebuiltDirectory = existsSync(prebuilt) ? prebuilt : env.ZARK_ASSET_SOURCE;
  let resolved;
  let step = 'Setting up: Starting';
  // Setup reports only coarse steps and the window's first refresh clears the
  // progress line, so repeat the current step until setup finishes.
  const heartbeat = setInterval(() => emit({ progress: step }), 2000);
  try {
    // First run downloads the pinned tools and installs or compiles the circuits.
    resolved = await setup(env, { prebuiltDirectory, onProgress: message => { step = `Setting up: ${message}`; emit({ progress: step }); } });
  } catch (error) {
    const message = `Setup failed: ${error.message}`;
    emit({ error: message, progress: '' });
    return refuseRequests(message);
  } finally {
    clearInterval(heartbeat);
  }
  emit({ progress: 'Connecting…' });
  const bridge = await startProfileBridge(resolved.home);
  try {
    process.exitCode = await runBackend({ env: { ...env, ZARK_DESKTOP_BASE: resolved.base } });
  } finally {
    if (bridge) await new Promise(resolve => bridge.close(resolve));
  }
}

await start();
