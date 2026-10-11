import { spawn } from 'node:child_process';
import { WalletError, fail } from './validation.mjs';
import { normalize } from './results.mjs';
import { timed, nativeProofTimings } from '../timing.mjs';

export const MAX_OUTPUT = 1024 * 1024;
// No shell, capped output and one process group for the CLI and its prover children.
// Inject runner(binary, args, options) in tests; return { stdout, stderr, code }.
export async function processRunner(binary, args, options) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(binary, args, {
        cwd: options.cwd, env: process.env, shell: false,
        detached: process.platform !== 'win32', stdio: [options.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
      });
    } catch { reject(new WalletError('process_failed', 'The wallet process could not start.')); return; }
    let stdout = '';
    let stderr = '';
    let bytes = 0;
    let failure;
    let killTimer;
    const stop = (code, message) => {
      if (failure) return;
      failure = new WalletError(code, message);
      const kill = signal => {
        try { process.platform === 'win32' ? child.kill(signal) : process.kill(-child.pid, signal); } catch { /* already exited */ }
      };
      kill('SIGTERM');
      killTimer = setTimeout(() => kill('SIGKILL'), 1500);
      killTimer.unref();
    };
    const timer = setTimeout(() => stop('process_timeout', 'The wallet process timed out. Resume the saved operation.'), options.timeout);
    timer.unref();
    if (child.stdin) {
      child.stdin.on('error', () => stop('process_failed', 'The wallet process could not read its input.'));
      child.stdin.end(options.input);
    }
    for (const [stream, name] of [[child.stdout, 'stdout'], [child.stderr, 'stderr']]) {
      stream.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > options.maxBuffer) { stop('output_limit', 'The wallet process exceeded its output limit. Resume the saved operation.'); return; }
        if (name === 'stdout') stdout += chunk.toString('utf8');
        else stderr += chunk.toString('utf8');
      });
    }
    child.on('error', () => {
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      reject(new WalletError('process_failed', 'The wallet process could not start.'));
    });
    child.on('close', code => {
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      failure ? reject(failure) : resolve({ stdout, stderr, code });
    });
  });
}

export async function _cli(wallet, command, args = []) {
  const phase = command === 'send' ? 'native_send' : command === 'receive' ? 'native_receive' : command === 'complete' ? 'native_complete' : 'native_other';
  return timed(phase, () => executeCli(wallet, command, args));
}

async function executeCli(wallet, command, args) {
  let execution;
  try {
    execution = await wallet.walletRunner(wallet.walletBinary, ['--config', wallet.configPath, command, ...args], {
      cwd: wallet.home, shell: false, maxBuffer: MAX_OUTPUT, timeout: 6 * 60 * 60 * 1000,
    });
  } catch (error) {
    if (error instanceof WalletError) throw error;
    fail('process_failed', 'The wallet process failed. Resume the same saved operation; preserve its journal.');
  }
  const stdout = String(execution.stdout ?? '');
  const stderr = String(execution.stderr ?? '');
  if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > MAX_OUTPUT) fail('output_limit', 'The wallet process exceeded its output limit.');
  nativeProofTimings(stderr);
  let envelope;
  try { envelope = JSON.parse(stdout.trim()); } catch { fail('invalid_response', 'The wallet process returned an invalid response. Preserve its journal.'); }
  if (envelope.api_version !== 1 || typeof envelope.ok !== 'boolean') fail('invalid_response', 'The wallet process returned an unsupported response.');
  if (!envelope.ok || (execution.code ?? execution.exitCode ?? 0) !== 0) {
    // Neither raw stderr nor server/native error text crosses the UI boundary.
    const nativeMessage = typeof envelope.error?.message === 'string' ? envelope.error.message : '';
    if (nativeMessage === 'invalid encrypted message') fail('invalid_message', 'Invalid encrypted message');
    if (/\b(?:unauthorized|forbidden|credential_expired)\b/i.test(nativeMessage)) fail('signer_unauthorized', 'Signer authorization required');
    if (nativeMessage === 'received coin amount differs from expected amount') fail('amount_mismatch', 'Coin amount does not match');
    if (nativeMessage === 'deposit lacks required confirmations') fail('awaiting_confirmation', 'Waiting for a Bitcoin confirmation.');
    fail('operation_failed', 'The wallet could not complete this operation. Check its configuration and resume the same saved operation; do not delete its journal.');
  }
  if (!envelope.result || typeof envelope.result !== 'object' || Array.isArray(envelope.result)) fail('invalid_response', 'The wallet process returned an invalid result.');
  return normalize(envelope.result);
}
