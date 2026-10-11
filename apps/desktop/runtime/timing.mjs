// Opt-in duration diagnostics contain no arguments, addresses, payloads or
// error messages. Never forward native stderr wholesale to the terminal/UI.
import { constants, openSync, fstatSync, writeSync, closeSync } from 'node:fs';
import path from 'node:path';

const phases = new Set(['chain_gateway', 'chain_gateway_connect', 'native_send', 'native_receive', 'native_complete', 'native_other', 'action_send', 'action_receive', 'action_queue',
  'mailbox_connect', 'mailbox_exchange', 'mailbox_delivery', 'poll_tick']);
const stages = new Set(['app_load', 'crs_authentication', 'verifier_initialization', 'prover_initialization',
  'external_verification', 'verification_cache_hit', 'verifier_asset_authentication', 'worker_asset_check',
  'signer_connect', 'signer_connect_wait', 'signer_exchange', 'chain_observation', 'chain_rpc', 'chain_prepare',
  'recovery_open', 'recovery_validation', 'local_durable_write', 'proof_input_freeze',
  'prover_process_prepare', 'prover_process_spawn', 'prover_process_wait',
  'helper_process_spawn', 'helper_readiness', 'verifier_process_spawn', 'verifier_process_wait']);

function emitTiming(line) {
  const file = process.env.ZARK_TIMINGS_FILE;
  if (!file) { console.error(line); return; }
  if (!path.isAbsolute(file)) return;
  let fd;
  try {
    fd = openSync(file, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.mode & 0o077 ||
        (process.getuid && stat.uid !== process.getuid()) || stat.size >= 10 * 1024 * 1024) return;
    writeSync(fd, `${line}\n`);
  } catch { /* Optional diagnostics must never interrupt a saved operation. */ }
  finally { if (fd !== undefined) closeSync(fd); }
}

export async function timed(phase, operation) {
  if (process.env.ZARK_TIMINGS !== '1' || !phases.has(phase)) return operation();
  const started = performance.now();
  let ok = false;
  try { const result = await operation(); ok = true; return result; }
  finally { timing(phase, performance.now() - started, ok); }
}

export function timing(phase, milliseconds, ok = true) {
  if (process.env.ZARK_TIMINGS !== '1' || !phases.has(phase)) return;
  emitTiming('ZARK_TIMING ' + JSON.stringify({ phase, milliseconds: Math.round(milliseconds), ok }));
}

const proofFields = ['asset_validation_seconds', 'input_preparation_seconds', 'witness_seconds',
  'witness_asset_validation_seconds', 'prove_seconds', 'verify_seconds', 'persistence_seconds',
  'output_validation_verify_persistence_seconds', 'total_seconds'];

export function nativeProofTimings(stderr, emit = emitTiming) {
  if (process.env.ZARK_TIMINGS !== '1') return;
  for (const line of String(stderr).split('\n')) {
    if (line.startsWith('ZARK_STAGE_TIMING ')) {
      try {
        const parsed = JSON.parse(line.slice('ZARK_STAGE_TIMING '.length));
        if (stages.has(parsed.phase) && Number.isSafeInteger(parsed.milliseconds) && parsed.milliseconds >= 0) {
          emit('ZARK_STAGE_TIMING ' + JSON.stringify({ phase: parsed.phase, milliseconds: parsed.milliseconds }));
        }
      } catch { /* Fixed labels and numbers only. */ }
      continue;
    }
    if (!line.startsWith('ZARK_PROOF_TIMING ')) continue;
    try {
      const parsed = JSON.parse(line.slice('ZARK_PROOF_TIMING '.length));
      if (proofFields.some(field => !Number.isFinite(parsed[field]) || parsed[field] < 0) || typeof parsed.reused !== 'boolean') continue;
      const safe = Object.fromEntries(proofFields.map(field => [field, parsed[field]]));
      emit('ZARK_PROOF_TIMING ' + JSON.stringify({ ...safe, reused: parsed.reused }));
    } catch { /* Malformed diagnostics cannot affect wallet state or leak text. */ }
  }
}
