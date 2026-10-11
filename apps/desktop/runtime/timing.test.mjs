import test from 'node:test';
import assert from 'node:assert/strict';
import { nativeProofTimings, timed } from './timing.mjs';
import { mkdtemp, readFile, symlink, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

test('proof timing output excludes all native text and non-timing fields', t => {
  const previous = process.env.ZARK_TIMINGS;
  t.after(() => { if (previous === undefined) delete process.env.ZARK_TIMINGS; else process.env.ZARK_TIMINGS = previous; });
  process.env.ZARK_TIMINGS = '1';
  const timing = { asset_validation_seconds: 0, input_preparation_seconds: 0, witness_seconds: 1,
    witness_asset_validation_seconds: 0, prove_seconds: 6, verify_seconds: 0.2, persistence_seconds: 0.1,
    output_validation_verify_persistence_seconds: 0.3, total_seconds: 7.3, reused: false };
  const lines = [];
  nativeProofTimings('private stderr\nZARK_PROOF_TIMING ' + JSON.stringify({ ...timing, secret: 'never forward' }) +
    '\nZARK_PROOF_TIMING ' + JSON.stringify({ ...timing, prove_seconds: 'private payload' }), line => lines.push(line));
  assert.deepEqual(lines, ['ZARK_PROOF_TIMING ' + JSON.stringify(timing)]);
  const stages = [];
  nativeProofTimings('ZARK_STAGE_TIMING {"phase":"signer_connect","milliseconds":12,"secret":"drop"}\n' +
    'ZARK_STAGE_TIMING {"phase":"private-address","milliseconds":12}\n' +
    'ZARK_STAGE_TIMING {"phase":"signer_connect","milliseconds":"private"}', line => stages.push(line));
  assert.deepEqual(stages, ['ZARK_STAGE_TIMING {"phase":"signer_connect","milliseconds":12}']);
  for (const phase of ['prover_process_prepare', 'prover_process_spawn', 'prover_process_wait',
    'helper_process_spawn', 'helper_readiness', 'verifier_process_spawn', 'verifier_process_wait']) {
    const forwarded = [];
    nativeProofTimings('ZARK_STAGE_TIMING ' + JSON.stringify({ phase, milliseconds: 7, secret: 'drop' }), line => forwarded.push(line));
    assert.deepEqual(forwarded, ['ZARK_STAGE_TIMING ' + JSON.stringify({ phase, milliseconds: 7 })]);
  }
  process.env.ZARK_TIMINGS = '0';
  nativeProofTimings('ZARK_PROOF_TIMING ' + JSON.stringify(timing), line => lines.push(line));
  assert.equal(lines.length, 1);
});

test('timings survive swallowed GUI stderr without following a diagnostic symlink', async t => {
  const previous = { flag: process.env.ZARK_TIMINGS, file: process.env.ZARK_TIMINGS_FILE };
  const root = await mkdtemp(path.join(os.tmpdir(), 'zark-timings-'));
  t.after(async () => {
    for (const [key, value] of [['ZARK_TIMINGS', previous.flag], ['ZARK_TIMINGS_FILE', previous.file]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await rm(root, { recursive: true, force: true });
  });
  process.env.ZARK_TIMINGS = '1';
  process.env.ZARK_TIMINGS_FILE = path.join(root, 'durations.jsonl');
  assert.equal(await timed('action_send', async () => 7), 7);
  const before = await readFile(process.env.ZARK_TIMINGS_FILE, 'utf8');
  assert.match(before, /^ZARK_TIMING \{"phase":"action_send","milliseconds":\d+,"ok":true\}\n$/);
  await symlink(process.env.ZARK_TIMINGS_FILE, path.join(root, 'link'));
  process.env.ZARK_TIMINGS_FILE = path.join(root, 'link');
  assert.equal(await timed('action_send', async () => 8), 8);
  assert.equal(await readFile(path.join(root, 'durations.jsonl'), 'utf8'), before);
});
