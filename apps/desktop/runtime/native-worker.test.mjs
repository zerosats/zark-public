import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { NativeWorker } from './wallet/native-worker.mjs';

const ready = `process.stdout.write(JSON.stringify({ worker_version: 1, ready: true }) + '\\n');`;
const input = `const rl = require('node:readline').createInterface({ input: process.stdin });`;
const reply = `const response = { api_version: 1, ok: true, result: { pid: process.pid, args: r.args } };
process.stdout.write(JSON.stringify({ worker_version: 1, id: r.id, response }) + '\\n');`;
function fixture(t, script = `${ready}${input} rl.on('line', line => { const r = JSON.parse(line); ${reply} });`, settings = {}) {
  let starts = 0;
  const worker = new NativeWorker({ binary: '/synthetic/wallet', config: '/synthetic/config', cwd: process.cwd(),
    startupTimeout: 2000, ...settings,
    spawnChild(binary, args, options) {
      starts++;
      assert.equal(binary, '/synthetic/wallet');
      assert.deepEqual(args, ['--config', '/synthetic/config', 'worker']);
      return spawn(process.execPath, ['-e', script], options);
    } });
  t.after(() => worker.close());
  const run = (args = ['verify-assets'], timeout = 3000) => worker.run('/synthetic/wallet', ['--config', '/synthetic/config', ...args], { cwd: process.cwd(), timeout });
  return { worker, run, starts: () => starts };
}
test('native worker keeps one process, serializes commands and isolates its config', async t => {
  const { worker, run, starts } = fixture(t);
  const [first, second] = await Promise.all([run(), run(['status', '--operation', '/synthetic/operation'])]);
  const a = JSON.parse(first.stdout), b = JSON.parse(second.stdout);
  assert.equal(a.result.pid, b.result.pid);
  assert.deepEqual(b.result.args, ['status', '--operation', '/synthetic/operation']);
  assert.equal(starts(), 1);
  await assert.rejects(worker.run('/synthetic/wallet', ['--config', '/different', 'send'], { cwd: process.cwd(), timeout: 1000 }));
  await assert.rejects(run(['x'.repeat(128 * 1024)]), { code: 'output_limit' });
  assert.equal((await run()).code, 0);
});
test('native worker lost reply is never replayed or silently restarted', async t => {
  const { run, starts } = fixture(t, `${ready}${input} rl.on('line', () => process.exit(0));`);
  await assert.rejects(run(['send']));
  await assert.rejects(run(['send']));
  assert.equal(starts(), 1);
});
test('ordinary command rejection preserves the worker; fatal asset rejection retires it', async t => {
  const { run, starts } = fixture(t, `${ready}${input} rl.on('line', line => {
    const r = JSON.parse(line);
    if (r.id === 2) { ${reply} return; }
    process.stdout.write(JSON.stringify({ worker_version: 1, id: r.id, ...(r.id === 3 ? { fatal: true } : {}),
      response: { api_version: 1, ok: false, error: { code: 'operation_failed', message: 'rejected' } } }) + '\\n');
  });`);
  assert.equal((await run()).code, 1);
  assert.equal((await run()).code, 0);
  await assert.rejects(run(), { code: 'worker_unavailable' });
  await assert.rejects(run(), { code: 'worker_unavailable' });
  assert.equal(starts(), 1);
});
test('wrong response IDs, output overflow and startup EOF fail closed', async t => {
  for (const script of [
    `${ready}${input} rl.on('line', line => { const r = JSON.parse(line); r.id++; ${reply} });`,
    `${ready}${input} rl.on('line', () => process.stdout.write('x'.repeat(1024 * 1024 + 1)));`,
    'process.exit(0);',
  ]) {
    const { run } = fixture(t, script);
    await assert.rejects(run());
  }
});
test('native worker request timeout prevents subsequent dispatch', async t => {
  const { run, starts } = fixture(t, `${ready}${input} rl.on('line', () => {});`);
  await assert.rejects(run(['send'], 30), { code: 'process_timeout' });
  await assert.rejects(run());
  assert.equal(starts(), 1);
});
test('shutdown drains the active request before closing the worker', async t => {
  const { worker, run } = fixture(t, `${ready}${input} rl.on('line', line => {
    const r = JSON.parse(line); setTimeout(() => { ${reply} }, 80);
  });`);
  await run();
  const active = run(['send']);
  // Allow dispatch, then close while the response remains outstanding.
  await new Promise(resolve => setImmediate(resolve));
  const closed = worker.close();
  assert.equal((await active).code, 0);
  await closed;
  await assert.rejects(run());
});
