import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Store } from '../runtime/storage.mjs';
import { retireLegacy } from './retire-legacy.mjs';

test('legacy retirement refuses pending work and queued mail; preserves ownership journals', async t => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'zark-mail-retire-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const store = new Store(path.join(home, '.desktop-gui'));
  const state = await store.load();
  state.invitations.push({ id: 'old', mailbox: { token: 'private' }, invitationPath: '/saved/keys' });
  state.tasks.push({ id: 'send', phase: 'pending', result: { operationPath: '/saved/operation' } });
  await store.save(state);
  await assert.rejects(retireLegacy(home, { poll: async () => [] }), /Finish transfers/);
  state.tasks[0].phase = 'complete'; await store.save(state);
  await assert.rejects(retireLegacy(home, { poll: async () => [{}] }), /still has messages/);
  assert.equal((await store.load()).invitations[0].retired, undefined);
  assert.deepEqual(await retireLegacy(home, { poll: async () => [] }), { retired: 1 });
  const after = await store.load();
  assert.deepEqual(after.tasks, state.tasks);
  assert.equal(after.invitations[0].invitationPath, '/saved/keys');
  assert.equal(after.invitations[0].retired, true);
  assert.deepEqual(await retireLegacy(home, { poll: async () => { throw new Error('Unexpected call'); } }), { retired: 0 });
});
