/** One-time operator migration after draining the development relay. Never moves keys. */
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { RelayClient } from './client.mjs';
import { Store, lockProfile } from '../runtime/storage.mjs';

export async function retireLegacy(home, relay = new RelayClient()) {
  const store = new Store(path.join(home, '.desktop-gui'));
  const release = await lockProfile(store.directory);
  try {
    const state = await store.load();
    const legacy = state.invitations.filter(b => b.mailbox && !b.retired && !b.mailbox.transport);
    if (!legacy.length) return { retired: 0 };
    if (state.tasks.some(t => !['complete', 'rejected'].includes(t.phase)) || state.swaps.some(s => !['complete', 'cancelled'].includes(s.phase))) throw new Error('Finish transfers and swaps, and cancel open offers in the old desktop before retiring its relay.');
    for (const box of legacy) {
      try {
        if ((await relay.poll(box.mailbox)).length) throw new Error('Legacy mailbox still has messages. Drain it using the old desktop first.');
      } catch (e) { if (e.code !== 'mailbox_expired') throw e; }
    }
    for (const box of legacy) { box.retired = true; box.used ??= 'retired-legacy-mailbox'; }
    delete state.receiveId;
    await store.save(state);
    return { retired: legacy.length };
  } finally { await release(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  if (process.argv.length !== 3 || !path.isAbsolute(process.argv[2])) throw new Error('Usage: node retire-legacy.mjs /absolute/wallet/home');
  console.log(JSON.stringify(await retireLegacy(process.argv[2])));
}
