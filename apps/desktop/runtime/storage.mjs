import { constants } from 'node:fs';
import { mkdir, lstat, open, rename, unlink, link } from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

export async function privateDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const st = await lstat(directory);
  if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o077) || (process.getuid && st.uid !== process.getuid())) throw new Error('Wallet directory must be private');
}
export async function readPrivate(file, limit = 16 * 1024 * 1024) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = await handle.stat();
    if (!st.isFile() || st.nlink !== 1 || st.size > limit || (st.mode & 0o077) || (process.getuid && st.uid !== process.getuid())) throw new Error('Invalid private wallet file');
    const bytes = Buffer.alloc(st.size + 1); let total = 0;
    while (total < bytes.length) {
      const result = await handle.read(bytes, total, bytes.length - total, total);
      if (!result.bytesRead) break;
      total += result.bytesRead;
    }
    if (total > st.size) throw new Error('Private wallet file changed while reading');
    return bytes.subarray(0, total);
  } finally { await handle.close(); }
}
async function write(file, bytes, immutable) {
  await privateDirectory(path.dirname(file));
  const temp = `${file}.${randomBytes(8).toString('hex')}.tmp`;
  const handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
    if (immutable) {
      try { await link(temp, file); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        if (!(await readPrivate(file)).equals(Buffer.from(bytes))) throw new Error('Frozen wallet input differs');
      }
      await unlink(temp);
    } else await rename(temp, file);
    const directory = await open(path.dirname(file), constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  } finally { await unlink(temp).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
}
export const writePrivate = (file, bytes) => write(file, bytes, false);
export const writePrivateImmutable = (file, bytes) => write(file, bytes, true);
export class Store {
  constructor(directory) { this.directory = directory; this.file = path.join(directory, 'state.json'); }
  async load() {
    await privateDirectory(this.directory);
    try {
      const state = JSON.parse(await readPrivate(this.file));
      if (state.version !== 1 || !['invitations', 'tasks', 'swaps', 'seen'].every(key => Array.isArray(state[key])) || state.tasks.length > 1024 || state.seen.length > 8192 || (state.deliveries !== undefined && (!Array.isArray(state.deliveries) || state.deliveries.length > 4096)) || (state.deposits !== undefined && (!Array.isArray(state.deposits) || state.deposits.length > 256))) throw new Error('Invalid desktop state');
      for (const swap of state.swaps) {
        if (swap.version === undefined) continue; // Preserve legacy journals exactly.
        if (swap.version !== 2 || !Array.isArray(swap.coins) || swap.coins.length < 1 || swap.coins.length > 5 || new Set(swap.coins.map(c => c.id)).size !== swap.coins.length || swap.coins.some(c => !/^[a-f0-9]{64}$/.test(c.id) || !Number.isSafeInteger(c.amountSat) || c.amountSat <= 0)) throw new Error('Invalid desktop swap');
        for (const field of ['peerCoins', 'drafts', 'peerDrafts', 'incoming', 'outgoing', 'slots', 'peerSlots']) if (swap[field] !== undefined && (!Array.isArray(swap[field]) || swap[field].length > 5)) throw new Error('Invalid desktop swap members');
      }
      return state;
    }
    catch (e) { if (e.code !== 'ENOENT') throw e; return { version: 1, invitations: [], tasks: [], swaps: [], seen: [] }; }
  }
  async save(value) {
    const bytes = JSON.stringify(value);
    if (Buffer.byteLength(bytes) > 16 * 1024 * 1024) throw new Error('Desktop state exceeds storage limit');
    await writePrivate(this.file, bytes);
  }
}

// Prevent two native windows/processes from coordinating one wallet at once.
export async function lockProfile(directory) {
  await privateDirectory(directory);
  const file = path.join(directory, 'process.lock');
  let h;
  try { h = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (e) {
    if (e.code !== 'EEXIST') throw e;
    throw new Error('Wallet profile is locked. After a crash, verify the previous wallet is stopped before removing process.lock.');
  }
  try { await h.writeFile(String(process.pid)); await h.sync(); } finally { await h.close(); }
  let released = false;
  return async () => { if (!released) { released = true; await unlink(file); } };
}
