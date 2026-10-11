import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { WalletError, fail } from './validation.mjs';

const MAX_RECORD = 16 * 1024 * 1024;
export async function exists(file) {
  try { await fs.lstat(file); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}
export async function readJson(file, optional = false, limit = MAX_RECORD) {
  let handle;
  let bytes;
  try {
    if (await fs.realpath(path.dirname(file)) !== path.dirname(file)) fail('unsafe_state', 'Wallet state must use canonical directories.');
    handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > limit || (stat.mode & 0o777) !== 0o600 ||
        (process.getuid && stat.uid !== process.getuid())) fail('unsafe_state', 'Wallet state must be private, owned, regular files.');
    bytes = Buffer.alloc(stat.size + 1);
    let bytesRead = 0;
    while (bytesRead < bytes.length) {
      const read = await handle.read(bytes, bytesRead, bytes.length - bytesRead, bytesRead);
      if (!read.bytesRead) break;
      bytesRead += read.bytesRead;
    }
    if (bytesRead > stat.size) fail('state_changed', 'Wallet state changed while it was being read. Retry the operation.');
    return JSON.parse(bytes.subarray(0, bytesRead).toString('utf8'));
  } catch (error) {
    if (optional && error.code === 'ENOENT') return null;
    if (error instanceof WalletError) throw error;
    fail('invalid_state', 'Wallet state is missing, unreadable, or invalid. Preserve its journal.');
  } finally { bytes?.fill(0); await handle?.close(); }
}
export async function privateDirectory(directory, create = false) {
  if (create) {
    try { await fs.mkdir(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 ||
      (process.getuid && stat.uid !== process.getuid())) fail('unsafe_state', 'Wallet directories must be private and owned.');
}
export async function boundedPublicFile(file, limit) {
  let handle;
  try {
    handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) fail('invalid_file', 'The selected file is not a regular file within the size limit.');
    const data = Buffer.alloc(stat.size + 1);
    let count = 0;
    while (count < data.length) {
      const read = await handle.read(data, count, data.length - count, count);
      if (!read.bytesRead) break;
      count += read.bytesRead;
    }
    if (count > stat.size) fail('state_changed', 'The selected file changed while it was read.');
    return data.subarray(0, count);
  } catch (error) {
    if (error instanceof WalletError) throw error;
    fail('invalid_file', 'The selected file cannot be read safely.');
  } finally { await handle?.close(); }
}
export async function writeIndex(file, value) {
  if (await exists(file)) await readJson(file);
  const temporary = `${file}.${randomUUID()}.tmp`;
  const handle = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(`${JSON.stringify(value)}\n`); await handle.sync(); } finally { await handle.close(); }
  await fs.rename(temporary, file);
  const directory = await fs.open(path.dirname(file), constants.O_RDONLY);
  try { await directory.sync(); } finally { await directory.close(); }
}

