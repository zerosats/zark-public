import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { extractVerifiedMember } from './release-download.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const pin = (archive_sha256, sha256) => ({ archive_sha256, sha256, member: 'bitcoin-30.2/bin/bitcoin-cli' });

test('release extraction authenticates archive before parsing and binary before installing', async t => {
  const root = await fs.mkdtemp(path.join(path.dirname(fileURLToPath(import.meta.url)), '.release-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const member = path.join(root, 'bitcoin-30.2/bin/bitcoin-cli');
  const archive = path.join(root, 'bitcoin.tar.gz');
  const output = path.join(root, 'installed-cli');
  const binary = Buffer.from('synthetic Bitcoin CLI; never executed');
  await fs.mkdir(path.dirname(member), { recursive: true });
  await fs.writeFile(member, binary, { mode: 0o700 });
  execFileSync('/usr/bin/tar', ['-czf', archive, '-C', root, 'bitcoin-30.2/bin/bitcoin-cli']);
  const archiveHash = sha(await fs.readFile(archive));
  await assert.rejects(extractVerifiedMember(archive, output, pin('00'.repeat(32), sha(binary))), /Release archive hash mismatch/);
  await assert.rejects(fs.access(output), /ENOENT/);
  await assert.rejects(extractVerifiedMember(archive, output, pin(archiveHash, '00'.repeat(32))), /Release binary hash mismatch/);
  await assert.rejects(fs.access(output), /ENOENT/);
  await assert.rejects(extractVerifiedMember(archive, output, { ...pin(archiveHash, sha(binary)), member: '../bitcoin-cli' }), /Release archive hash mismatch/);
  await extractVerifiedMember(archive, output, pin(archiveHash, sha(binary)));
  assert.deepEqual(await fs.readFile(output), binary);
  assert.equal((await fs.stat(output)).mode & 0o777, 0o700);
});
