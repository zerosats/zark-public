import https from 'node:https';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { open, unlink } from 'node:fs/promises';
import { privateDirectory } from './storage.mjs';

// Downloads one tool from its official release archive (platform.mjs pins).
const maxArchive = 100 * 1024 * 1024;
const maxBinary = 128 * 1024 * 1024;
const hex = /^[0-9a-f]{64}$/;
const member = /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*$/;

async function digestArchive(file) {
  const input = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await input.stat();
    if (!stat.isFile() || stat.size > maxArchive) throw new Error('Invalid release archive');
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    while (true) {
      const { bytesRead } = await input.read(buffer, 0, buffer.length, offset);
      if (!bytesRead) break;
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    if (offset !== stat.size) throw new Error('Release archive changed while reading');
    return hash.digest('hex');
  } finally { await input.close(); }
}

export async function extractVerifiedMember(archive, destination, { archive_sha256: expectedArchive, member: name, sha256: expectedBinary }) {
  if (!hex.test(expectedArchive) || !hex.test(expectedBinary) || !member.test(name ?? '') || name.split('/').includes('..') ||
      await digestArchive(archive) !== expectedArchive) {
    throw new Error('Release archive hash mismatch');
  }
  // Authenticate the complete archive before letting tar parse any of its bytes.
  const binary = await new Promise((resolve, reject) => {
    execFile('/usr/bin/tar', ['-xOzf', archive, name],
      { encoding: 'buffer', maxBuffer: maxBinary, timeout: 60_000 },
      (error, stdout) => error ? reject(error) : resolve(stdout));
  });
  if (createHash('sha256').update(binary).digest('hex') !== expectedBinary) {
    throw new Error('Release binary hash mismatch');
  }
  const output = await open(destination, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o700);
  try { await output.writeFile(binary); await output.sync(); }
  finally { await output.close(); }
}

/** Streams the archive to `output`, following HTTPS-only redirects (GitHub uses a CDN). */
function fetchArchive(url, output, expectedSha256, redirects = 5) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { agent: false, rejectUnauthorized: true }, async response => {
      try {
        if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
          response.resume();
          const next = new URL(response.headers.location, url);
          if (next.protocol !== 'https:' || redirects === 0) throw new Error('Release download redirect refused');
          resolve(fetchArchive(next.href, output, expectedSha256, redirects - 1));
          return;
        }
        const declared = response.headers['content-length'] == null ? null : Number(response.headers['content-length']);
        if (response.statusCode !== 200 || response.headers['content-encoding'] ||
            (declared !== null && (!Number.isSafeInteger(declared) || declared < 0 || declared > maxArchive))) {
          throw new Error('Release archive unavailable');
        }
        const hash = createHash('sha256');
        let size = 0;
        for await (const chunk of response) {
          size += chunk.length;
          if (size > maxArchive || (declared !== null && size > declared)) throw new Error('Release archive exceeds limit');
          hash.update(chunk);
          let offset = 0;
          while (offset < chunk.length) {
            const result = await output.write(chunk, offset, chunk.length - offset);
            if (!result.bytesWritten) throw new Error('Could not save release archive');
            offset += result.bytesWritten;
          }
        }
        if ((declared !== null && size !== declared) || hash.digest('hex') !== expectedSha256) {
          throw new Error('Release archive hash mismatch');
        }
        await output.sync();
        resolve();
      } catch (error) { response.destroy(); reject(error); }
    });
    request.setTimeout(30_000, () => request.destroy(new Error('Release archive download timed out')));
    request.on('error', reject);
  });
}

export async function downloadRelease(pin, base) {
  if (!/^https:\/\/(github\.com|bitcoincore\.org)\//.test(pin?.url ?? '') || !hex.test(pin.archive_sha256) || !hex.test(pin.sha256)) {
    throw new Error('Invalid release pin');
  }
  const downloads = path.join(base, 'assets', '.downloads');
  await privateDirectory(downloads);
  const nonce = randomBytes(16).toString('hex');
  const archive = path.join(downloads, `${nonce}.tar.gz.part`);
  const binary = path.join(downloads, `${nonce}.bin.part`);
  const output = await open(archive, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  let success = false;
  try {
    await fetchArchive(pin.url, output, pin.archive_sha256);
    await extractVerifiedMember(archive, binary, pin);
    success = true;
    return binary;
  } finally {
    await output.close();
    await unlink(archive).catch(() => {});
    if (!success) await unlink(binary).catch(() => {});
  }
}
