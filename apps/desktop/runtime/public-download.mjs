import { trustedRuntimeDirectory } from './trust.mjs';
import https from 'node:https';
import tls from 'node:tls';
import path from 'node:path';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { constants } from 'node:fs';
import { open, readFile, unlink } from 'node:fs/promises';
import { isIP } from 'node:net';
import { privateDirectory } from './storage.mjs';

const MAX_ASSET = 512 * 1024 * 1024;
const HEX32 = /^[0-9a-f]{64}$/;

export async function publicService(directory = trustedRuntimeDirectory()) {
  const service = JSON.parse(await readFile(path.join(directory, 'public-services.json'), 'utf8'));
  const match = /^(.*):(\d{1,5})$/.exec(service.chain_address ?? '');
  if (service.version !== 1 || !match || isIP(match[1]) !== 4 || +match[2] < 1 || +match[2] > 65535 ||
      service.chain_server_name !== 'chain.internal' || !HEX32.test(service.chain_certificate_sha256)) {
    throw new Error('Invalid checked-in public chain service');
  }
  const certificate = await readFile(path.join(directory, 'public-chain-certificate.pem'));
  const fingerprint = createHash('sha256').update(new X509Certificate(certificate).raw).digest('hex');
  if (fingerprint !== service.chain_certificate_sha256) throw new Error('Public chain certificate pin mismatch');
  return { service, certificate, host: match[1], port: +match[2] };
}

export async function downloadPublicAsset(entry, base, connection) {
  const expected = entry.source_sha256 ?? entry.sha256;
  if (!HEX32.test(expected) || !/^[A-Za-z0-9_./-]+$/.test(entry.path) ||
      entry.path.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new Error('Invalid checked-in public asset entry');
  }
  const downloads = path.join(base, 'assets', '.downloads');
  await privateDirectory(downloads);
  const temporary = path.join(downloads, `${randomBytes(16).toString('hex')}.part`);
  const output = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await new Promise((resolve, reject) => {
      const request = https.get({ host: connection.host, port: connection.port,
        path: `/assets/${entry.path}`, servername: connection.service.chain_server_name,
        ca: connection.certificate, rejectUnauthorized: true, agent: false,
        checkServerIdentity: (_, peer) => {
          const error = tls.checkServerIdentity(connection.service.chain_server_name, peer);
          if (error) return error;
          if (!peer.raw || createHash('sha256').update(peer.raw).digest('hex') !== connection.service.chain_certificate_sha256) {
            return new Error('Public chain certificate pin mismatch');
          }
        } }, async response => {
        try {
          const declared = Number(response.headers['content-length']);
          if (response.statusCode !== 200 || !Number.isSafeInteger(declared) || declared < 0 || declared > MAX_ASSET ||
              response.headers['content-encoding']) throw new Error(`Public asset unavailable: ${entry.path}`);
          const hash = createHash('sha256'); let size = 0;
          for await (const chunk of response) {
            size += chunk.length;
            if (size > declared || size > MAX_ASSET) throw new Error(`Public asset exceeds limit: ${entry.path}`);
            hash.update(chunk);
            let offset = 0;
            while (offset < chunk.length) {
              const result = await output.write(chunk, offset, chunk.length - offset);
              if (!result.bytesWritten) throw new Error(`Could not save public asset: ${entry.path}`);
              offset += result.bytesWritten;
            }
          }
          if (size !== declared || hash.digest('hex') !== expected) throw new Error(`Public asset hash mismatch: ${entry.path}`);
          await output.sync();
          resolve();
        } catch (error) { response.destroy(); reject(error); }
      });
      request.setTimeout(30_000, () => request.destroy(new Error(`Public asset download timed out: ${entry.path}`)));
      request.on('error', reject);
    });
    return temporary;
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  } finally { await output.close(); }
}
