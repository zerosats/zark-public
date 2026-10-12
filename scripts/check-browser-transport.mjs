// Invoked only by the ignored Rust HTTPS test with an isolated synthetic service.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHash, X509Certificate } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const [endpoint, pagePort, certificate] = process.argv.slice(2);
assert.match(endpoint, /^https:\/\/localhost:[0-9]+$/);
const module = process.env.ZARK_TEST_PLAYWRIGHT;
if (!module) throw new Error('Set ZARK_TEST_PLAYWRIGHT to an installed playwright/index.mjs');
const { chromium } = await import(pathToFileURL(module));
// Trust ONLY this ephemeral fixture key in the isolated test browser. Normal
// wallet fetch uses browser PKI; no ignoreHTTPSErrors or global TLS bypass.
const cert = new X509Certificate(await readFile(certificate));
const spki = createHash('sha256').update(cert.publicKey.export({ format: 'der', type: 'spki' })).digest('base64');
const pageServer = createServer((_request, response) => {
  response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
  response.end('<!doctype html><title>Zark synthetic transport test</title>');
});
await new Promise(resolve => pageServer.listen(Number(pagePort), '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ headless: true,
    ...(process.env.ZARK_TEST_CHROME ? { executablePath: process.env.ZARK_TEST_CHROME } : { channel: 'chrome' }),
    args: [`--ignore-certificate-errors-spki-list=${spki}`],
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`http://127.0.0.1:${pagePort}`);
  const result = await page.evaluate(async endpoint => {
    const get = await fetch(`${endpoint}/health`, { credentials: 'omit' });
    const post = body => fetch(`${endpoint}/v1/mail`, { method: 'POST', credentials: 'omit',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const mail = await post({ version: 1, method: 'GET', path: '/health', body: null });
    const signer = await fetch(`${endpoint}/v1/signer`, { method: 'POST', credentials: 'omit',
      headers: { 'Content-Type': 'application/json' }, body: '{}' });
    let blockedHeader = false;
    try { await fetch(`${endpoint}/v1/mail`, { method: 'POST', credentials: 'omit',
      headers: { 'Content-Type': 'application/json', 'X-Not-Allowed': '1' }, body: '{}' }); }
    catch { blockedHeader = true; }
    return { health: await get.json(), mail: await mail.json(), signer: await signer.json(), blockedHeader };
  }, endpoint);
  assert.equal(result.health.service, 'zark-browser');
  assert.equal(result.mail.result.service, 'zark-mail');
  assert.equal(result.signer.error.code, 'invalid_request');
  assert.equal(result.blockedHeader, true);
  // Different serialized origin, same loopback fixture. The server must deny
  // the request even though the test browser trusts its ephemeral certificate.
  const denied = await context.newPage();
  await denied.goto(`http://localhost:${pagePort}`);
  assert.equal(await denied.evaluate(async endpoint => {
    try { await fetch(`${endpoint}/health`, { credentials: 'omit' }); return false; }
    catch { return true; }
  }, endpoint), true);
  console.log('Chromium HTTPS fetch, JSON preflight, mailbox health, safe signer errors and denied origins: passed');
} finally {
  await browser?.close();
  await new Promise(resolve => pageServer.close(resolve));
}
