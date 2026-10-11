// Client for the deployment's MutinyNet faucet behind the pinned chain gateway.
// The faucet returns a signed, unbroadcast funding transaction for a fresh
// deposit address; the wallet still saves recovery before publishing it.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gatewayRequest } from './chain-bridge.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const MAX_TRANSACTION_HEX = 200_000;

export class FaucetError extends Error {
  constructor(message) { super(message); this.code = 'faucet'; }
}

function refusal(status, body) {
  let code;
  try { code = JSON.parse(body.toString('utf8')).error; } catch { code = undefined; }
  if (status === 429 || code === 'daily_limit') return new FaucetError('Daily test sats limit reached. Try again tomorrow.');
  if (code === 'empty') return new FaucetError('The test sats faucet is empty right now.');
  if (code === 'invalid_address') return new FaucetError('The faucet can only fund a Zark deposit address.');
  return new FaucetError('Test sats faucet unavailable. Retry.');
}

export class FaucetClient {
  constructor(services, certificate, request = gatewayRequest) {
    this.gateway = { address: services.chain_address, server_name: services.chain_server_name, certificate_sha256: services.chain_certificate_sha256 };
    this.certificate = certificate;
    this.request = request;
  }

  static async load() {
    const [services, certificate] = await Promise.all([
      readFile(path.join(here, 'public-services.json'), 'utf8').then(JSON.parse),
      readFile(path.join(here, 'public-chain-certificate.pem')),
    ]);
    return new FaucetClient(services, certificate);
  }

  async call(method, body) {
    let result;
    try { result = await this.request(this.gateway, this.certificate, body, method, '/faucet'); }
    catch { throw new FaucetError('Test sats faucet unavailable. Retry.'); }
    if (result.status !== 200) throw refusal(result.status, result.body);
    try { return JSON.parse(result.body.toString('utf8')); }
    catch { throw new FaucetError('Test sats faucet unavailable. Retry.'); }
  }

  async info() {
    const value = await this.call('GET');
    if (value?.version !== 1 || !Number.isSafeInteger(value.amount_sat) || value.amount_sat <= 0 || typeof value.available !== 'boolean') {
      throw new FaucetError('Test sats faucet unavailable. Retry.');
    }
    return { amountSat: value.amount_sat, available: value.available };
  }

  /** Returns raw transaction hex; the caller validates it against the deposit. */
  async fund(address) {
    const value = await this.call('POST', Buffer.from(JSON.stringify({ address })));
    const hex = value?.transaction;
    if (value?.version !== 1 || typeof hex !== 'string' || !hex || hex.length > MAX_TRANSACTION_HEX || hex.length % 2 || !/^[0-9a-f]+$/.test(hex)) {
      throw new FaucetError('Test sats faucet unavailable. Retry.');
    }
    return hex;
  }
}
