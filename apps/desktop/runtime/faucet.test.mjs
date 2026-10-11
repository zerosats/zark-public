import test from 'node:test';
import assert from 'node:assert/strict';
import { FaucetClient } from './faucet.mjs';
import { safeError } from './controller.mjs';

const services = { chain_address: '192.0.2.1:7449', chain_server_name: 'chain.internal', chain_certificate_sha256: 'a'.repeat(64) };
const reply = (status, value) => async () => ({ status, body: Buffer.from(JSON.stringify(value)) });

test('faucet requests use the pinned gateway and return validated transactions', async () => {
  const calls = [];
  const client = new FaucetClient(services, Buffer.from('pem'), async (gateway, certificate, body, method, url) => {
    calls.push({ gateway, method, url, body: body && JSON.parse(body) });
    return method === 'GET'
      ? { status: 200, body: Buffer.from('{"version":1,"amount_sat":25000,"available":true}') }
      : { status: 200, body: Buffer.from('{"version":1,"transaction":"02ab"}') };
  });
  assert.deepEqual(await client.info(), { amountSat: 25_000, available: true });
  assert.equal(await client.fund('tb1pdeposit'), '02ab');
  assert.deepEqual(calls[1], {
    gateway: { address: '192.0.2.1:7449', server_name: 'chain.internal', certificate_sha256: 'a'.repeat(64) },
    method: 'POST', url: '/faucet', body: { address: 'tb1pdeposit' },
  });
});

test('faucet refusals and malformed replies become safe wallet messages', async () => {
  const message = async request => safeError(await new FaucetClient(services, null, request).fund('tb1p').catch(error => error));
  assert.equal(await message(reply(429, { error: 'daily_limit' })), 'Daily test sats limit reached. Try again tomorrow.');
  assert.equal(await message(reply(503, { error: 'empty' })), 'The test sats faucet is empty right now.');
  assert.equal(await message(reply(200, { version: 1, transaction: '<script>' })), 'Test sats faucet unavailable. Retry.');
  assert.equal(await message(async () => { throw new Error('ECONNREFUSED'); }), 'Test sats faucet unavailable. Retry.');
});
