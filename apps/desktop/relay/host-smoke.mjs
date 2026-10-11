/** Invoked by the ignored Rust host test with a fresh, isolated signer fixture. */
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { WalletAdapter } from '../runtime/wallet.mjs';
import { SignerRelayClient } from './signer-client.mjs';

const [configPath, walletBinary, root] = process.argv.slice(2);
const { endpoint } = JSON.parse(await readFile(configPath));
async function client(name) {
  const home = path.join(root, name);
  await mkdir(home, { mode: 0o700 });
  const wallet = new WalletAdapter({ configPath, walletBinary, home });
  const address = await wallet.newAddress();
  const relay = new SignerRelayClient(endpoint, wallet);
  const mailbox = await relay.createMailbox(address.address, {
    token: (name === 'alice' ? 'aa' : 'bb').repeat(32), invitationPath: address.invitationPath,
  });
  return { wallet, relay, mailbox, address: address.address, home };
}
const alice = await client('alice'), bob = await client('bob');
const message = { id: 'private-logical-id', kind: 'coin', payload: {
  coin: 'private-coin-id', amountSat: 50000, transferOperation: 'private-operation',
  envelope: 'synthetic-test-offer',
} };
await alice.relay.send(bob.address, message);
const raw = await bob.relay.request('GET', `/v1/mailboxes/${bob.mailbox.addressHash}/messages`, { bearer: bob.mailbox.token });
assert.equal(raw.messages.length, 1);
assert.equal(raw.messages[0].kind, undefined);
assert.equal(raw.messages[0].payload, undefined);
assert(!JSON.stringify(raw).includes(message.payload.coin));
const [received] = await bob.relay.poll(bob.mailbox);
assert.deepEqual(received.payload, message.payload);
assert.equal(received.kind, 'coin');
assert.notEqual(received.id, message.id);
await bob.relay.ack(bob.mailbox, received.id);
const restarted = new SignerRelayClient(endpoint, new WalletAdapter({ configPath, walletBinary, home: alice.home }));
await assert.rejects(restarted.send(bob.address, message), { code: 'message_replayed' });
assert.deepEqual(await bob.relay.poll(bob.mailbox), []);
const offer = await alice.relay.createOffer({ amountSat: 50000, receiveAddress: alice.address, mailbox: alice.mailbox });
assert((await bob.relay.listOffers()).some(o => o.id === offer.id && o.amountSat === 50000));
const claim = await bob.relay.claimOffer(offer.id, { receiveAddress: bob.address, mailbox: bob.mailbox });
assert.equal((await alice.relay.getOffer(offer.id, offer.ownerToken)).claim.receiveAddress, bob.address);
assert.equal(claim.status, 'claimed');
console.log('Native wallet encryption, signer mail delivery, frozen retry and board claim: passed');
