import test from 'node:test';
import assert from 'node:assert/strict';
import { checkoutCompatibility } from './check-checkout.mjs';

test('checkout launcher rejects deployment pins for another protocol generation', () => {
  assert.throws(() => checkoutCompatibility({ version: 9 }, 10), /selected deployment is protocol v9/);
  assert.doesNotThrow(() => checkoutCompatibility({ version: 10 }, 10));
});
