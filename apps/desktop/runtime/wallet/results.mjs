import path from 'node:path';
import { HEX32, digest, fail } from './validation.mjs';

const PUBLIC_FIELDS = new Set([
  'address', 'one_use', 'operation', 'phase', 'coin', 'transfer_operation',
  'transaction_id', 'amount_received_sat', 'deposit_amount_sat', 'recovery_amount_sat',
  'amount_sat', 'fee_sat', 'confirmations', 'required_confirmations', 'waiting',
  'signature_status', 'broadcast', 'activation_broadcast', 'completed', 'aborted',
  'offer', 'manifest', 'batch', 'digest', 'members', 'context', 'revision',
  'metadata_only', 'current_ownership_verified', 'recovery_and_activation_saved',
  'funding_bound', 'funding_address', 'kind', 'next_action',
  'accepted', 'recovery_saved', 'verified', 'version', 'proof_roles', 'deployment', 'valid',
  'incoming', 'outgoing',
]);

export function publicResult(value) {
  const result = {};
  for (const [key, item] of Object.entries(value ?? {})) {
    if (!PUBLIC_FIELDS.has(key)) continue;
    if (typeof item === 'string' && item.length <= 16384) result[key] = item;
    else if (typeof item === 'boolean' || (typeof item === 'number' && Number.isSafeInteger(item)) || item === null) result[key] = item;
    else if (key === 'members' && Array.isArray(item) && item.every(x => typeof x === 'string' && HEX32.test(x))) result[key] = item;
    else if (['incoming', 'outgoing'].includes(key) && Array.isArray(item) && item.length <= 5) result[key] = item.map(child => {
      if (!child || typeof child.operation !== 'string' || !path.isAbsolute(child.operation)) fail('invalid_response', 'Invalid swap group result.');
      return { operation: child.operation, ...(key === 'incoming' ? { coin: digest(child.coin), accepted: child.accepted === true, recovery_saved: child.recovery_saved === true } : { completed: child.completed === true }) };
    });
  }
  return result;
}
export function normalize(value) {
  const raw = publicResult(value);
  const result = { ...raw, raw };
  const aliases = {
    operation: 'operationPath', offer: 'offerPath', transfer_operation: 'transferOperation',
    transaction_id: 'transactionId', amount_received_sat: 'amountReceivedSat',
    deposit_amount_sat: 'depositAmountSat', recovery_amount_sat: 'recoveryAmountSat',
    amount_sat: 'amountSat', fee_sat: 'feeSat', required_confirmations: 'requiredConfirmations',
    metadata_only: 'metadataOnly', current_ownership_verified: 'currentOwnershipVerified',
    signature_status: 'signatureStatus', next_action: 'nextAction', one_use: 'oneUse',
  };
  for (const [key, alias] of Object.entries(aliases)) if (Object.hasOwn(raw, key)) result[alias] = raw[key];
  return result;
}
