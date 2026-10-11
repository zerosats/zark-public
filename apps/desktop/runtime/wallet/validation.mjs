import path from 'node:path';

export const HEX32 = /^[0-9a-f]{64}$/;
export class WalletError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'WalletError';
    this.code = code;
    Object.assign(this, details);
  }
}

export function fail(code, message) { throw new WalletError(code, message); }
export function absolute(value, name) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    fail('invalid_path', `${name} must be an absolute local path.`);
  }
  return path.resolve(value);
}
export function inside(root, child) {
  const relative = path.relative(root, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}
export function digest(value) {
  if (typeof value === 'string' && HEX32.test(value)) return value;
  if (Array.isArray(value) && value.length === 32 && value.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) {
    return Buffer.from(value).toString('hex');
  }
  return null;
}
export function sat(value) { return Number.isSafeInteger(value) && value > 0 && value <= 2_100_000_000_000_000 ? value : null; }
export function textValue(value, name, max = 4096) {
  if (typeof value !== 'string' || !value || value.length > max || /[\x00-\x1f\x7f]/.test(value)) {
    fail('invalid_input', `${name} is invalid.`);
  }
  return value;
}

export const amount = value => {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0 || n > 2_100_000_000_000_000) throw new Error('Invalid amount');
  return n;
};
