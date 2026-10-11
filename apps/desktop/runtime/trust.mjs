import path from 'node:path';
import { fileURLToPath } from 'node:url';

const bundled = path.dirname(fileURLToPath(import.meta.url));

export function trustedRuntimeDirectory(env = process.env) {
  const directory = env.ZARK_TRUSTED_RUNTIME ?? bundled;
  if (!path.isAbsolute(directory)) throw new Error('ZARK_TRUSTED_RUNTIME must be an absolute path');
  return directory;
}
