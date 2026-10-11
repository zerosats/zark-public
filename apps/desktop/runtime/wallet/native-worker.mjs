// A single profile-bound child retains public authenticated assets and exact
// proof-verification results. Requests stay serial; no failed request is replayed.
import { spawn } from 'node:child_process';
import { WalletError } from './validation.mjs';
import { nativeProofTimings } from '../timing.mjs';

const MAX_FRAME = 1024 * 1024;
const MAX_REQUEST = 128 * 1024;
const unavailable = () => new WalletError('worker_unavailable', 'Restart the wallet and resume the same saved operation; preserve its journal.');

export class NativeWorker {
  constructor({ binary, config, cwd, spawnChild = spawn, startupTimeout = 120_000 }) {
    this.binary = binary; this.config = config; this.cwd = cwd;
    this.spawnChild = spawnChild; this.startupTimeout = startupTimeout;
    this.tail = Promise.resolve(); this.nextId = 1;
    this.stdout = Buffer.alloc(0); this.stderr = '';
    this.outputBytes = 0; this.closed = false; this.failure = null;
  }
  run(binary, args, options) {
    const result = this.tail.then(() => this.request(binary, args, options));
    this.tail = result.catch(() => {});
    return result;
  }
  async request(binary, args, options) {
    if (this.closed || this.failure || binary !== this.binary || options.cwd !== this.cwd ||
        args[0] !== '--config' || args[1] !== this.config || options.input !== undefined) throw unavailable();
    await this.start();
    if (this.failure || this.closed) throw unavailable();
    const id = this.nextId;
    if (!Number.isSafeInteger(id)) { this.fail(unavailable()); throw unavailable(); }
    const frame = JSON.stringify({ version: 1, id, args: args.slice(2) }) + '\n';
    if (Buffer.byteLength(frame) > MAX_REQUEST) throw new WalletError('output_limit', 'Wallet request is too large.');
    this.nextId++;
    this.outputBytes = 0;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(new WalletError('process_timeout', 'The wallet process timed out. Resume the saved operation.')), options.timeout);
      timer.unref();
      this.pending = { id, resolve, reject, timer };
      // Once written, any loss is uncertain. Only an explicit saved-operation
      // retry after restarting the worker can continue it.
      this.child.stdin.write(frame, error => { if (error) this.fail(unavailable()); });
    });
  }
  start() {
    if (this.ready) return this.ready;
    this.ready = new Promise((resolve, reject) => {
      this.startResolve = resolve; this.startReject = reject;
      this.startTimer = setTimeout(() => this.fail(unavailable()), this.startupTimeout);
      this.startTimer.unref();
      try {
        this.child = this.spawnChild(this.binary, ['--config', this.config, 'worker'], {
          cwd: this.cwd, env: process.env, shell: false,
          detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch { this.fail(unavailable()); return; }
      this.exited = new Promise(done => { this.exitResolve = done; });
      this.child.stdin.on('error', () => this.fail(unavailable()));
      this.child.stdout.on('data', chunk => this.readStdout(chunk));
      this.child.stderr.on('data', chunk => this.readStderr(chunk));
      this.child.on('error', () => { this.fail(unavailable()); });
      this.child.on('close', () => {
        clearTimeout(this.killTimer);
        if (!this.closed || this.pending || this.startReject) this.fail(unavailable());
        clearTimeout(this.killTimer);
        this.exitResolve();
      });
    });
    return this.ready;
  }
  count(chunk) {
    this.outputBytes += chunk.length;
    if (this.outputBytes > MAX_FRAME) {
      this.fail(new WalletError('output_limit', 'The wallet process exceeded its output limit. Resume its saved operation.'));
      return false;
    }
    return !this.failure;
  }
  readStdout(chunk) {
    if (!this.count(chunk)) return;
    this.stdout = Buffer.concat([this.stdout, chunk]);
    if (this.stdout.length > MAX_FRAME) { this.fail(unavailable()); return; }
    let newline;
    while (!this.failure && (newline = this.stdout.indexOf(10)) !== -1) {
      const bytes = this.stdout.subarray(0, newline);
      this.stdout = this.stdout.subarray(newline + 1);
      let frame;
      try { frame = JSON.parse(bytes.toString('utf8')); } catch { this.fail(unavailable()); return; }
      if (frame?.worker_version !== 1) { this.fail(unavailable()); return; }
      if (this.startResolve) {
        if (frame.ready !== true || Object.keys(frame).length !== 2) { this.fail(unavailable()); return; }
        clearTimeout(this.startTimer);
        const resolve = this.startResolve;
        this.startResolve = this.startReject = null;
        resolve();
        continue;
      }
      const pending = this.pending;
      if (!pending || frame.id !== pending.id || frame.response?.api_version !== 1 || typeof frame.response.ok !== 'boolean' ||
          Object.keys(frame).some(k => !['worker_version', 'id', 'response', 'fatal'].includes(k)) ||
          (frame.fatal !== undefined && frame.fatal !== true)) { this.fail(unavailable()); return; }
      if (frame.fatal) { this.fail(unavailable()); return; }
      this.pending = null;
      clearTimeout(pending.timer);
      pending.resolve({ stdout: JSON.stringify(frame.response), stderr: '', code: frame.response.ok ? 0 : 1 });
    }
  }
  readStderr(chunk) {
    if (!this.count(chunk)) return;
    // Only sanitized duration records leave this transport. Native diagnostics
    // and secret-bearing errors are discarded rather than buffered across jobs.
    this.stderr += chunk.toString('utf8');
    if (Buffer.byteLength(this.stderr) > MAX_FRAME) { this.fail(unavailable()); return; }
    let newline;
    while ((newline = this.stderr.indexOf('\n')) !== -1) {
      nativeProofTimings(this.stderr.slice(0, newline));
      this.stderr = this.stderr.slice(newline + 1);
    }
  }
  kill(signal) {
    if (!this.child?.pid) return;
    try { process.platform === 'win32' ? this.child.kill(signal) : process.kill(-this.child.pid, signal); } catch { /* already exited */ }
  }
  fail(error) {
    if (this.failure) return;
    this.failure = error;
    clearTimeout(this.startTimer);
    this.startReject?.(error);
    this.startReject = this.startResolve = null;
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(error);
      this.pending = null;
    }
    this.kill('SIGTERM');
    this.killTimer = setTimeout(() => this.kill('SIGKILL'), 1500);
    this.killTimer.unref();
  }
  close() {
    this.closing ??= this.drainAndClose();
    return this.closing;
  }
  async drainAndClose() {
    // Stop admission before draining. Already queued commands either finish or
    // are refused before dispatch; an active native command keeps its locks.
    this.closed = true;
    await this.tail;
    if (!this.child) return;
    this.child.stdin.end();
    this.killTimer = setTimeout(() => this.kill('SIGKILL'), 1500);
    this.killTimer.unref();
    await this.exited;
    clearTimeout(this.killTimer);
  }
}
