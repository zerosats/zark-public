import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { absolute, digest, sat, fail, HEX32 } from './validation.mjs';
import { readJson, boundedPublicFile } from './files.mjs';
import { MAX_OUTPUT } from './native-process.mjs';

export function decodeTransaction(wallet, transactionPath) {
  return wallet._serialize(async () => {
    transactionPath = absolute(transactionPath, 'Signed funding transaction');
    const bytes = await boundedPublicFile(transactionPath, 2_000_000);
    const hex = bytes.toString('utf8').trim();
    bytes.fill(0);
    if (!hex || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) fail('invalid_transaction', 'Select a file containing a signed raw transaction in hexadecimal form.');
    const config = await readJson(wallet.configPath, false, MAX_OUTPUT);
    const chain = config.chain;
    if (!chain || !HEX32.test(config.bitcoin_cli_sha256 ?? '') || !['regtest', 'custom_signet'].includes(chain.deployment?.network) || !Number.isInteger(chain.rpc_port) || chain.rpc_port < 1 || chain.rpc_port > 65535) fail('invalid_config', 'The pinned Bitcoin RPC configuration is invalid.');
    const binary = absolute(wallet.bitcoinCli ?? chain.bitcoin_cli, 'Bitcoin executable');
    const executable = await boundedPublicFile(binary, 128 * 1024 * 1024);
    if (createHash('sha256').update(executable).digest('hex') !== config.bitcoin_cli_sha256) fail('asset_mismatch', 'The Bitcoin executable does not match the wallet configuration pin.');
    const datadir = absolute(chain.datadir, 'Bitcoin data directory');
    const args = [chain.deployment.network === 'regtest' ? '-regtest' : '-signet', `-datadir=${datadir}`, `-rpcport=${chain.rpc_port}`, '-rpcconnect=127.0.0.1', '-rpcclienttimeout=10'];
    if (chain.rpc_cookie) args.push(`-rpccookiefile=${absolute(chain.rpc_cookie, 'Bitcoin RPC cookie')}`);
    args.push('-stdin', 'decoderawtransaction');
    let execution;
    try { execution = await wallet.runner(binary, args, { cwd: wallet.home, shell: false, maxBuffer: MAX_OUTPUT, timeout: 15_000, input: `${hex}\n` }); }
    catch { fail('bitcoin_rpc_failed', 'Bitcoin transaction decoding is unavailable. Retry when the node is connected.'); }
    const stdout = String(execution.stdout ?? '');
    if ((execution.code ?? execution.exitCode ?? 0) !== 0 || Buffer.byteLength(stdout) + Buffer.byteLength(String(execution.stderr ?? '')) > MAX_OUTPUT) fail('bitcoin_rpc_failed', 'Bitcoin transaction decoding failed.');
    let decoded;
    try { decoded = JSON.parse(stdout); } catch { fail('bitcoin_rpc_failed', 'Bitcoin transaction decoding returned an invalid response.'); }
    if (!HEX32.test(decoded.txid ?? '') || !Array.isArray(decoded.vin) || !Array.isArray(decoded.vout)) fail('invalid_transaction', 'Bitcoin transaction decoding returned an invalid transaction.');
    return {
      txid: decoded.txid,
      vin: decoded.vin.map(input => ({ txid: input.txid, vout: input.vout, scriptSig: { hex: input.scriptSig?.hex ?? '' }, txinwitness: input.txinwitness ?? [] })),
      vout: decoded.vout.map(output => ({ value: output.value, n: output.n, scriptPubKey: { address: output.scriptPubKey?.address, hex: output.scriptPubKey?.hex, type: output.scriptPubKey?.type } })),
    };
  });
}

export function createDeposit(wallet, { amountSat }) {
  return wallet._serialize(async () => {
    if (!sat(amountSat) || amountSat <= 2330) fail('invalid_amount', 'Deposit amount must exceed the activation fee, recovery fee, and dust limit.');
    let entry = wallet.index.operations.find(item => item.kind === 'origin' && !item.fundingPublished);
    if (entry && entry.amountSat !== amountSat) fail('operation_conflict', 'A deposit is already being prepared with a different amount. Resume that operation.');
    if (!entry) {
      entry = { kind: 'origin', amountSat, operationPath: path.join(wallet.stateDirectory, 'operations', `origin-${randomUUID()}`), published: false };
      wallet.index.operations.push(entry);
      await wallet._save();
    }
    // The returned script is for an unbroadcast signed funding transaction.
    // Do not expose it as a direct-pay address before recovery is saved.
    return wallet._runSaved(entry, 'origin-create', ['--operation', entry.operationPath, '--amount', String(amountSat)]);
  });
}

export function bindDeposit(wallet, { operationPath, transactionPath, vout }) {
  return wallet._serialize(async () => {
    operationPath = await wallet._operationPath(operationPath);
    transactionPath = absolute(transactionPath, 'Signed funding transaction');
    if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) fail('invalid_input', 'Funding output index is invalid.');
    let entry = wallet.index.operations.find(item => item.operationPath === operationPath);
    if (!entry) {
      const metadata = await readJson(path.join(operationPath, 'operation.json'), false, 100_000);
      if (metadata.kind?.kind !== 'origin') fail('invalid_operation', 'Funding requires an origin operation.');
      entry = { kind: 'origin', operationPath, amountSat: metadata.kind.amount, published: true };
      wallet.index.operations.push(entry);
    }
    if (entry.kind !== 'origin') fail('invalid_operation', 'Funding requires an origin operation.');
    if (entry.transactionPath && (entry.transactionPath !== transactionPath || entry.vout !== vout)) fail('operation_conflict', 'This deposit already has different frozen funding parameters.');
    entry.transactionPath = transactionPath;
    entry.vout = vout;
    await wallet._save();
    return wallet._runSaved(entry, 'origin-bind', ['--operation', operationPath, '--transaction', transactionPath, '--vout', String(vout)]);
  });
}
