#!/usr/bin/env python3
"""Compile the six v10 role circuits and fail if any exceeds its row budget.

Requires an explicit pinned nargo and the original pinned bb (not the tuned
prover). Sources are copied to a fresh scratch directory, so checkout target/
directories are untouched. Rows are bb's finalized noir-recursive circuit_size;
no witness is generated and nothing is proved. A role fails when it grows past
its budget plus the tolerance, or when its power-of-two proving size grows.
The proving-time column is only a linear estimate. Re-baselining with --update
records the reviewed --reason in the budget file.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUDGET = ROOT/'circuits/row-budget.json'
LOCK = ROOT/'runtime/fast-prover/source-lock.json'

def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()

def require_pin(path, pin, name):
    if digest(path) != pin: raise ValueError(name+' pin mismatch: '+str(path))

def run(argv, cwd, env, log, timeout):
    with log.open('wb') as stream:
        subprocess.run(list(map(str,argv)),cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT,
                       timeout=timeout,check=True)

def dyadic(rows): return 1 << max(rows-1,1).bit_length()

def check_toolchain(args, budget, lock):
    tools = budget['toolchain']
    # The budget is only meaningful for the suite's original verifier bb.
    if tools['bb_sha256'] != lock['tools']['verifier_sha256']:
        raise ValueError('row budget bb differs from source-lock verifier; re-baseline the budget')
    if not tools['noir_version'].endswith('+'+lock['noir_commit']):
        raise ValueError('row budget noir version differs from source-lock noir commit')
    if set(budget['roles']) != set(lock['roles']) or any(
            budget['roles'][role]['package'] != pin['package'] for role, pin in lock['roles'].items()):
        raise ValueError('row budget roles or packages differ from source-lock roles')
    require_pin(args.nargo, tools['nargo_sha256'], 'nargo')
    require_pin(args.bb, tools['bb_sha256'], 'bb')

def measure(args, budget, scratch):
    circuits = scratch/'circuits'
    shutil.copytree(ROOT/'circuits', circuits, ignore=shutil.ignore_patterns('target','Prover.toml'))
    home = scratch/'home'; home.mkdir()
    logs = scratch/'logs'; logs.mkdir()
    # nargo takes a git-cache lock under HOME even for path-only dependencies.
    env = dict(os.environ, HOME=str(home))
    for key in ('HARDWARE_CONCURRENCY','BB_HARDWARE_CONCURRENCY','RAYON_NUM_THREADS','OMP_NUM_THREADS'):
        env[key] = str(args.threads)
    rows = {}
    for role, entry in budget['roles'].items():
        package = entry['package']
        program = circuits/package
        artifact = program/'target'/(package.replace('-','_')+'.json')
        print('Compile '+role, flush=True)
        run([args.nargo,'compile','--force'], program, env, logs/(role+'-compile.log'), args.timeout)
        version = json.loads(artifact.read_text())['noir_version']
        if version != budget['toolchain']['noir_version']:
            raise ValueError('unexpected compiler version in artifact: '+version)
        log = logs/(role+'-gates.json')
        run([args.bb,'gates','-b',artifact,'-t',budget['toolchain']['target']], scratch, env, log, args.timeout)
        text = log.read_text()
        functions = json.loads(text[text.index('{'):])['functions']
        if len(functions) != 1: raise ValueError('expected one ACIR function: '+role)
        rows[role] = functions[0]['circuit_size']
    return rows

def report(budget, rows):
    policy = budget['policy']
    seconds = policy['proving_microseconds_per_row']/1e6
    print('\n%-24s %10s %10s %9s %8s %10s %7s  %s' % (
        'role','budget','measured','delta','delta%','time','dyadic','status'))
    failures = []
    for role, entry in budget['roles'].items():
        allowed, measured = entry['circuit_size'], rows[role]
        limit = allowed + math.ceil(allowed*policy['tolerance_fraction'])
        delta = measured-allowed
        status = 'ok'
        if measured > limit: status = 'OVER BUDGET (limit %d)' % limit
        elif dyadic(measured) > dyadic(allowed): status = 'DYADIC SIZE GREW'
        elif -delta > allowed*policy['tolerance_fraction']: status = 'ok (below budget; consider --update)'
        if not status.startswith('ok'): failures.append(role)
        print('%-24s %10d %10d %+9d %+7.2f%% %+8.1fms %7s  %s' % (
            role, allowed, measured, delta, 100*delta/allowed, 1000*delta*seconds,
            '2^%d' % (dyadic(measured).bit_length()-1), status))
    total = sum(entry['circuit_size'] for entry in budget['roles'].values())
    delta = sum(rows.values())-total
    print('%-24s %10d %10d %+9d %+7.2f%% %+8.1fms' % (
        'total', total, sum(rows.values()), delta, 100*delta/total, 1000*delta*seconds))
    print('Time is a linear estimate at %g us/row, not a measurement.' % policy['proving_microseconds_per_row'])
    return failures

def main(args):
    budget = json.loads(BUDGET.read_text())
    lock = json.loads(LOCK.read_text())
    check_toolchain(args, budget, lock)
    (ROOT/'work').mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix='circuit-rows-', dir=ROOT/'work'))
    try:
        rows = measure(args, budget, scratch)
        failures = report(budget, rows)
        if args.update:
            # A new baseline is a reviewed decision, not a way to silence a failure.
            for role, entry in budget['roles'].items(): entry['circuit_size'] = rows[role]
            budget['baseline_reason'] = args.reason
            BUDGET.write_text(json.dumps(budget, indent=2)+'\n')
            print('Updated '+str(BUDGET.relative_to(ROOT)))
            failures = []
    except BaseException:
        print('Kept scratch directory with logs: '+str(scratch), file=sys.stderr, flush=True)
        raise
    if failures:
        print('Row budget exceeded: '+', '.join(failures), file=sys.stderr)
        print('Kept scratch directory with logs: '+str(scratch), file=sys.stderr, flush=True)
        return 1
    if args.keep: print('Kept scratch directory: '+str(scratch), flush=True)
    else: shutil.rmtree(scratch)
    return 0

if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nargo', type=Path, required=True, help='absolute pinned nargo executable')
    parser.add_argument('--bb', type=Path, required=True, help='absolute pinned original bb executable')
    parser.add_argument('--timeout', type=int, default=300, help='seconds per nargo or bb command')
    parser.add_argument('--threads', type=int, default=4)
    parser.add_argument('--keep', action='store_true', help='keep compiled artifacts and logs under work/')
    parser.add_argument('--update', action='store_true', help='rewrite budgets with the measured rows')
    parser.add_argument('--reason', help='reviewed reason recorded with --update')
    args = parser.parse_args()
    if not (args.nargo.is_absolute() and args.bb.is_absolute()):
        parser.error('--nargo and --bb must be absolute paths')
    if args.update != bool(args.reason and args.reason.strip()):
        parser.error('--update requires a non-empty --reason, and --reason requires --update')
    try: sys.exit(main(args))
    except (KeyError,OSError,ValueError,subprocess.SubprocessError) as error:
        print(error, file=sys.stderr); sys.exit(1)
