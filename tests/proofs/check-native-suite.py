#!/usr/bin/env python3
"""Qualify a built fast-prover suite's native-hint artifacts against its fused parents.

Inputs come from a completed `check-plan-c.py` work directory whose circuits
have the same verification keys as the suite (checked first). For each positive
fixture the fused artifact runs with Brillig hints and the suite artifact runs
through a shared zark-fast-helper; native-hint witnesses must be byte-identical.
The suite artifact's witness is then proven with the given prover and verified
with the original verifier against the suite key. Selected negatives must still
fail through the native path. All fixtures are synthetic.
"""
import argparse, gzip, hashlib, json, os, subprocess, time
from pathlib import Path
from native_negative import diagnostic_artifact, require_rejection

ROLES = {'deposit': 'deposit_authorization', 'sender-1': 'sender_from_origin', 'receiver-1': 'receiver_authorization',
         'sender-2': 'sender_from_transfer', 'receiver-2': 'receiver_authorization', 'exit-0': 'exit_from_origin',
         'exit-1': 'exit_from_transfer', 'exit-2': 'exit_from_transfer'}
NEGATIVES = {'cancelling-origin-activation-and-attestation': 'sender_from_origin',
             'shifted-origin-activation-partial': 'sender_from_origin',
             'wrong-origin-attestation-scalar': 'sender_from_origin',
             'wrong-origin-recovery-partial': 'sender_from_origin',
             'wrong-origin-activation-partial': 'sender_from_origin',
             'wrong-previous-partial': 'sender_from_transfer', 'wrong-recipient': 'receiver_authorization'}


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('suite', 'qualification', 'executor', 'helper', 'prover', 'verifier', 'crs'):
        ap.add_argument('--' + name, type=Path, required=True)
    ap.add_argument('--work', type=Path, required=True)
    args = ap.parse_args()
    os.umask(0o077)
    if not args.work.resolve().is_relative_to(Path(__file__).resolve().parents[2] / 'work'):
        raise ValueError('Use a fresh synthetic work/ directory')
    args.work.mkdir(parents=True, exist_ok=False)
    programs = {p['role']: Path(p['artifact']) for p in json.loads((args.suite / 'suite/programs.json').read_text())}
    manifest = json.loads((args.suite / 'suite/suite-manifest.json').read_text())
    for pin in manifest['roles']:
        role = pin['role']
        if digest(args.suite / 'suite' / role / 'vk') != digest(args.qualification / (role + '-key/vk')):
            raise SystemExit(f'{role}: suite and qualification verification keys differ')
        if digest(programs[role]) != pin['compiled_artifact_sha256']:
            raise SystemExit(f'{role}: suite artifact differs from its manifest pin')
    lock_roles = json.loads((Path(__file__).resolve().parents[2] / 'runtime/fast-prover/source-lock.json').read_text())['roles']
    fused = {role: args.suite / 'fused/circuits' / lock_roles[role]['package'] / 'target' /
             (lock_roles[role]['package'].replace('-', '_') + '.json') for role in lock_roles}
    env = dict(os.environ, BB_MSM_NEW='1', HARDWARE_CONCURRENCY='16')
    env.pop('BB_MSM_LEGACY', None)
    helper = subprocess.Popen([args.helper], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    report = dict(positives={}, negatives={})
    try:
        url = json.loads(helper.stdout.readline())['url']

        def execute(artifact, label, name, native):
            extra = ['--oracle-resolver', url] if native else []
            t = time.monotonic()
            run = subprocess.run([args.executor, 'execute', '-a', artifact, '-p', args.qualification / 'inputs' / (label + '.toml'),
                                  '-o', args.work, '-w', name] + extra, capture_output=True, text=True, timeout=600)
            return run, time.monotonic() - t

        for label, role in ROLES.items():
            native = lock_roles[role]['native']
            entry = dict(role=role, native=native)
            run, entry['suite_witness_s'] = execute(programs[role], label, label + '-suite', native)
            if run.returncode: raise SystemExit(f'{label}: suite execution failed: {run.stderr[-1500:]}')
            if native:
                plain, entry['fused_witness_s'] = execute(fused[role], label, label + '-fused', False)
                if plain.returncode: raise SystemExit(f'{label}: fused execution failed')
                same = gzip.decompress((args.work / (label + '-suite.gz')).read_bytes()) == \
                    gzip.decompress((args.work / (label + '-fused.gz')).read_bytes())
                entry['witness_identical_to_brillig'] = same
                if not same: raise SystemExit(f'{label}: native witness differs from Brillig witness')
            out = args.work / label; out.mkdir(exist_ok=True)
            vk = args.suite / 'suite' / role / 'vk'
            t = time.monotonic()
            subprocess.run([args.prover, 'prove', '-b', programs[role], '-w', args.work / (label + '-suite.gz'), '-k', vk,
                            '-o', out, '-t', 'noir-recursive', '-c', args.crs], env=env, check=True, capture_output=True)
            entry['prove_s'] = time.monotonic() - t
            subprocess.run([args.verifier, 'verify', '-p', out / 'proof', '-i', out / 'public_inputs', '-k', vk,
                            '-t', 'noir-recursive', '-c', args.crs], check=True, capture_output=True)
            entry['verified_by_original_verifier'] = True
            report['positives'][label] = entry
            print(f"{label:<11} {role:<23} native={native!s:<5} identical={entry.get('witness_identical_to_brillig', '-')!s:<5} "
                  f"witness {entry['suite_witness_s']:.2f}s prove {entry['prove_s']:.2f}s verified", flush=True)
        diagnostic_programs = {}
        for role in set(NEGATIVES.values()):
            path = args.work / (role + '-diagnostic.json')
            diagnostic_artifact(programs[role], fused[role], path)
            diagnostic_programs[role] = path
        for label, role in NEGATIVES.items():
            run, _ = execute(programs[role], label, label + '-suite', lock_roles[role]['native'])
            require_rejection(label, run)
            checked, _ = execute(diagnostic_programs[role], label, label + '-diagnostic', lock_roles[role]['native'])
            entry = require_rejection(label, checked, diagnostic=True)
            (args.work / (label + '-negative.log')).write_text(checked.stdout + checked.stderr)
            report['negatives'][label] = dict(role=role, **entry,
                diagnostic_artifact_sha256=digest(diagnostic_programs[role]),
                fused_parent_sha256=digest(fused[role]), bytecode_unchanged=True)
            print(f'{label:<44} rejected at expected constraint', flush=True)
    finally:
        helper.kill(); helper.wait()
    (args.work / 'native-suite-report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
