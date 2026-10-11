#!/usr/bin/env python3
"""Compare the native zark_glv_batch_hint_v1 helper with the Brillig batch hint.

A research program calls `glv_batch::hint_for_test`, which returns the raw hint
(selected index and every transcript limb) without any constrained replay. It is
compiled twice, from the maintained vendor sources and from the donor overlay,
and the donor's witness code is transplanted with the same derivation used for
the suite. Each case runs through noir-execute once with Brillig hints and once
through a fresh zark-fast-helper; the complete witnesses must be identical.
All inputs are synthetic public constants; nothing here is a wallet key.
"""
import argparse, gzip, json, os, random, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from fast_prover.derive import derive  # noqa: E402

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
DONORS = {'glv_msm.nr': 'circuits/vendor/noir_bigcurve/src/glv_msm.nr',
          'glv_batch.nr': 'circuits/vendor/noir_bigcurve/src/glv_batch.nr'}
REVIEWED_DIAGNOSTICS = {'GLV local hint expects normalized finite points', 'GLV local hint selector echo mismatch'}
PROGRAM = '''use bigcurve::{BigCurve, Secp256k1};
use bignum::{BigNum, Secp256k1_Fq, Secp256k1_Fr};

fn point(limbs: [u128; 6]) -> Secp256k1 {
    Secp256k1::from_coordinates(Secp256k1_Fq::from_limbs([limbs[0], limbs[1], limbs[2]]),
        Secp256k1_Fq::from_limbs([limbs[3], limbs[4], limbs[5]]), false)
}

fn main(glv_points: [[u128; 6]; 2], glv_scalars: [[u8; 32]; 2], short_points: [[u128; 6]; 2],
        short_scalars: [Field; 2], forced: bool, index: u16) -> pub (u16, [u128; 3195]) {
    // Safety: research differential harness; outputs are compared, never trusted.
    unsafe {
        bigcurve::glv_batch::hint_for_test(
            [point(glv_points[0]), point(glv_points[1])],
            [Secp256k1_Fr::from_be_bytes(glv_scalars[0]), Secp256k1_Fr::from_be_bytes(glv_scalars[1])],
            [point(short_points[0]), point(short_points[1])], short_scalars, forced, index)
    }
}
'''


def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    k = (3 * a[0] * a[0] * pow(2 * a[1], -1, P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, P)) % P
    x = (k * k - a[0] - b[0]) % P
    return x, (k * (a[0] - x) - a[1]) % P


def mul(k, point=G):
    result = None
    while k:
        if k & 1: result = add(result, point)
        point, k = add(point, point), k >> 1
    return result


def limbs(point):
    split = lambda v: [v & (2**120 - 1), (v >> 120) & (2**120 - 1), v >> 240]
    return split(point[0]) + split(point[1])


def bank_offset(index):
    text = (ROOT / 'circuits/vendor/noir_bigcurve/src/glv_offset_table_wide.nr').read_text()
    numbers = [int(v) for v in text[text.index('= [') + 2:].replace('[', ' ').replace(']', ' ').replace(',', ' ').split() if v.strip(';')]
    row = numbers[12 * index:12 * index + 6]
    join = lambda l: l[0] + (l[1] << 120) + (l[2] << 240)
    return join(row[:3]), join(row[3:6])


def case(glv, scalars, shorts, weights, forced=False, index=0):
    return dict(glv_points=[[str(v) for v in limbs(p)] for p in glv],
                glv_scalars=[list((s % N).to_bytes(32, 'big')) for s in scalars],
                short_points=[[str(v) for v in limbs(p)] for p in shorts],
                short_scalars=[str(w) for w in weights], forced=forced, index=index)


def corpus():
    rng = random.Random(20261007)
    q0, q1, s0, s1 = (mul(k) for k in (7, 11, 13, 17))
    generic = ([q0, q1], [N - 1, rng.randrange(N)], [s0, s1], [2**128 - 1, 12345])
    cases = {'generic': case(*generic), 'zero-weights': case([q0, q1], generic[1], [s0, s1], [0, 0]),
             'zero-glv-scalars': case([q0, q1], [0, 0], [s0, s1], [5, 9]),
             'max-weights': case([q0, q1], generic[1], [s0, s1], [2**128 - 1, 2**128 - 1]),
             'cancels-to-infinity': case([G, G], [1, N - 2], [G, G], [1, 0])}
    for name, pair in {'signs-++': (1, LAMBDA), 'signs--': (N - 1, N - LAMBDA),
                       'signs+-': (LAMBDA, N - 1), 'signs-+': (N - LAMBDA, 1)}.items():
        cases[name] = case([q0, q1], list(pair), [s0, s1], [3, 2**127])
    for index in (255, 256, 511):
        cases['forced-%d' % index] = case(*generic, forced=True, index=index)
    # Column 0 on offset 0 with first digit +1: offset 0 is inadmissible.
    offset = bank_offset(0)
    cases['searched-past-inadmissible'] = case([offset, q1], [1, 5], [s0, s1], [7, 8])
    cases['forced-inadmissible'] = case([offset, q1], [1, 5], [s0, s1], [7, 8], forced=True, index=0)
    for seed in range(6):
        points = [mul(rng.randrange(1, N)) for _ in range(4)]
        cases['random-%d' % seed] = case(points[:2], [rng.randrange(N), rng.randrange(N)], points[2:],
                                         [rng.randrange(2**128), rng.randrange(2**128)])
    return cases


def toml(values):
    def encode(v):
        if isinstance(v, bool): return 'true' if v else 'false'
        if isinstance(v, int): return '"%d"' % v
        if isinstance(v, str): return '"%s"' % v
        return '[' + ', '.join(encode(x) for x in v) + ']'
    return ''.join('%s = %s\n' % (k, encode(v)) for k, v in values.items())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('nargo', 'executor', 'helper'): ap.add_argument('--' + name, type=Path, required=True)
    ap.add_argument('--work', type=Path, help='keep the workspace here')
    args = ap.parse_args()
    work = Path(args.work or tempfile.mkdtemp(prefix='batch-parity-'))
    env = dict(os.environ, HOME=str(work / 'home')); (work / 'home').mkdir(parents=True, exist_ok=True)
    artifacts = {}
    for stage in ('brillig', 'donor'):
        base = work / stage
        shutil.copytree(ROOT / 'circuits/vendor', base / 'vendor', dirs_exist_ok=True)
        if stage == 'donor':
            for name, target in DONORS.items():
                shutil.copyfile(ROOT / 'runtime/fast-prover/donor' / name, base / target.removeprefix('circuits/'))
        program = base / 'batch_hint_parity'; (program / 'src').mkdir(parents=True, exist_ok=True)
        (program / 'Nargo.toml').write_text('[package]\nname="batch_hint_parity"\ntype="bin"\nauthors=[""]\n'
            '[dependencies]\nbigcurve={path="../vendor/noir_bigcurve"}\nbignum={path="../vendor/noir-bignum"}\n')
        (program / 'src/main.nr').write_text(PROGRAM)
        subprocess.run([args.nargo, 'compile', '--force'], cwd=program, env=env, check=True, capture_output=True)
        artifacts[stage] = program / 'target/batch_hint_parity.json'
    brillig, donor = (json.loads(artifacts[s].read_text())['abi']['error_types'] for s in ('brillig', 'donor'))
    additions = {k: donor[k] for k in donor.keys() - brillig.keys()}
    assert {v['string'] for v in additions.values()} <= REVIEWED_DIAGNOSTICS, additions
    native = work / 'native.json'
    if native.exists(): native.unlink()
    evidence = derive(artifacts['brillig'], artifacts['donor'], native, additions)
    assert evidence['exact_whole_circuit_vector']
    helper = subprocess.Popen([args.helper], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        url = json.loads(helper.stdout.readline())['url']
        results = {}
        for name, values in corpus().items():
            inputs = work / (name + '.toml'); inputs.write_text(toml(values))
            witnesses = {}
            for label, artifact, extra in (('brillig', artifacts['brillig'], []),
                                           ('native', native, ['--oracle-resolver', url])):
                run = subprocess.run([args.executor, 'execute', '-a', artifact, '-p', inputs, '-o', work,
                                      '-w', name + '-' + label] + extra, capture_output=True, text=True)
                if run.returncode: raise SystemExit(f'{name} {label} failed: {run.stderr[-2000:]}')
                witnesses[label] = gzip.decompress((work / (name + '-' + label + '.gz')).read_bytes())
            equal = witnesses['brillig'] == witnesses['native']
            results[name] = equal
            print(f'{name:<28} {"identical" if equal else "DIFFERENT"} ({len(witnesses["native"])} witness bytes)', flush=True)
    finally:
        helper.kill(); helper.wait()
    (work / 'parity.json').write_text(json.dumps(dict(results=results, derivation=evidence['transplanted_functions']), indent=2) + '\n')
    if not all(results.values()): raise SystemExit('native and Brillig batch hints differ')
    print(f'{len(results)} cases identical; workspace {work}')


if __name__ == '__main__':
    main()
