#!/usr/bin/env python3
"""Authenticate native tools and the maintained suite for isolated qualification.

The output contains local paths, so keep it outside Git. It is an input to real
flow tests and desktop packaging, not evidence that those tests have passed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform

ROOT = Path(__file__).resolve().parents[1]
CRS = {
    'bn254_g1.dat': 'd777711ae9fb1951c47a0eaf7e0ebcaccc39e6731d9b3a560d7ff0c2fcdf2f0d',
    'bn254_g1_compressed.dat': 'bf9f1cdbe7b7bb2667c8ee5b887f6ce8b07ec99d60944e17da880ad3717e141b',
}


def pin(file):
    file = file.resolve(strict=True)
    with file.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(path=str(file), sha256=digest)


def prepare(args):
    host = {'Darwin-arm64': 'darwin-arm64', 'Linux-x86_64': 'linux-x64',
            'Linux-aarch64': 'linux-arm64'}.get(platform.system() + '-' + platform.machine())
    toolchains = json.loads((ROOT / 'runtime/toolchains.json').read_text())
    if host not in toolchains:
        raise ValueError('Unsupported native build host')
    lock = json.loads((ROOT / 'runtime/fast-prover/source-lock.json').read_text())
    suite = args.suite.resolve(strict=True)
    manifest_path = suite / 'suite-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    expected = [dict(role=role, compiled_artifact_sha256=value['artifact_sha256'],
                     vk_sha256=value['vk_sha256'], metadata_sha256=value['metadata_sha256'],
                     recursive_hash=value['recursive_hash'], public_bytes=value['public_bytes'])
                for role, value in lock['roles'].items()]
    if (manifest.get('protocol_version') != 10 or manifest.get('roles') != expected
            or manifest.get('noir_version') != '1.0.0-beta.25'
            or manifest.get('bb_version') != '5.2.0'
            or manifest.get('verifier_target') != 'noir-recursive'):
        raise ValueError('Suite differs from the maintained source lock')
    programs = []
    for role in expected:
        directory = suite / role['role']
        for file, field in [('circuit.json', 'compiled_artifact_sha256'),
                            ('vk', 'vk_sha256'), ('vk.json', 'metadata_sha256')]:
            if pin(directory / file)['sha256'] != role[field]:
                raise ValueError('Suite file pin mismatch: ' + role['role'] + '/' + file)
        programs.append(dict(role=role['role'], directory=str(directory),
                             artifact=str(directory / 'circuit.json')))
    tools = {name: pin(args.tools / filename) for name, filename in {
        'nargo': 'nargo', 'bb': 'bb', 'bitcoind': 'bitcoind', 'bitcoin_cli': 'bitcoin-cli',
        'zark_wallet': 'zark-wallet', 'zark_signer': 'zark-signer',
        'executor': 'executor', 'prover': 'prover', 'helper': 'zark-fast-helper',
    }.items()}
    for name, field in [('nargo', 'nargo_sha256'), ('bb', 'verifier_sha256')]:
        if tools[name]['sha256'] != toolchains[host][field]:
            raise ValueError('Unqualified compiler/verifier: ' + name)
    for file, expected_hash in CRS.items():
        if pin(args.crs / file)['sha256'] != expected_hash:
            raise ValueError('CRS pin mismatch: ' + file)
    if not 1 <= args.threads <= 32:
        raise ValueError('Use between 1 and 32 workers')
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    programs_path = output / 'programs.json'
    programs_path.write_text(json.dumps(programs, indent=2) + '\n')
    runtime = {key: tools.pop(key) for key in ('executor', 'prover', 'helper')}
    runtime.update(witness_threads=args.threads, prove_threads=args.threads,
                   verify_threads=args.threads, extended_native_hints=True)
    (output / 'runs').mkdir(mode=0o700)
    flow = dict(manifest=str(manifest_path), manifest_sha256=pin(manifest_path)['sha256'],
                programs=str(programs_path), crs=str(args.crs.resolve()),
                run_parent=str(output / 'runs'), fast_runtime=runtime, **tools)
    (output / 'flow.json').write_text(json.dumps(flow, indent=2) + '\n')
    print(output / 'flow.json')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('suite', 'tools', 'crs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--threads', type=int, default=4)
    prepare(parser.parse_args())
