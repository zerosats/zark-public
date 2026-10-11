#!/usr/bin/env python3
"""Sign a qualified Mac bundle while retaining exact tools for frozen wallets.

This prepares a NEW app, not a notarization claim. Submit the resulting app to
Apple, staple its ticket, and verify Gatekeeper before distributing it.
"""
import argparse
import hashlib
import importlib.util
import json
import plistlib
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from native_build import check_local_paths

ROOT = Path(__file__).resolve().parents[1]
MACHO = {bytes.fromhex(value) for value in ('cffaedfe', 'feedfacf', 'cafebabe', 'bebafeca')}


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def sha(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(file):
    return json.loads(Path(file).read_text())


def unsigned_hash(binary, directory):
    # Compare executable bytes after the same platform tool removes signatures.
    # Never remove a signature from an original or installed wallet tool.
    copy = directory / 'unsigned-check'
    run('cp', '-c', binary, copy)
    try:
        run('codesign', '--remove-signature', copy, capture_output=True)
        data = bytearray(copy.read_bytes())
        if data[:4] != bytes.fromhex('cffaedfe'):
            raise ValueError('Expected a thin 64-bit Apple Silicon executable')
        position = 32
        for _ in range(struct.unpack_from('<I', data, 16)[0]):
            command, size = struct.unpack_from('<II', data, position)
            if size < 8 or position + size > len(data):
                raise ValueError('Invalid Mach-O load command')
            if command == 0x19 and data[position + 8:position + 24].rstrip(b'\0') == b'__LINKEDIT':
                # codesign removes the signature bytes but retains the segment's
                # old VM reservation. Its size varies with the signature size;
                # normalize only this field, retaining every byte of code/data
                # and all other load-command fields in the comparison.
                data[position + 32:position + 40] = bytes(8)
            position += size
        return hashlib.sha256(data).hexdigest()
    finally:
        copy.unlink()


def package(args):
    original = args.input.resolve(strict=True)
    output = args.output.resolve()
    if output.exists():
        raise ValueError('Use a new empty output path; preserve previous packages')
    receipt = load(args.receipt)
    old_app = original / 'Contents/Resources/app'
    old_runtime = old_app / 'apps/desktop/runtime'
    inventory = old_runtime / 'asset-hashes.json'
    if sha(inventory) != receipt['asset_inventory_sha256']:
        raise ValueError('Input asset inventory differs from the qualified receipt')
    for relative, pin in [('bin/zark-wallet', receipt['wallet_sha256']), ('node/bin/node', receipt['node_sha256'])]:
        if sha(old_app / relative) != pin:
            raise ValueError('Input runtime differs from the qualified receipt: ' + relative)
    manifest = load(inventory)
    for entry in manifest['files']:
        if sha(old_app / 'prebuilt' / entry['path']) != entry['sha256']:
            raise ValueError('Input tool or circuit differs from admission: ' + entry['path'])
    run('codesign', '--verify', '--deep', '--strict', original)
    output.mkdir(parents=True)
    bundle = output / 'Zark.app'
    run('cp', '-cR', original, bundle)
    app = bundle / 'Contents/Resources/app'
    runtime = app / 'apps/desktop/runtime'

    # Install this source revision's runtime, including frozen-tool compatibility.
    spec = importlib.util.spec_from_file_location('build_desktop', ROOT / 'scripts/build-desktop.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    builder.stage_runtime(app)
    entry = runtime / 'app.mjs'
    pins = load(runtime / 'public-deployment-pins.json')
    entry.write_text(builder.packaged_entrypoint(entry.read_text(), pins['deployment']))

    before = inventory.read_bytes()
    previous_hash = hashlib.sha256(before).hexdigest()
    (runtime / f'asset-hashes-{previous_hash}.json').write_bytes(before)
    history = [previous_hash, *manifest.get('previous_asset_manifests', [])]
    for pin in history:
        if len(pin) != 64 or any(c not in '0123456789abcdef' for c in pin):
            raise ValueError('Invalid input manifest history')
        if sha(runtime / f'asset-hashes-{pin}.json') != pin:
            raise ValueError('Input manifest history hash mismatch')

    signed = []
    with tempfile.TemporaryDirectory(prefix='signing-', dir=output) as temporary:
        temp = Path(temporary)
        entitlements = temp / 'node.plist'
        with entitlements.open('wb') as stream:
            plistlib.dump({'com.apple.security.cs.allow-jit': True}, stream)
        for binary in sorted(bundle.rglob('*')):
            if not binary.is_file():
                continue
            with binary.open('rb') as stream:
                if stream.read(4) not in MACHO:
                    continue
            relative = binary.relative_to(bundle)
            check_local_paths(binary)
            # Keep Core's qualified, timestamped Developer ID signature byte-for-byte.
            if relative.as_posix().endswith('/prebuilt/tools/bitcoin-cli-core-30.2'):
                metadata = run('codesign', '-dv', '--verbose=4', binary, capture_output=True, text=True).stderr
                if ('Authority=Developer ID Application:' not in metadata or 'Timestamp=' not in metadata
                        or '(runtime)' not in metadata):
                    raise ValueError('Bitcoin CLI needs a timestamped Developer ID hardened-runtime signature')
                run('codesign', '--verify', '--strict', binary)
                continue
            unsigned = unsigned_hash(binary, temp)
            original_hash = sha(binary)
            options = ['--entitlements', entitlements] if relative.as_posix().endswith('/node/bin/node') else []
            run('codesign', '--force', '--sign', args.identity, '--options', 'runtime', '--timestamp', *options, binary)
            if unsigned_hash(binary, temp) != unsigned:
                raise ValueError('Signing changed executable bytes: ' + str(relative))
            run('codesign', '--verify', '--strict', binary)
            signed.append({'path': str(relative), 'before_sha256': original_hash,
                           'sha256': sha(binary), 'unsigned_sha256': unsigned})

    # The protocol suite, deployment and Bitcoin CLI pins remain unchanged.
    for entry in manifest['files']:
        file = app / 'prebuilt' / entry['path']
        actual = sha(file)
        if actual != entry['sha256']:
            relative = str(file.relative_to(bundle))
            if not any(item['path'] == relative and item['before_sha256'] == entry['sha256'] for item in signed):
                raise ValueError('Unexpected asset change: ' + entry['path'])
            entry['sha256'] = actual
    manifest['asset_revision'] = hashlib.sha256(json.dumps(manifest['files'], sort_keys=True).encode()).hexdigest()
    manifest['previous_asset_manifests'] = list(dict.fromkeys(history))
    (runtime / 'asset-hashes.json').write_text(json.dumps(manifest, indent=2) + '\n')
    run('codesign', '--force', '--sign', args.identity, '--options', 'runtime', '--timestamp', bundle)
    run('codesign', '--verify', '--deep', '--strict', '--verbose=2', bundle)
    # Signing the outer app finalizes its main executable's identifier/seal.
    with tempfile.TemporaryDirectory(prefix='verify-signing-', dir=output) as temporary:
        for item in signed:
            binary = bundle / item['path']
            if sha(binary) != item['sha256']:
                if unsigned_hash(binary, Path(temporary)) != item['unsigned_sha256']:
                    raise ValueError('Outer signing changed executable bytes')
                item['sha256'] = sha(binary)
    for entry in manifest['files']:
        if sha(app / 'prebuilt' / entry['path']) != entry['sha256']:
            raise ValueError('Outer signing changed a pinned asset')
    result = {**receipt, 'native_source_commit': receipt['source_commit'],
              'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()),
              'wallet_sha256': sha(app / 'bin/zark-wallet'), 'node_sha256': sha(app / 'node/bin/node'),
              'asset_inventory_sha256': sha(runtime / 'asset-hashes.json'),
              'asset_revision': manifest['asset_revision'], 'signing': 'Developer ID; notarization pending',
              'signing_identity': args.identity, 'signature_only_binary_changes': signed,
              'input_receipt_sha256': sha(args.receipt)}
    (output / 'build-receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print(bundle)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--identity', required=True, help='Developer ID Application certificate fingerprint')
    package(parser.parse_args())
