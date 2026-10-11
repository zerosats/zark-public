#!/usr/bin/env python3
"""Build the Mac or Linux desktop app from qualified tools and explicit trust.

The flow file authenticates tools and the suite. Trust comes from the separate
signer receipt, never from an existing user's wallet. Compiled assets stay out
of Git. --admit-assets writes a new public asset inventory for operator review;
ordinary rebuilds require that admitted inventory to match exactly.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import ssl
import platform
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from appimage import preserve_and_verify
from native_build import environment as native_environment, check_local_paths

ROOT = Path(__file__).resolve().parents[1]


def sha(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(file):
    return json.loads(Path(file).read_text())


def run(*args, **kwargs):
    subprocess.run(list(map(str, args)), check=True, **kwargs)


def certificate_sha(file):
    if not file.is_file():
        raise ValueError('Trust directory must include ' + file.name)
    pem = file.read_text()
    if pem.count('-----BEGIN ') != 1:
        raise ValueError('Trust directory must hold exactly one certificate in ' + file.name)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def check_trust(trust):
    # The app checks these files against each other only at a user's first
    # launch. Refuse to build an app whose signer trust would fail there.
    receipt = load(trust / 'deployment-receipt.json')
    pins = load(trust / 'public-deployment-pins.json')
    deployment = load(trust / 'deployment.json')
    services = load(trust / 'public-services.json')
    certificate = certificate_sha(trust / 'certificate.pem')
    gateway_certificate = certificate_sha(trust / 'public-chain-certificate.pem')
    for agrees, name in [
            (certificate == receipt['certificate_sha256'] == pins['certificate_sha256'], 'signer certificate'),
            (gateway_certificate == services.get('chain_certificate_sha256'), 'gateway certificate'),
            (bool(receipt.get('address')) and services.get('signer_address') == receipt['address'], 'signer address'),
            (sha(trust / 'deployment.json') == receipt['deployment_file_sha256'], 'deployment file'),
            (pins['deployment'] == receipt['deployment'], 'deployment identity'),
            (deployment['suite'] == pins['suite'] == receipt['suite'], 'suite'),
            (pins['manifest_sha256'] == receipt['manifest_sha256'], 'suite manifest'),
            (deployment['protocol_version'] == receipt['protocol_version'] == pins['version'] == 10, 'protocol version')]:
        if not agrees:
            raise ValueError('Trust files disagree on the ' + name)
    initial, gap, margin = (deployment.get(name) for name in ('initial_delay', 'gap', 'margin'))
    # Match RecoverySchedule::validate and Noir's committed eight-owner policy.
    if (any(type(value) is not int for value in (initial, gap, margin))
            or not (1 <= initial <= 65535 and 1 <= gap <= 65535 and 0 < margin < gap)
            or initial < 7 * gap + margin):
        raise ValueError('Invalid eight-owner recovery schedule: initial_delay must cover 7 * gap + margin')


def platform_key(system=None, machine=None):
    pair = (system or platform.system(), machine or platform.machine())
    targets = {('Darwin', 'arm64'): 'darwin-arm64', ('Linux', 'x86_64'): 'linux-x64',
               ('Linux', 'aarch64'): 'linux-arm64'}
    if pair not in targets:
        raise ValueError('Build on Apple Silicon macOS or x86-64/arm64 Linux')
    return targets[pair]


def check_binary(file, target):
    # Refuse accidental cross-platform tools before producing a distributable.
    with Path(file).open('rb') as stream:
        header = stream.read(20)
    if target == 'darwin-arm64':
        valid = header[:8] == bytes.fromhex('cffaedfe0c000001')
    else:
        machine = 62 if target == 'linux-x64' else 183
        valid = (header[:6] == b'\x7fELF\x02\x01' and len(header) == 20
                 and int.from_bytes(header[18:20], 'little') == machine)
    if not valid:
        raise ValueError('Binary does not match ' + target + ': ' + str(file))


def assets(flow, trust, destination, admit, target=None):
    target = target or platform_key()
    target_platform = target
    destination.mkdir(parents=True)
    files = []

    def copy(source, relative, pin, executable=False):
        if sha(source) != pin:
            raise ValueError('Input pin mismatch: ' + str(source))
        if executable:
            check_binary(source, target_platform)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755 if executable else 0o644)
        if sha(target) != pin:
            raise ValueError('Copy changed: ' + relative)
        files.append(dict(path=relative, sha256=pin))

    receipt = load(trust / 'deployment-receipt.json')
    manifest_path = Path(flow['manifest'])
    if flow['manifest_sha256'] != receipt['manifest_sha256'] or sha(manifest_path) != receipt['manifest_sha256']:
        raise ValueError('Qualified suite differs from deployment signer')
    manifest = load(manifest_path)
    if manifest['protocol_version'] != 10:
        raise ValueError('Expected v10 suite')
    programs = []
    for role in manifest['roles']:
        name = role['role']
        if not name.replace('_', '').isalnum():
            raise ValueError('Invalid suite role')
        for filename, field in [('circuit.json', 'compiled_artifact_sha256'), ('vk', 'vk_sha256'), ('vk.json', 'metadata_sha256')]:
            copy(manifest_path.parent / name / filename, f'suite/{name}/{filename}', role[field])
        copy(manifest_path.parent / name / 'circuit.json', f'circuits/{name}/target/{name}.json', role['compiled_artifact_sha256'])
        programs.append(dict(role=name, directory=name, artifact=name + '.json'))
    copy(manifest_path, 'suite/suite-manifest.json', receipt['manifest_sha256'])
    for key, filename in [('nargo', 'nargo'), ('bb', 'bb'), ('bitcoin_cli', 'bitcoin-cli-core-30.2')]:
        copy(flow[key]['path'], 'tools/' + filename, flow[key]['sha256'], True)
    runtime = flow['fast_runtime']
    for key in ['executor', 'prover', 'helper']:
        copy(runtime[key]['path'], 'tools/' + key, runtime[key]['sha256'], True)
    for name, pin in [('bn254_g1.dat', 'd777711ae9fb1951c47a0eaf7e0ebcaccc39e6731d9b3a560d7ff0c2fcdf2f0d'),
                      ('bn254_g1_compressed.dat', 'bf9f1cdbe7b7bb2667c8ee5b887f6ce8b07ec99d60944e17da880ad3717e141b')]:
        copy(Path(flow['crs']) / name, 'crs/' + name, pin)
    copy(trust / 'certificate.pem', 'certificate.pem', sha(trust / 'certificate.pem'))
    result = dict(version=1, protocol_version=10, prebuilt_required=True, programs=programs, files=files,
                  fast_runtime=dict(platform=target, executor='tools/executor', prover='tools/prover', helper='tools/helper',
                                    **{k: runtime[k] for k in ['witness_threads', 'prove_threads', 'verify_threads', 'extended_native_hints']}))
    inventory = trust / 'asset-hashes.json'
    if admit:
        if inventory.exists():
            raise ValueError('Preserving existing asset admission; review a new directory')
        inventory.write_text(json.dumps(result, indent=2) + '\n')
    elif load(inventory) != result:
        raise ValueError('Packaged assets differ from checked-in admission')


def stage_shell(destination):
    shutil.copytree(ROOT / 'apps/desktop-tauri', destination, ignore=shutil.ignore_patterns('target', 'stage', 'gen'))
    config = load(destination / 'tauri.conf.json')
    config.update(version='0.1.0', productName='Zark', identifier='org.zerosats.zark.desktop')
    (destination / 'tauri.conf.json').write_text(json.dumps(config, indent=2) + '\n')


def stage_runtime(app):
    excluded = ('README.md', 'host-smoke.mjs', 'retire-legacy.mjs', 'server.mjs', 'client.mjs')
    for folder in ['apps/desktop/runtime', 'apps/desktop/relay']:
        shutil.copytree(ROOT / folder, app / folder,
            ignore=shutil.ignore_patterns('*.test.mjs', 'test-support', '__pycache__',
                *excluded),
            dirs_exist_ok=True)
    for name in excluded:
        (app / 'apps/desktop/relay' / name).unlink(missing_ok=True)


def build_mac_shell(shell, output, destination):
    # Tauri also embeds CARGO_MANIFEST_DIR as a literal. rustc path remapping
    # does not cover that, so compile its staged source outside any user's home.
    with tempfile.TemporaryDirectory(prefix='zark-shell-', dir='/tmp') as temporary:
        source = Path(temporary) / 'source'
        shutil.copytree(shell, source, ignore=shutil.ignore_patterns('target'))
        with (output / 'build.log').open('w') as log:
            run('cargo', '+1.95.0', 'build', '--release', '--locked', '-j', '2', cwd=source,
                env={**native_environment(source), 'CARGO_TARGET_DIR': str(Path(temporary) / 'target'),
                     'MACOSX_DEPLOYMENT_TARGET': '13.3'}, stdout=log, stderr=log)
        binary = Path(temporary) / 'target/release/zark-desktop'
        check_local_paths(binary)
        shutil.copyfile(binary, destination)
        destination.chmod(0o755)


def packaged_entrypoint(source, deployment):
    if len(deployment) != 64 or any(c not in '0123456789abcdef' for c in deployment):
        raise ValueError('Invalid packaged deployment identity')
    # Frozen wallets cannot switch signer identities. Keep every deployment's
    # profiles separate, while retaining an explicit operator-selected base.
    return ("import os from 'node:os';\nimport path from 'node:path';\n"
            "const profileBase = process.platform === 'darwin' ? path.join(os.homedir(), 'Library/Application Support/Zark') : path.join(process.env.XDG_DATA_HOME && path.isAbsolute(process.env.XDG_DATA_HOME) ? process.env.XDG_DATA_HOME : path.join(os.homedir(), '.local/share'), 'zark');\n"
            "process.env.ZARK_DESKTOP_BASE ??= path.join(profileBase, 'deployments', " + json.dumps(deployment) + ");\n"
            "process.env.ZARK_PROFILE ??= 'wallet';\n"
            "process.env.ZARK_TRUSTED_RUNTIME = fileURLToPath(new URL('.', import.meta.url));\n"
            "process.env.ZARK_ASSET_SOURCE = fileURLToPath(new URL('../../../prebuilt', import.meta.url));\n" + source)


def package(args):
    host = platform_key()
    flow, trust = load(args.flow), args.trust.resolve(strict=True)
    check_trust(trust)
    output = args.output.resolve()
    output.mkdir(mode=0o755)
    bundle = output / 'Zark.app'
    contents = bundle / 'Contents'
    app = contents / 'Resources/app' if host == 'darwin-arm64' else output / 'linux-resources/app'
    assets(flow, trust, app / 'prebuilt', args.admit_assets, host)
    stage_runtime(app)
    runtime = app / 'apps/desktop/runtime'
    for name in ['asset-hashes.json', 'deployment.json', 'public-deployment-pins.json', 'public-services.json']:
        shutil.copyfile(trust / name, runtime / name)
    # Never silently fall back to the repository's older gateway identity.
    shutil.copyfile(trust / 'public-chain-certificate.pem', runtime / 'public-chain-certificate.pem')
    entry = runtime / 'app.mjs'
    # Resolve relative to the installed bundle; never embed the builder's home.
    entry.write_text(packaged_entrypoint(entry.read_text(), load(trust / 'deployment-receipt.json')['deployment']))
    for source, target, pin in [(args.node, app / 'node/bin/node', args.node_sha256),
                               (Path(flow['zark_wallet']['path']), app / 'bin/zark-wallet', flow['zark_wallet']['sha256'])]:
        if sha(source) != pin:
            raise ValueError('Runtime binary pin mismatch: ' + str(source))
        check_binary(source, platform_key())
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755)
    shutil.copyfile(ROOT / 'LICENSE', app / 'LICENSE')
    shutil.copytree(ROOT / 'licenses', app / 'licenses')
    shell = output / 'shell-source'
    stage_shell(shell)
    if host.startswith('linux-'):
        package_linux(args, flow, trust, output, app, shell, host)
        return
    (contents / 'MacOS').mkdir()
    build_mac_shell(shell, output, contents / 'MacOS/zark-desktop')
    iconset = output / 'zark.iconset'
    iconset.mkdir()
    for size in [16, 32, 128, 256, 512]:
        for scale in [1, 2]:
            filename = f'icon_{size}x{size}' + ('@2x' if scale == 2 else '') + '.png'
            run('sips', '-z', str(size * scale), str(size * scale), ROOT / 'apps/desktop-tauri/icons/icon.png',
                '--out', iconset / filename, stdout=subprocess.DEVNULL)
    run('iconutil', '-c', 'icns', iconset, '-o', contents / 'Resources/icon.icns')
    with (contents / 'Info.plist').open('wb') as stream:
        plistlib.dump(dict(CFBundleName='Zark', CFBundleDisplayName='Zark',
            CFBundleIdentifier='org.zerosats.zark.desktop', CFBundleExecutable='zark-desktop',
            CFBundlePackageType='APPL', CFBundleVersion='1', CFBundleShortVersionString='0.1.0',
            LSMinimumSystemVersion='13.3', NSHighResolutionCapable=True, CFBundleIconFile='icon.icns'), stream)
    # Signing the outer bundle must not rewrite authenticated nested binaries.
    run('codesign', '--force', '--sign', '-', bundle)
    run('codesign', '--verify', '--deep', '--strict', bundle)
    for entry in load(trust / 'asset-hashes.json')['files']:
        if sha(app / 'prebuilt' / entry['path']) != entry['sha256']:
            raise ValueError('Signing changed a pinned asset')
    if sha(app / 'bin/zark-wallet') != flow['zark_wallet']['sha256'] or sha(app / 'node/bin/node') != args.node_sha256:
        raise ValueError('Signing changed a runtime binary')
    (output / 'build-receipt.json').write_text(json.dumps(dict(platform='darwin-arm64',
        source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        source_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()),
        wallet_sha256=flow['zark_wallet']['sha256'], node_sha256=args.node_sha256,
        asset_inventory_sha256=sha(trust / 'asset-hashes.json'), minimum_macos='13.3',
        signing='ad-hoc; not notarized'), indent=2) + '\n')
    print(bundle, flush=True)


def package_linux(args, flow, trust, output, app, shell, target):
    # Tauri's resource mapping is shared with the ordinary Linux release.
    app.rename(shell / 'stage')
    cache = args.target_cache.resolve() if args.target_cache else shell / 'target'
    with (output / 'build.log').open('w') as log:
        run('cargo', '+1.95.0', 'tauri', 'build', '--ci', '--config', 'tauri.release.conf.json',
            '--bundles', 'appimage', '--', '--locked', cwd=shell,
            env={**os.environ, 'CARGO_TARGET_DIR': str(cache), 'CARGO_BUILD_JOBS': '2'},
            stdout=log, stderr=log)
    with (output / 'build.log').open('a') as log:
        bundle = preserve_and_verify(cache, shell / 'stage', output, trust, flow,
                                     args.node_sha256, target, log)
    (output / 'build-receipt.json').write_text(json.dumps(dict(platform=target,
        source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        source_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()),
        wallet_sha256=flow['zark_wallet']['sha256'], node_sha256=args.node_sha256,
        asset_inventory_sha256=sha(trust / 'asset-hashes.json'), bundle_sha256=sha(bundle),
        signing='unsigned', extracted_resources_verified=True), indent=2) + '\n')
    print(bundle, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['flow', 'trust', 'node', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--node-sha256', required=True)
    parser.add_argument('--target-cache', type=Path)
    parser.add_argument('--admit-assets', action='store_true')
    package(parser.parse_args())
