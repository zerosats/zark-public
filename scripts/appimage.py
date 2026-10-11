"""Preserve authenticated tools across linuxdeploy's ELF rewriting."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def digest(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_resources(app, trust, flow, node_sha256):
    for entry in json.loads((trust / 'asset-hashes.json').read_text())['files']:
        if digest(app / 'prebuilt' / entry['path']) != entry['sha256']:
            raise ValueError('Packaged asset pin mismatch: ' + entry['path'])
    for file, pin in [('bin/zark-wallet', flow['zark_wallet']['sha256']),
                      ('node/bin/node', node_sha256)]:
        if digest(app / file) != pin:
            raise ValueError('Packaged runtime pin mismatch: ' + file)


def preserve_and_verify(cache, stage, output, trust, flow, node_sha256, target, log):
    # linuxdeploy discovers shared libraries, but also rewrites RPATH in every
    # embedded ELF, including our hash-pinned tools. Restore the authenticated
    # resources after dependency collection, then use only its output plugin.
    # The app's existing LD_LIBRARY_PATH supplies the collected libraries.
    appdir = cache / 'release/bundle/appimage/Zark.AppDir'
    resources = appdir / 'usr/lib/Zark/app'
    if not resources.is_dir():
        raise ValueError('Tauri AppDir resource layout changed')
    shutil.copytree(stage, resources, dirs_exist_ok=True)
    verify_resources(resources, trust, flow, node_sha256)
    plugin = Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'tauri/linuxdeploy-plugin-appimage.AppImage'
    if not plugin.is_file():
        raise ValueError('Tauri AppImage output plugin is missing: ' + str(plugin))
    bundle = output / ('Zark-0.1.0-' + target + '.AppImage')
    subprocess.run([str(plugin), '--appimage-extract-and-run', '--appdir', str(appdir)],
                   env={**os.environ, 'OUTPUT': str(bundle),
                        'ARCH': 'aarch64' if target == 'linux-arm64' else 'x86_64',
                        'APPIMAGE_EXTRACT_AND_RUN': '1'},
                   check=True, stdout=log, stderr=log)
    bundle.chmod(0o755)
    # Checking the staging directory alone misses mutations made by bundlers.
    with tempfile.TemporaryDirectory(prefix='verify-appimage-', dir=output) as directory:
        subprocess.run([str(bundle), '--appimage-extract'], cwd=directory,
                       check=True, stdout=log, stderr=log)
        verify_resources(Path(directory) / 'squashfs-root/usr/lib/Zark/app',
                         trust, flow, node_sha256)
    return bundle
