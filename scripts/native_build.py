"""Build native release components without embedding the builder's home path."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess


def environment(source, original=None):
    env = dict(os.environ if original is None else original)
    encoded = env.get('CARGO_ENCODED_RUSTFLAGS')
    flags = encoded.split('\x1f') if encoded is not None else shlex.split(env.get('RUSTFLAGS', ''))
    flags = [flag for flag in flags if flag]
    # More specific mappings go last, as required by rustc. Preserve caller flags.
    flags.extend(['--remap-path-prefix=' + str(Path.home()) + '=/build/home',
                  '--remap-path-prefix=' + str(Path(source).resolve()) + '=/zark'])
    env.pop('RUSTFLAGS', None)
    env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
    env['CARGO_INCREMENTAL'] = '0'
    return env


def check_local_paths(binary):
    if os.fsencode(str(Path.home()) + '/') in Path(binary).read_bytes():
        raise ValueError('Native binary contains a local home path: ' + str(binary))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--toolchain', default='1.95.0')
    parser.add_argument('cargo_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    flags = args.cargo_args[1:] if args.cargo_args[:1] == ['--'] else args.cargo_args
    if not flags:
        parser.error('Provide cargo arguments after --')
    subprocess.run(['cargo', '+' + args.toolchain, *flags], cwd=args.source,
                   env=environment(args.source), check=True)
