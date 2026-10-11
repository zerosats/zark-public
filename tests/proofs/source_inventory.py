"""Exact inventories for the local Noir sources used by qualification."""
import hashlib
from pathlib import Path
import stat
import tomllib

from plan_c_suite import LIBRARIES, ROLES

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 10000
VENDOR_PACKAGES = ('noir-bignum', 'noir_bigcurve', 'poseidon')


def inventory(directory, packages=None):
    """Hash compiler inputs, rejecting links and incomplete package trees."""
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('source directory missing or linked: ' + str(directory))
    pins = {}
    entries = 0

    def visit(path, depth):
        nonlocal entries
        entries += 1
        if entries > MAX_ENTRIES or depth > 32:
            raise ValueError('source inventory exceeds bounds')
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                if child.name not in ('target', 'Prover.toml'):
                    visit(child, depth + 1)
        elif not stat.S_ISREG(info.st_mode):
            raise ValueError('source inventory contains a link or special file: ' + str(path))
        elif path.name == 'Nargo.toml' or path.suffix == '.nr':
            if info.st_size > MAX_SOURCE_BYTES:
                raise ValueError('source file exceeds size bound: ' + str(path))
            with path.open('rb') as stream:
                data = stream.read(MAX_SOURCE_BYTES + 1)
            if len(data) != info.st_size or len(data) > MAX_SOURCE_BYTES:
                raise ValueError('source changed while reading: ' + str(path))
            pins[path.relative_to(directory).as_posix()] = hashlib.sha256(data).hexdigest()

    if packages is None:
        visit(directory, 0)
    else:
        for package in packages:
            visit(directory / package, 0)
    if not pins:
        raise ValueError('empty source inventory: ' + str(directory))
    return pins


def circuit_pins(circuits, selected=False):
    """Keep report paths stable: sources are relative to the qualification root."""
    circuits = Path(circuits)
    packages = LIBRARIES + [package for _, package, _, _ in ROLES]
    pins = inventory(circuits, packages if selected else None)
    required = [package + '/Nargo.toml' for package in packages if package != 'vendor']
    required += ['vendor/' + package + '/Nargo.toml' for package in VENDOR_PACKAGES]
    if any(name not in pins for name in required):
        raise ValueError('incomplete circuit package inventory')
    # Compiling these manifests must not escape to an unpinned external tree.
    for name in pins:
        if not name.endswith('/Nargo.toml'):
            continue
        manifest = circuits / name
        data = tomllib.loads(manifest.read_text())
        for dependency in data.get('dependencies', {}).values():
            if not isinstance(dependency, dict) or set(dependency) != {'path'}:
                raise ValueError('qualification requires local pinned dependencies: ' + name)
            relative = dependency['path']
            if not isinstance(relative, str) or Path(relative).is_absolute():
                raise ValueError('dependency must use a relative source path: ' + name)
            target = (manifest.parent / relative / 'Nargo.toml').resolve(strict=True)
            if not target.is_relative_to(circuits.resolve()):
                raise ValueError('dependency escapes staged circuits: ' + name)
            if target.relative_to(circuits.resolve()).as_posix() not in pins:
                raise ValueError('dependency missing from source inventory: ' + name)
    return {'circuits/' + name: pin for name, pin in pins.items()}


def dependency_pins(sources):
    prefix = 'circuits/vendor/'
    pins = {name[len(prefix):]: pin for name, pin in sources.items() if name.startswith(prefix)}
    if not pins:
        raise ValueError('qualification has no staged dependency pins')
    return pins


def check_pins(expected, actual, label):
    if not isinstance(expected, dict) or not expected or expected != actual:
        raise ValueError(label + ' inventory mismatch (missing, extra, or changed source)')


def verify_qualification_sources(report, qualification, root, copied=None):
    """Bind reports to compiled sources, current vendor, and any isolated copy."""
    sources = circuit_pins(Path(qualification) / 'circuits')
    check_pins(report.get('sources'), sources, 'qualified circuit')
    dependencies = dependency_pins(sources)
    check_pins(report.get('dependencies'), dependencies, 'qualified dependency')
    check_pins(dependencies, inventory(Path(root) / 'circuits/vendor'), 'maintained dependency')
    if copied is not None:
        check_pins(sources, circuit_pins(Path(copied) / 'circuits'), 'copied circuit')
