"""Download and verify the pinned ACME source before extraction; never execute it."""
import hashlib
from pathlib import Path
import subprocess
import sys

# acme.sh 3.1.6 signed tag, resolved to its source commit. A changed archive,
# including a GitHub compression change, fails closed and needs pin review.
COMMIT = "807da6498377ee5e0cf43a78091f46f12dc59a89"
SHA256 = "ddbe1bcbd1a44a2623a2af167ebdc678669e6e2eb396742f2d1d28e02dc14220"
URL = f"https://github.com/acmesh-official/acme.sh/archive/{COMMIT}.tar.gz"
MAX_ARCHIVE = 8 * 1024 * 1024


def prepare(stage):
    stage = Path(stage).resolve(strict=True)
    if not stage.is_dir() or any(stage.iterdir()):
        raise ValueError("ACME staging directory must be empty")
    archive = stage / "acme.tar.gz"
    subprocess.run([
        "curl", "--fail", "--silent", "--show-error", "--location",
        "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
        "--connect-timeout", "15", "--max-time", "120",
        "--max-filesize", str(MAX_ARCHIVE), URL, "--output", str(archive),
    ], check=True)
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("ACME archive too large")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise ValueError("ACME archive checksum mismatch; nothing extracted or executed")
    subprocess.run([
        "tar", "--no-same-owner", "--no-same-permissions",
        "-xzf", str(archive), "-C", str(stage),
    ], check=True)
    source = stage / f"acme.sh-{COMMIT}"
    if not (source / "acme.sh").is_file():
        raise ValueError("Verified ACME archive has no client")
    return source


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: prepare-acme-client.py EMPTY_STAGING_DIRECTORY")
    print(prepare(sys.argv[1]))
