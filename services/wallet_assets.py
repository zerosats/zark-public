"""Only authenticated public suite files may cross the browser bridge."""
import hashlib
import os
import re
import stat
import tempfile
from pathlib import Path
from wallet_transport import decode_json

ROLES = ("deposit_authorization", "sender_from_origin", "sender_from_transfer",
         "receiver_authorization", "exit_from_origin", "exit_from_transfer")
NAMES = {"suite/suite-manifest.json"} | {
    f"suite/{role}/{filename}" for role in ROLES for filename in ("circuit.json", "vk", "vk.json")}
MAX_ASSET = 512 * 1024 * 1024


class PublicSuite:
    def __init__(self, suite, inventory, pins):
        self.root = Path(suite).resolve(strict=True)
        inventory = decode_json(Path(inventory).read_bytes())
        if inventory.get("version") != 1 or inventory.get("protocol_version") != 10 or inventory.get("complete") is not True:
            raise ValueError("invalid suite inventory")
        self.hashes = {}
        for entry in inventory["files"]:
            name, digest = entry["path"], entry["sha256"]
            if name == "certificate.pem":
                continue  # Native public certificate is not an asset route.
            if name not in NAMES or name in self.hashes or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("invalid suite asset")
            self.hashes[name] = digest
        if set(self.hashes) != NAMES or self.hashes["suite/suite-manifest.json"] != pins["manifest_sha256"]:
            raise ValueError("incomplete or mismatched suite inventory")
        self.verify()

    def authenticated(self, name):
        if name not in self.hashes:
            raise KeyError(name)
        file = self.root / name.removeprefix("suite/")
        if not file.resolve(strict=True).is_relative_to(self.root):
            raise ValueError("asset outside suite")
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
        snapshot = tempfile.SpooledTemporaryFile(max_size=1024 * 1024)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ASSET:
                raise ValueError("invalid suite file")
            digest, size = hashlib.sha256(), 0
            while chunk := os.read(fd, 1024 * 1024):
                size += len(chunk)
                if size > MAX_ASSET:
                    raise ValueError("suite file limit")
                digest.update(chunk)
                snapshot.write(chunk)
            if digest.hexdigest() != self.hashes[name]:
                raise ValueError("suite file hash mismatch")
            # Serve the authenticated snapshot, avoiding a hash/read TOCTOU gap.
            snapshot.seek(0)
            return snapshot, size
        except BaseException:
            snapshot.close()
            raise
        finally:
            os.close(fd)

    def verify(self):
        for name in self.hashes:
            snapshot, _ = self.authenticated(name)
            snapshot.close()
