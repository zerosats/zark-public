import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "prepare_acme", Path(__file__).with_name("prepare-acme-client.py")
)
acme = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acme)


class PrepareAcmeTests(unittest.TestCase):
    def archive(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as bundle:
            content = b"# harmless test fixture, never executed\n"
            member = tarfile.TarInfo(f"acme.sh-{acme.COMMIT}/acme.sh")
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))
        return output.getvalue()

    def runner(self, data, calls):
        real_run = subprocess.run

        def run(command, **kwargs):
            calls.append(command)
            if command[0] == "curl":
                Path(command[-1]).write_bytes(data)
                return subprocess.CompletedProcess(command, 0)
            return real_run(command, **kwargs)

        return run

    def test_verified_archive_extracts_without_execution(self):
        data, calls = self.archive(), []
        with tempfile.TemporaryDirectory() as stage:
            with patch.object(acme, "SHA256", hashlib.sha256(data).hexdigest()), \
                 patch.object(acme.subprocess, "run", side_effect=self.runner(data, calls)):
                source = acme.prepare(stage)
            self.assertIn("harmless test fixture", (source / "acme.sh").read_text())
        self.assertEqual([command[0] for command in calls], ["curl", "tar"])
        self.assertIn("--no-same-owner", calls[1])
        self.assertIn("--no-same-permissions", calls[1])

    def test_wrong_or_corrupted_archive_never_reaches_extractor(self):
        original = self.archive()
        for data in (b"not an archive", original + b"changed"):
            with self.subTest(data_length=len(data)), tempfile.TemporaryDirectory() as stage:
                calls = []
                with patch.object(acme, "SHA256", hashlib.sha256(original).hexdigest()), \
                     patch.object(acme.subprocess, "run", side_effect=self.runner(data, calls)):
                    with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                        acme.prepare(stage)
                self.assertEqual([command[0] for command in calls], ["curl"])
                self.assertEqual([p.name for p in Path(stage).iterdir()], ["acme.tar.gz"])

    def test_nonempty_stage_is_rejected_before_download(self):
        with tempfile.TemporaryDirectory() as stage, patch.object(acme.subprocess, "run") as run:
            (Path(stage) / "old").write_text("preserve")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                acme.prepare(stage)
            run.assert_not_called()

    def test_download_failure_does_not_extract(self):
        with tempfile.TemporaryDirectory() as stage, patch.object(
            acme.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "curl")
        ) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                acme.prepare(stage)
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
