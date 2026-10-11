import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import subprocess
import ssl
import re
import unittest
from native_build import environment

spec=importlib.util.spec_from_file_location('package',Path(__file__).with_name('build-desktop.py'))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimePackagingTests(unittest.TestCase):
    def test_every_packaged_relative_import_resolves_without_legacy_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module.stage_runtime(root)
            relay = root / 'apps/desktop/relay'
            self.assertEqual({p.name for p in relay.iterdir()},
                             {'signer-client.mjs', 'messaging-client.mjs', 'mailbox-connection.mjs'})
            for file in root.rglob('*.mjs'):
                for reference in re.findall(r'''(?:from\s*|import\s*\()["'](\.[^"']+)["']''', file.read_text()):
                    self.assertTrue((file.parent / reference).is_file(), str(file) + ': ' + reference)

    def test_path_remapping_preserves_caller_compiler_flags(self):
        env = environment('/tmp/zark-source', {'RUSTFLAGS': '-C "opt-level=2"'})
        flags = env['CARGO_ENCODED_RUSTFLAGS'].split('\x1f')
        self.assertEqual(flags[:2], ['-C', 'opt-level=2'])
        self.assertNotIn('RUSTFLAGS', env)
        self.assertEqual(flags[-1], '--remap-path-prefix=' + str(Path('/tmp/zark-source').resolve()) + '=/zark')
        encoded = environment('/tmp/zark-source', {'CARGO_ENCODED_RUSTFLAGS': '-C\x1fopt-level=1',
                                                  'RUSTFLAGS': '--ignored'})
        self.assertEqual(encoded['CARGO_ENCODED_RUSTFLAGS'].split('\x1f')[:2], ['-C', 'opt-level=1'])


class TrustFileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.trust = Path(self.directory.name)/'trust'
        self.trust.mkdir()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-days', '1', '-subj', '/CN=synthetic-test-only',
            '-keyout', str(Path(self.directory.name)/'key.pem'),
            '-out', str(self.trust/'certificate.pem')], check=True, capture_output=True)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-days', '1', '-subj', '/CN=synthetic-gateway-only',
            '-keyout', str(Path(self.directory.name)/'gateway-key.pem'),
            '-out', str(self.trust/'public-chain-certificate.pem')], check=True, capture_output=True)
        fingerprint = module.certificate_sha(self.trust/'certificate.pem')
        deployment = dict(protocol_version=10, initial_delay=34560, gap=2880, margin=1440, suite='11'*32)
        (self.trust/'deployment.json').write_text(json.dumps(deployment))
        common = dict(deployment='22'*32, suite='11'*32, manifest_sha256='33'*32, certificate_sha256=fingerprint)
        for name, value in {
            'deployment-receipt.json': dict(common, protocol_version=10, address='127.0.0.1:17448',
                deployment_file_sha256=module.sha(self.trust/'deployment.json')),
            'public-deployment-pins.json': dict(common, version=10),
            'public-services.json': dict(signer_address='127.0.0.1:17448', chain_certificate_sha256=module.certificate_sha(self.trust/'public-chain-certificate.pem')),
        }.items():
            (self.trust/name).write_text(json.dumps(value))

    def tearDown(self):
        self.directory.cleanup()

    def edit(self, name, **changes):
        path = self.trust/name
        path.write_text(json.dumps(dict(json.loads(path.read_text()), **changes), indent=2)+'\n')

    def schedule(self, **changes):
        self.edit('deployment.json', **changes)
        self.edit('deployment-receipt.json', deployment_file_sha256=module.sha(self.trust/'deployment.json'))

    def test_eight_owner_schedule_and_trust_files_agree(self):
        module.check_trust(self.trust)

    def test_old_three_owner_schedule_is_rejected_even_with_matching_receipt(self):
        self.schedule(initial_delay=20160)
        with self.assertRaisesRegex(ValueError, 'eight-owner recovery schedule'):
            module.check_trust(self.trust)

    def test_recovery_budget_boundary(self):
        self.schedule(initial_delay=21600)
        module.check_trust(self.trust)
        self.schedule(initial_delay=21599)
        with self.assertRaisesRegex(ValueError, 'eight-owner recovery schedule'):
            module.check_trust(self.trust)

    def test_invalid_recovery_fields_are_rejected(self):
        for changes in [dict(initial_delay=65536), dict(initial_delay=0),
                        dict(gap=0), dict(gap=65536), dict(margin=0),
                        dict(margin=2880), dict(margin=-1),
                        dict(initial_delay='34560'), dict(gap=True), dict(margin=1.5)]:
            with self.subTest(changes=changes):
                self.schedule(initial_delay=34560, gap=2880, margin=1440)
                self.schedule(**changes)
                with self.assertRaisesRegex(ValueError, 'eight-owner recovery schedule'):
                    module.check_trust(self.trust)

    def test_gateway_certificate_is_required(self):
        (self.trust/'public-chain-certificate.pem').unlink()
        with self.assertRaisesRegex(ValueError, 'must include public-chain-certificate.pem'):
            module.check_trust(self.trust)

    def test_other_gateway_certificate_is_rejected(self):
        shutil.copyfile(self.trust/'certificate.pem', self.trust/'public-chain-certificate.pem')
        with self.assertRaisesRegex(ValueError, 'gateway certificate'):
            module.check_trust(self.trust)

    def test_additional_gateway_certificate_is_rejected(self):
        with (self.trust/'public-chain-certificate.pem').open('a') as stream:
            stream.write((self.trust/'certificate.pem').read_text())
        with self.assertRaisesRegex(ValueError, 'exactly one certificate'):
            module.check_trust(self.trust)

    def test_gateway_pin_mismatch_is_rejected(self):
        self.edit('public-services.json', chain_certificate_sha256='00'*32)
        with self.assertRaisesRegex(ValueError, 'gateway certificate'):
            module.check_trust(self.trust)

    def test_signer_address_mismatch_is_rejected(self):
        self.edit('public-services.json', signer_address='127.0.0.1:12345')
        with self.assertRaisesRegex(ValueError, 'signer address'):
            module.check_trust(self.trust)

    def test_missing_receipt_address_is_rejected(self):
        self.edit('deployment-receipt.json', address=None)
        with self.assertRaisesRegex(ValueError, 'signer address'):
            module.check_trust(self.trust)

    def test_other_certificate_is_rejected(self):
        shutil.copyfile(self.trust/'public-chain-certificate.pem', self.trust/'certificate.pem')
        with self.assertRaisesRegex(ValueError, 'signer certificate'):
            module.check_trust(self.trust)

    def test_additional_certificate_is_rejected(self):
        extra = (self.trust/'public-chain-certificate.pem').read_text()
        with (self.trust/'certificate.pem').open('a') as stream:
            stream.write(extra)
        with self.assertRaisesRegex(ValueError, 'exactly one certificate'):
            module.check_trust(self.trust)

    def test_changed_deployment_file_is_rejected(self):
        self.edit('deployment.json', gap=2881)
        with self.assertRaisesRegex(ValueError, 'deployment file'):
            module.check_trust(self.trust)

    def test_pins_for_another_suite_are_rejected(self):
        self.edit('public-deployment-pins.json', suite='00'*32)
        with self.assertRaisesRegex(ValueError, 'suite'):
            module.check_trust(self.trust)

    def test_pins_for_another_deployment_are_rejected(self):
        self.edit('public-deployment-pins.json', deployment='00'*32)
        with self.assertRaisesRegex(ValueError, 'deployment identity'):
            module.check_trust(self.trust)


class PlatformTests(unittest.TestCase):
    def test_supported_native_build_hosts(self):
        for system, machine, target in [('Darwin', 'arm64', 'darwin-arm64'),
                ('Linux', 'x86_64', 'linux-x64'), ('Linux', 'aarch64', 'linux-arm64')]:
            self.assertEqual(module.platform_key(system, machine), target)
        with self.assertRaises(ValueError):
            module.platform_key('Darwin', 'x86_64')

    def test_cannot_package_tools_for_another_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'tool'
            headers = {
                'darwin-arm64': bytes.fromhex('cffaedfe0c000001') + bytes(12),
                'linux-x64': b'\x7fELF\x02\x01' + bytes(12) + (62).to_bytes(2, 'little'),
                'linux-arm64': b'\x7fELF\x02\x01' + bytes(12) + (183).to_bytes(2, 'little'),
            }
            for target, header in headers.items():
                binary.write_bytes(header)
                module.check_binary(binary, target)
                for wrong in headers.keys() - {target}:
                    with self.assertRaisesRegex(ValueError, 'Binary does not match'):
                        module.check_binary(binary, wrong)
            binary.write_bytes(b'#!/bin/sh\n')
            with self.assertRaises(ValueError):
                module.check_binary(binary, 'linux-arm64')




class PackagedProfileTests(unittest.TestCase):
    def test_deployments_do_not_reuse_old_wallets_and_explicit_base_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / 'legacy-wallet'
            legacy.write_text('existing recovery must remain unchanged')
            source = "import {fileURLToPath} from 'node:url'; console.log(process.env.ZARK_DESKTOP_BASE);"
            def base(deployment, override=None):
                entry = root / 'entry.mjs'
                entry.write_text(module.packaged_entrypoint(source, deployment))
                env = {k:v for k,v in os.environ.items() if k not in ('ZARK_DESKTOP_BASE', 'XDG_DATA_HOME')}
                env['HOME'] = directory
                if override: env['ZARK_DESKTOP_BASE'] = override
                return Path(subprocess.check_output(['node', str(entry)], env=env, text=True).strip())
            a, b = base('11'*32), base('22'*32)
            self.assertNotEqual(a, b)
            self.assertEqual(a.name, '11'*32)
            self.assertEqual(b.name, '22'*32)
            self.assertEqual(a.parent.name, 'deployments')
            self.assertEqual(base('11'*32, str(root/'chosen')), root/'chosen')
            self.assertEqual(legacy.read_text(), 'existing recovery must remain unchanged')
            with self.assertRaises(ValueError): module.packaged_entrypoint(source, '../legacy-wallet')

if __name__ == '__main__':
    unittest.main()
