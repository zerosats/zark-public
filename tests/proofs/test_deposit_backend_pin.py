"""Keep the opt-in recursive backend bound to the maintained deposit key."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('suite_recipe', ROOT/'scripts/build-fast-prover-suite.py')
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


class DepositBackendPin(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads((ROOT/'runtime/fast-prover/source-lock.json').read_text())
        self.patch = ROOT/'runtime/fast-prover/barretenberg-deposit-aggregation.patch'

    def test_maintained_patch_matches_admitted_deposit_key(self):
        recipe.require_deposit_backend_pin(self.lock, self.patch)

    def test_changed_deposit_key_requires_backend_repin(self):
        changed = copy.deepcopy(self.lock)
        changed['roles']['deposit_authorization']['recursive_hash'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'key pin differs'):
            recipe.require_deposit_backend_pin(changed, self.patch)

    def test_missing_literal_is_rejected(self):
        (ROOT/'work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='deposit-pin-', dir=ROOT/'work') as directory:
            patch = Path(directory)/'backend.patch'
            patch.write_text('')
            with self.assertRaisesRegex(ValueError, 'key pin differs'):
                recipe.require_deposit_backend_pin(self.lock, patch)


if __name__ == '__main__':
    unittest.main()
