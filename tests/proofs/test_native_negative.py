import subprocess
import unittest
from native_negative import require_rejection


class NegativeTests(unittest.TestCase):
    def result(self, code, text):
        return subprocess.CompletedProcess([], code, '', text)

    def test_batch_requires_exact_assertion(self):
        label = 'wrong-origin-attestation-scalar'
        for code, text in [(-9, ''), (2, 'missing input'), (1, 'Failed assertion\n'),
                           (1, 'error: Assertion failed: another guard\nFailed assertion\n'),
                           (0, 'error: Assertion failed: batched origin partials and attestation\nFailed assertion\n')]:
            with self.subTest(code=code, text=text), self.assertRaises(ValueError):
                require_rejection(label, self.result(code, text), diagnostic=True)
        require_rejection(label, self.result(1, 'error: Assertion failed: batched origin partials and attestation\nFailed assertion\n'), diagnostic=True)

    def test_environment_errors_and_signals_never_qualify(self):
        for label in ('wrong-recipient', 'wrong-previous-partial'):
            for code in (-9, -15, 0, 1, 2, 101, 137):
                with self.subTest(label=label, code=code), self.assertRaises(ValueError):
                    require_rejection(label, self.result(code, 'failed to open input'))

    def test_anonymous_failure_requires_claim_location(self):
        summary = "error: Failed constraint\nFailed to solve program: 'Cannot satisfy constraint'\n"
        with self.assertRaises(ValueError):
            require_rejection('wrong-recipient', self.result(1, summary), diagnostic=True)
        require_rejection('wrong-recipient', self.result(1, summary + 'private-transfer-relations/src/claim.nr:32:5\nassert(actual.x == claimed.x)'), diagnostic=True)


if __name__ == '__main__':
    unittest.main()
