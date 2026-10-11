"""Classify native negative fixtures using ACIR-only diagnostic metadata.

Derived release artifacts strip source locations. Qualification restores only
constrained-opcode locations from a parent with an identical Circuit vector;
Brillig locations stay empty because its witness bytecode was replaced.
"""
import base64
import copy
import json
from pathlib import Path
import re
import sys
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from fast_prover.derive import decode

BATCH = 'batched origin partials and attestation'
EXPECTED = {
    'cancelling-origin-activation-and-attestation': BATCH,
    'shifted-origin-activation-partial': BATCH,
    'wrong-origin-attestation-scalar': BATCH,
    'wrong-origin-activation-partial': BATCH,
    'wrong-origin-recovery-partial': 'exact authorized state and issuance',
    'wrong-previous-partial': 'signer partial equation',
    'wrong-recipient': None,
}


def diagnostic_artifact(native_path, fused_path, output):
    native, fused = (json.loads(p.read_text()) for p in (native_path, fused_path))
    if decode(native)[2] != decode(fused)[2]:
        raise ValueError('Diagnostic parent has a different constrained Circuit vector')
    for key in ('parameters', 'return_type'):
        if native['abi'][key] != fused['abi'][key]:
            raise ValueError('Diagnostic parent has a different ABI')
    def debug(artifact):
        return json.loads(zlib.decompress(base64.b64decode(artifact['debug_symbols']), -15))
    target, parent = debug(native), debug(fused)
    if len(target['debug_infos']) != len(parent['debug_infos']):
        raise ValueError('Diagnostic function count differs')
    for info, source in zip(target['debug_infos'], parent['debug_infos']):
        for key in ('acir_locations', 'location_tree'):
            info[key] = source[key]
        info['brillig_locations'] = {key: {} for key in info['brillig_locations']}
        info['brillig_procedure_locs'] = {}
    result = copy.deepcopy(native)
    compressor = zlib.compressobj(wbits=-15)
    result['debug_symbols'] = base64.b64encode(compressor.compress(json.dumps(target).encode()) + compressor.flush()).decode()
    result['file_map'] = fused['file_map']
    assert all(result[k] == native[k] for k in native if k not in ('debug_symbols', 'file_map'))
    output.write_text(json.dumps(result) + '\n')


def require_rejection(label, run, diagnostic=False):
    text = run.stderr + run.stdout
    # Executor returns 1 for a circuit rejection. Signals, usage errors, and
    # failures to read inputs must never be counted as successful negatives.
    summary = "Failed to solve program: 'Cannot satisfy constraint'" if label == 'wrong-recipient' else 'Failed assertion'
    if run.returncode != 1 or summary not in text.splitlines():
        raise ValueError(f'{label}: unexpected execution failure ({run.returncode}): {text[-1200:]}')
    if diagnostic:
        expected = EXPECTED[label]
        if expected is not None:
            if f'error: Assertion failed: {expected}' not in text.splitlines():
                raise ValueError(f'{label}: did not reach expected assertion: {expected}')
        elif not ('error: Failed constraint' in text.splitlines()
                  and re.search(r'private-transfer-relations/src/claim\.nr:32:5\b', text)
                  and 'assert(actual.x == claimed.x)' in text):
            raise ValueError(f'{label}: did not reach the claim-key equality constraint')
    return dict(rejected_at='constrained_execution', expected_assertion=EXPECTED[label] or 'claim.nr:32:5 claim-key equality')
