"""Independent integer Poseidon2 oracle for the pinned Noir beta.25 permutation.

Research only. This implementation is deliberately ordinary Python arithmetic,
not a call into Noir or Barretenberg. Constants and upstream reference vectors
are pinned in constants.json. The five permutation vectors are published in
Noir's tests as cross-checks against zkhash 0.2.0 (HorizenLabs/poseidon2).
"""
import hashlib
import json
from pathlib import Path

CONSTANTS_PATH = Path(__file__).resolve().parents[2] / "crates/protocol/src/application_hash/constants.json"
CONSTANTS_SHA256 = "9818e07435f23729461a657ad42c058790ed7f38fd0929475548e9b1acec209d"
raw = CONSTANTS_PATH.read_bytes()
if hashlib.sha256(raw).hexdigest() != CONSTANTS_SHA256:
    raise ValueError("pinned Poseidon2 constants or provenance changed")
PARAMETERS = json.loads(raw)
MODULUS = int(PARAMETERS["field_modulus"])
DIAGONAL = tuple(int(x, 16) for x in PARAMETERS["internal_matrix_diagonal"])
ROUND_CONSTANTS = tuple(tuple(int(x, 16) for x in row)
                        for row in PARAMETERS["round_constants"])
assert PARAMETERS["noir_commit"] == "75061fab15986eedee4e7d9104ff87dd9fa4ca10"
assert (PARAMETERS["state_width"], PARAMETERS["full_rounds"],
        PARAMETERS["partial_rounds"]) == (4, 8, 56)
assert len(ROUND_CONSTANTS) == 64
assert all(len(row) == 4 for row in ROUND_CONSTANTS)
assert all(0 <= x < MODULUS for x in DIAGONAL)
assert all(0 <= x < MODULUS for row in ROUND_CONSTANTS for x in row)


def external_matrix(state):
    """Equivalent integer matrix, independently expressed from upstream steps."""
    a, b, c, d = state
    return [(5*a + 7*b + c + 3*d) % MODULUS,
            (4*a + 6*b + c + d) % MODULUS,
            (a + 3*b + 5*c + 7*d) % MODULUS,
            (a + b + 4*c + 6*d) % MODULUS]


def permutation(values):
    if len(values) != 4 or any(type(x) is not int or not 0 <= x < MODULUS
                               for x in values):
        raise ValueError("permutation requires four canonical BN254 scalars")
    state = external_matrix(values)
    for round_index, constants in enumerate(ROUND_CONSTANTS):
        if round_index < 4 or round_index >= 60:
            state = external_matrix([pow((x + c) % MODULUS, 5, MODULUS)
                                     for x, c in zip(state, constants)])
        else:
            # Internal rounds use only the first round constant and S-box.
            assert constants[1:] == (0, 0, 0)
            state[0] = pow((state[0] + constants[0]) % MODULUS, 5, MODULUS)
            total = sum(state)
            state = [(x*d + total) % MODULUS for x, d in zip(state, DIAGONAL)]
    return state


def stock_hash(fields):
    """Pinned dependency's rate-three hash, only for its reference tests.

    Zark application_hash does NOT use this one-field/capacity-one wrapper.
    """
    if any(type(x) is not int or not 0 <= x < MODULUS for x in fields):
        raise ValueError("noncanonical field input")
    state = [0, 0, 0, (len(fields) << 64) % MODULUS]
    for start in range(0, len(fields), 3):
        for lane, value in enumerate(fields[start:start+3]):
            state[lane] = (state[lane] + value) % MODULUS
        state = permutation(state)
    return (state if fields else permutation(state))[0]


def validate_reference_vectors():
    for case in PARAMETERS["permutation_reference_vectors"]:
        actual = permutation([int(x, 16) for x in case["input"]])
        assert actual == [int(x, 16) for x in case["output"]]
    expected = [
        0x16433a80e26a23547e25d61dd95fd5793d1ca2dcd78ae64cd146d3b99a35fa7c,
        0x118d5a5ecb25dafe99eb45cb196604a23d0b7c0cbd0c2be29e0787e59b7a1d8a,
        0x0f1badcd0d52ced816fb6e6826fdf66ada038135d53cbb993f320ca6529223cd,
    ]
    for size, reference in enumerate(expected, 1):
        assert stock_hash([1000*(i+1) for i in range(size)]) == reference
    return {"upstream_permutation_vectors": 5, "upstream_stock_hash_vectors": 3}


if __name__ == "__main__":
    print(json.dumps(validate_reference_vectors(), indent=2))
