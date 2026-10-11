"""Explicit research-v10 application commitments; Bitcoin hashing stays SHA256.

The wrapper uses the pinned width-four Poseidon2 permutation with rate two and
capacity two. Domain, byte length, injective BE31 chunks and field padding are
unambiguous. Two canonical field representatives each supply their low 128 bits.
This is a new, unaudited protocol construction, not Noir's stock hash function.
"""
import hashlib
from poseidon2_oracle import MODULUS, permutation

DOMAIN_BYTES = b"ZARK/app-commit/p2/v1"
DOMAIN = int.from_bytes(DOMAIN_BYTES, "big")
PROTOCOL_VERSION = 10
APPLICATION_NAMES = frozenset({
    "policy", "funding", "owner-capability", "recovery", "nonce", "signing",
    "server-share", "issuance", "state", "origin-predecessor", "origin-refresh",
    "origin-capability", "recipient", "intent", "mask", "masked-share", "bridge",
    "delta", "draft-access", "refresh", "bootstrap-nonce", "bootstrap-signing",
    "origin", "exit-intent", "exit", "exit-nonce", "exit-capability", "exit-share",
})
APPLICATION_TAGS = frozenset("ZARK/private-handoff/" + name + "/v1"
                             for name in APPLICATION_NAMES)


def encode_fields(message):
    if not isinstance(message, bytes):
        raise TypeError("application hash requires exact bytes")
    if len(message) >= 2**64:
        raise ValueError("application preimage too long")
    fields = [DOMAIN, len(message)]
    fields.extend(int.from_bytes(message[i:i+31], "big")
                  for i in range(0, len(message), 31))
    # The explicit byte length distinguishes partial final chunks with leading
    # zeroes, while the terminator makes the field stream padded unambiguously.
    fields.append(1)
    if len(fields) % 2:
        fields.append(0)
    assert all(0 <= value < MODULUS for value in fields)
    return fields


def application_hash(message):
    fields = encode_fields(message)
    state = [0, 0, 0, 0]
    for i in range(0, len(fields), 2):
        state[0] = (state[0] + fields[i]) % MODULUS
        state[1] = (state[1] + fields[i+1]) % MODULUS
        state = permutation(state)
    mask = 2**128 - 1
    return b"".join((x & mask).to_bytes(16, "big") for x in state[:2])


def h(tag, *parts):
    """Narrow fixture dispatch: only reviewed application tags use Poseidon2.

    Deployment identity remains SHA256 over its exact versioned serialization.
    Unknown tags fail closed; this cannot accidentally replace Bitcoin tagged
    hashes, artifact authentication, synthetic-key derivation or arbitrary SHA.
    """
    if type(tag) is not str or any(not isinstance(part, bytes) for part in parts):
        raise TypeError("tag must be text and all parts must be bytes")
    message = tag.encode("ascii") + b"".join(parts)
    if tag in APPLICATION_TAGS:
        return application_hash(message)
    if tag == "ZARK/private-deployment/v2":
        return hashlib.sha256(message).digest()
    raise ValueError("unreviewed application hash tag: " + tag)
