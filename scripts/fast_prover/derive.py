"""Derive witness bytecode while preserving the complete qualified Circuit vector.

This is an artifact transformation from two pinned compiler outputs. It is not
the raw output of the compiler and cannot qualify a source-level circuit change.
"""
import base64
import copy
import gzip
import hashlib
import json
import struct
import zlib

from . import debug_metadata as metadata
from . import msgpack as native_api

OPCODES = ("BinaryFieldOp", "BinaryIntOp", "Not", "Cast", "JumpIf", "Jump", "CalldataCopy",
           "Call", "Const", "IndirectConst", "Return", "ForeignCall", "Mov", "ConditionalMov",
           "Load", "Store", "BlackBox", "Trap", "Stop")
FOREIGN_FUNCTIONS = frozenset(("zark_glv_hint_v1", "zark_glv_batch_hint_v1", "zark_fixed_generator_hint_v1"))


# gzip.compress writes OS byte 255 on some Python versions and the zlib build's
# own OS code (19 on macOS, 3 on Linux) on others. Pinned artifacts must not
# depend on either, so the member header is fixed: mtime 0, XFL 2 (level 9) and
# OS 19, which reproduces the admitted v10 artifacts byte for byte.
GZIP_HEADER = bytes.fromhex("1f8b0800000000000213")


def deterministic_gzip(raw):
    deflate = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = deflate.compress(raw) + deflate.flush()
    return GZIP_HEADER + body + struct.pack("<II", zlib.crc32(raw) & 0xFFFFFFFF, len(raw) & 0xFFFFFFFF)


def field(value, name, index):
    if isinstance(value, list): return value[index]
    return value[name] if name in value else value[index]


def assign(value, name, index, replacement):
    if isinstance(value, list): value[index] = replacement
    else: value[name if name in value else index] = replacement


def decode(artifact):
    raw = gzip.decompress(base64.b64decode(artifact["bytecode"], validate=True))
    if raw[0] != 3: raise ValueError("derivation is restricted to pinned named MessagePack format3")
    program = native_api.decode(raw[1:])
    if len(program) != 2: raise ValueError("unexpected Program fields")
    circuits = field(program, "functions", 0)
    hints = field(program, "unconstrained_functions", 1)
    if not isinstance(circuits, list) or not isinstance(hints, list) or not circuits or not hints:
        raise ValueError("nonempty circuit and hint vectors required")
    return raw[0], program, circuits, hints


def call_sites(circuits):
    result = []
    for circuit_index, circuit in enumerate(circuits):
        if len(circuit) != 6: raise ValueError("unexpected pinned Circuit fields")
        for opcode_index, opcode in enumerate(field(circuit, "opcodes", 1)):
            if not isinstance(opcode, dict) or set(opcode) != {"BrilligCall"}: continue
            call = opcode["BrilligCall"]
            if len(call) != 4: raise ValueError("unexpected BrilligCall fields")
            result.append((circuit_index, opcode_index, call))
    return result


def compatible_map(old_circuits, new_circuits, old_pool, new_pool):
    if len(old_circuits) != len(new_circuits): raise ValueError("circuit vector count differs")
    left, right = call_sites(old_circuits), call_sites(new_circuits)
    if len(left) != len(right) or not left: raise ValueError("ordered Brillig call-site count differs")
    forward, reverse, sites = {}, {}, []
    for (old_circuit, old_opcode, a), (new_circuit, new_opcode, b) in zip(left, right):
        if old_circuit != new_circuit: raise ValueError("Brillig call moved between circuits")
        for index, name in ((1, "inputs"), (2, "outputs"), (3, "predicate")):
            if field(a, name, index) != field(b, name, index):
                raise ValueError("Brillig call interface differs: " + name)
        i, j = field(a, "id", 0), field(b, "id", 0)
        if (type(i) is not int or type(j) is not int
                or not 0 <= i < len(old_pool) or not 0 <= j < len(new_pool)):
            raise ValueError("Brillig function ID out of pool bounds")
        if forward.get(i, j) != j or reverse.get(j, i) != i:
            raise ValueError("Brillig function mapping is not one-to-one")
        forward[i], reverse[j] = j, i
        sites.append(dict(circuit=old_circuit, original_opcode=old_opcode, donor_opcode=new_opcode,
                          original_id=i, donor_id=j))
    return forward, sites


def validate_local_bytecode(entry):
    if len(entry) != 2: raise ValueError("unexpected whole Brillig entry schema")
    code = field(entry, "bytecode", 1)
    if not isinstance(code, list) or not code: raise ValueError("empty Brillig bytecode")
    foreign = set()
    for instruction in code:
        if isinstance(instruction, str):
            if instruction != "Return": raise ValueError("unsupported unit Brillig opcode")
            continue
        if not isinstance(instruction, dict) or len(instruction) != 1:
            raise ValueError("unexpected Brillig opcode shape")
        name, payload = next(iter(instruction.items()))
        if name not in OPCODES: raise ValueError("unsupported Brillig opcode: " + str(name))
        if name in ("Jump", "Call", "JumpIf"):
            location = field(payload, "location", 1 if name == "JumpIf" else 0)
            if type(location) is not int or not 0 <= location < len(code):
                raise ValueError("Brillig jump/call target leaves its own bytecode slice")
        if name == "ForeignCall":
            function = field(payload, "function", 0)
            if function not in FOREIGN_FUNCTIONS: raise ValueError("unsupported foreign call: " + str(function))
            foreign.add(function)
    return sorted(foreign)


def merge_abi(original, donor, allowed_additions):
    if set(original) != set(donor) or "error_types" not in original:
        raise ValueError("ABI shape differs")
    if {k:v for k,v in original.items() if k != "error_types"} != {k:v for k,v in donor.items() if k != "error_types"}:
        raise ValueError("non-diagnostic ABI fields differ")
    a, b = original["error_types"], donor["error_types"]
    if any(a[key] != b[key] for key in a.keys() & b.keys()): raise ValueError("ABI error selector collision")
    additions = {key: b[key] for key in sorted(b.keys() - a.keys())}
    if additions != allowed_additions: raise ValueError("unreviewed donor diagnostic catalog additions")
    result = copy.deepcopy(original)
    result["error_types"].update(additions)
    return result


def derive(original_path, donor_path, output_path, allowed_additions):
    if output_path.exists(): raise ValueError("fresh derived artifact path required")
    original, donor = (json.loads(path.read_text()) for path in (original_path, donor_path))
    fmt, program, circuits, old_pool = decode(original)
    donor_fmt, _, donor_circuits, donor_pool = decode(donor)
    if donor_fmt != fmt: raise ValueError("artifact format changed")
    mapping, sites = compatible_map(circuits, donor_circuits, old_pool, donor_pool)
    replacement = copy.deepcopy(old_pool)
    functions = []
    for old_id, new_id in sorted(mapping.items()):
        names = validate_local_bytecode(donor_pool[new_id])
        replacement[old_id] = copy.deepcopy(donor_pool[new_id])
        functions.append(dict(original_id=old_id, donor_id=new_id, foreign_calls=names,
            old_sha256=hashlib.sha256(native_api.encode(old_pool[old_id])).hexdigest(),
            donor_sha256=hashlib.sha256(native_api.encode(donor_pool[new_id])).hexdigest()))
    if len(replacement) != len(old_pool): raise ValueError("original Brillig pool length changed")
    derived_program = copy.deepcopy(program)
    assign(derived_program, "unconstrained_functions", 1, replacement)
    raw = bytes((fmt,)) + native_api.encode(derived_program)
    roundtrip = native_api.decode(raw[1:])
    if field(roundtrip, "functions", 0) != circuits:
        raise ValueError("complete constrained Circuit vector changed during serialization")
    if field(roundtrip, "unconstrained_functions", 1) != replacement:
        raise ValueError("whole Brillig pool changed during serialization")
    result = copy.deepcopy(original)
    result["abi"] = merge_abi(original["abi"], donor["abi"], allowed_additions)
    result["bytecode"] = base64.b64encode(deterministic_gzip(raw)).decode("ascii")
    result = metadata.stripped_artifact(result)
    expected_changes = {"bytecode", "debug_symbols", "file_map"} | ({"abi"} if allowed_additions else set())
    changed = {key for key in original if original[key] != result[key]}
    if set(original) != set(result) or changed != expected_changes:
        raise ValueError("derived artifact changed fields beyond the declared boundary")
    _, _, final_circuits, final_pool = decode(result)
    if final_circuits != circuits or final_pool != replacement:
        raise ValueError("final derived artifact lost exact Circuit or Brillig identity")
    output_path.write_text(json.dumps(result, separators=(",", ":")) + "\n")
    return dict(artifact_kind="derived witness artifact; not raw compiler output",
        original_artifact=str(original_path), donor_artifact=str(donor_path),
        original_pool_length=len(old_pool), donor_pool_length=len(donor_pool), derived_pool_length=len(final_pool),
        exact_whole_circuit_vector=True, exact_non_diagnostic_abi=True,
        abi_identical_to_original=result["abi"] == original["abi"],
        original_error_catalog_preserved=True, added_error_types=allowed_additions,
        untouched_pool_ids=sorted(set(range(len(old_pool))) - set(mapping)),
        ordered_call_sites=sites, transplanted_functions=functions,
        changed_artifact_fields=sorted(changed), format=fmt,
        constrained_sha256=hashlib.sha256(native_api.encode(circuits)).hexdigest(),
        minimal_debug="qualified empty maps for all old IDs and root-only location trees; source diagnostics removed")
