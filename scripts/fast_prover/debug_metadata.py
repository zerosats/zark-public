"""Minimal pinned Noir debug metadata preserving error-formatter indexes."""
import base64
import copy
import gzip
import json
import zlib
from . import msgpack as native_api

def program_field(value, name, index):
    if isinstance(value, list): return value[index]
    return value[name] if name in value else value[index]

def stripped_artifact(original):
    stripped = copy.deepcopy(original)
    debug = json.loads(zlib.decompress(base64.b64decode(original['debug_symbols'], validate=True), -zlib.MAX_WBITS))
    raw = gzip.decompress(base64.b64decode(original['bytecode'], validate=True))
    if raw[0] != 3: raise ValueError('unsupported pinned ACIR format')
    program = native_api.decode(raw[1:])
    circuits = program_field(program, 'functions', 0)
    hints = program_field(program, 'unconstrained_functions', 1)
    if set(debug) != {'debug_infos'} or len(debug['debug_infos']) != len(circuits):
        raise ValueError('debug vector does not match circuit vector')
    fields = ('brillig_locations', 'location_tree', 'acir_locations', 'variables',
              'functions', 'types', 'brillig_procedure_locs')
    minimal = {'debug_infos': []}
    for info in debug['debug_infos']:
        if set(info) != set(fields) or set(info['location_tree']) != {'locations'}:
            raise ValueError('unexpected pinned DebugInfo schema')
        locations = info['location_tree']['locations']
        if not locations or locations[0]['parent'] is not None:
            raise ValueError('missing parentless root')
        ids = set(info['brillig_locations'])
        if any(str(int(key)) != key or not 0 <= int(key) < len(hints) for key in ids):
            raise ValueError('invalid Brillig debug index')
        ids.update(str(index) for index in range(len(hints)))
        empty = {key: {} for key in fields}
        empty['brillig_locations'] = {key: {} for key in sorted(ids, key=int)}
        empty['location_tree'] = {'locations': [copy.deepcopy(locations[0])]}
        minimal['debug_infos'].append(empty)
    encoder = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    encoded = encoder.compress(json.dumps(minimal, separators=(',', ':')).encode()) + encoder.flush()
    stripped['debug_symbols'] = base64.b64encode(encoded).decode('ascii')
    stripped['file_map'] = {}
    if json.loads(zlib.decompress(base64.b64decode(stripped['debug_symbols']), -zlib.MAX_WBITS)) != minimal:
        raise ValueError('invalid debug encoding')
    changed = {key for key in original if original[key] != stripped[key]}
    if set(original) != set(stripped) or changed != {'debug_symbols', 'file_map'}:
        raise ValueError('unexpected metadata transformation')
    return stripped
