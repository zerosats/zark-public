"""Pinned ACIR format-three MessagePack codec; no execution or network access."""
import struct

def encode(value):
    if value is None: return b'\xc0'
    if isinstance(value, bool):
        return b'\xc3' if value else b'\xc2'
    if isinstance(value, bytes):
        return b'\xc6'+struct.pack('>I', len(value))+value
    if isinstance(value, str):
        raw = value.encode()
        return b'\xdb'+struct.pack('>I', len(raw))+raw
    if isinstance(value, int) and 0 <= value < 2**32:
        return b'\xce'+struct.pack('>I', value)
    if isinstance(value, int) and 0 <= value < 2**64:
        return b'\xcf'+struct.pack('>Q', value)
    if isinstance(value, int) and -(2**63) <= value < 0:
        return b'\xd3'+struct.pack('>q', value)
    if isinstance(value, list):
        return b'\xdd'+struct.pack('>I', len(value))+b''.join(map(encode, value))
    if isinstance(value, dict):
        return b'\xdf'+struct.pack('>I', len(value))+b''.join(encode(k)+encode(v) for k,v in value.items())
    raise TypeError(type(value))

def decode(raw):
    index = 0
    def take(n):
        nonlocal index
        result = raw[index:index+n]
        if len(result) != n: raise ValueError('truncated MessagePack')
        index += n
        return result
    def number(n): return int.from_bytes(take(n), 'big')
    def read():
        code = number(1)
        if code <= 0x7f: return code
        if code >= 0xe0: return code-256
        if code == 0xc0: return None
        if code in (0xc2,0xc3): return code == 0xc3
        if code in (0xcc,0xcd,0xce,0xcf): return number(2**(code-0xcc))
        if code in (0xc4,0xc5,0xc6): return take(number(2**(code-0xc4)))
        if code in (0xd9,0xda,0xdb): return take(number(2**(code-0xd9))).decode()
        if 0xa0 <= code <= 0xbf: return take(code & 31).decode()
        if 0x90 <= code <= 0x9f or code in (0xdc,0xdd):
            n = code & 15 if code < 0xa0 else number(2 if code == 0xdc else 4)
            return [read() for _ in range(n)]
        if 0x80 <= code <= 0x8f or code in (0xde,0xdf):
            n = code & 15 if code < 0x90 else number(2 if code == 0xde else 4)
            result = {}
            for _ in range(n):
                key, value = read(), read()
                if key in result: raise ValueError('duplicate MessagePack map key')
                result[key] = value
            return result
        raise ValueError('unsupported MessagePack tag '+hex(code))
    result = read()
    if index != len(raw): raise ValueError('trailing MessagePack bytes')
    return result
