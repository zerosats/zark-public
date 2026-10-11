"""Strict injective encoding for isolated research proof ABI; canonical bytes unchanged."""
FIELD_MODULUS=21888242871839275222246405745257275088548364400416034343698204186575808495617
ROLE_BYTES={'deposit_authorization':1466,'sender_from_origin':685,'sender_from_transfer':685,
            'receiver_authorization':877,'exit_from_origin':877,'exit_from_transfer':877}

def pack_bytes(statement,length):
    raw=bytes(statement)
    if len(raw)!=length:raise ValueError('canonical statement length')
    return [int.from_bytes(raw[i:i+31],'big') for i in range(0,length,31)]

def encode_public(statement,length):
    return b''.join(x.to_bytes(32,'big') for x in pack_bytes(statement,length))

def decode_public(encoded,length):
    if len(encoded)!=32*((length+30)//31):raise ValueError('public field count')
    result=bytearray()
    for i in range(0,len(encoded),32):
        value=int.from_bytes(encoded[i:i+32],'big')
        width=min(31,length-len(result))
        if value>=FIELD_MODULUS or value>=1<<(8*width):raise ValueError('noncanonical chunk or nonzero high padding')
        result.extend(value.to_bytes(width,'big'))
    return bytes(result)

def check_public(encoded,statement,length):
    canonical=bytes(statement)
    if decode_public(encoded,length)!=canonical or encoded!=encode_public(canonical,length):
        raise ValueError('proof public inputs do not bind authoritative canonical statement')
