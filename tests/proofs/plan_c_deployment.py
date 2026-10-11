"""Deterministic regtest identity for synthetic six-role proof qualification.

Encoding mirrors the native manifest/deployment ID definitions. Native verifier
tests independently recompute both IDs; these keys must never hold real funds.
"""
from plan_c_fixtures import b32,even_secret,h,le,mul,sha
from plan_c_suite import ROLES

def suite_id(manifest):
    assert manifest['protocol_version']==10
    assert [p['role'] for p in manifest['roles']]==[r for r,_,_,_ in ROLES]
    encoded=b'ZARK/private-suite/v1\0noir-1.0.0-beta.25\0bb-5.2.0\0noir-recursive\0'+le(10)
    for i,pin in enumerate(manifest['roles']):
        encoded+=bytes([i])+b''.join(bytes.fromhex(pin[k]) for k in ['compiled_artifact_sha256','vk_sha256','recursive_hash','metadata_sha256'])+le(pin['public_bytes'])
    return sha(encoded)

def deployment(manifest):
    value=dict(protocol_version=10,signer_protocol_version=5,network='regtest',
        genesis_hash='0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
        signet_challenge='',initial_delay=25,gap=3,margin=1,
        origin_key=b32(mul(even_secret('origin attestation'))[0]).hex(),
        control_key=b32(mul(even_secret('control attestation'))[0]).hex(),
        suite=suite_id(manifest).hex())
    policy=h('ZARK/private-handoff/policy/v1',le(10),le(25),le(3),le(1),le(8))
    identity=h('ZARK/private-deployment/v2',le(10),le(5),b'\0',bytes.fromhex(value['genesis_hash']),le(0),policy,
        bytes.fromhex(value['origin_key']),bytes.fromhex(value['control_key']),bytes.fromhex(value['suite']))
    return value,identity
