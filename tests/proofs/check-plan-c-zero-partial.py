#!/usr/bin/env python3
"""Real proofs for a mathematically valid zero predecessor partial.

The independent fixture checks the completed Bitcoin signature equation. The
new receiver proof is consumed by both a fresh sender and a fresh exit proof.
"""
import argparse,json,os
from fixture_prover import FixtureProver
from plan_c_fixtures import Fixtures,b32,even_secret,mul,serialize_values
from support import fields,digest

def main(args):
    runner=FixtureProver(args.qualification,args.work,['receiver_authorization','sender_from_transfer','exit_from_transfer'])
    cfg=b32(mul(even_secret('origin attestation'))[0])+b''.join(bytes.fromhex(pin['recursive_hash']) for pin in runner.manifest['roles'])
    f=Fixtures(cfg,deployment=bytes.fromhex(runner.qualification['deployment_id']));origin=f.origin();_,rv,bob=f.handover(origin,1,zero_partial=True)
    assert bob['partial']==bytes(32)
    expected=b''.join(bytes(31)+bytes([x]) for x in rv['handover'])
    assert (runner.source/'sender-1/public_inputs').read_bytes()==expected
    def inputs(path,role,prefix):
        return {prefix+'_vk':json.loads((runner.source/(role+'-key/vk.json')).read_text())['vk'],prefix+'_proof':fields((path/'proof').read_bytes())}
    rv.update(inputs(runner.source/'sender-1','sender_from_origin','handover'))
    (runner.work/'prepared-zero-receiver.json').write_text(json.dumps(serialize_values(rv))+'\n')
    if args.prepare_only:return
    receiver=runner.prove('receiver_authorization','zero-receiver',rv)
    sv,_,_=f.handover(bob,2)
    sv.update(previous_authorization=f.authorization(bob),previous_partial=bob['partial'],**inputs(receiver,'receiver_authorization','previous'))
    runner.prove('sender_from_transfer','zero-predecessor-sender',sv)
    ev=f.exit(bob,1)
    ev.update(previous_authorization=f.authorization(bob),previous_partial=bob['partial'],**inputs(receiver,'receiver_authorization','current'))
    runner.prove('exit_from_transfer','zero-predecessor-exit',ev)
    runner.report(dict(synthetic_fixture=True,valid_zero_partial=True,completed_signature_group_equation_checked=True,
        live_signer_flow=False,fixture_source_sha256=digest(runner.root/'tests/proofs/plan_c_fixtures.py')))

if __name__=='__main__':
    os.umask(0o077);parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification',default='work/plan-c-proof-qualification');parser.add_argument('--work',default='work/plan-c-zero-partial')
    parser.add_argument('--prepare-only',action='store_true');main(parser.parse_args())
