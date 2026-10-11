#!/usr/bin/env python3
"""Check native parity equations, then qualify eight full-deposit parity vectors.

Native recovery vectors are an independent arithmetic preflight. Fresh proofs
use the production fused deposit relation and cover all recovery parity triples;
no retired standalone authorization/completion proof is generated.
"""
import argparse,json,os
from pathlib import Path
from fixture_prover import FixtureProver
from plan_c_fixtures import Fixtures,N,P,add,mul,normal,tagged,b32,even_secret,serialize_values
from support import digest

def read_point(encoded):
    encoded=bytes(encoded);assert len(encoded)==64
    point=(int.from_bytes(encoded[:32],'big'),int.from_bytes(encoded[32:],'big'))
    assert point[0]<P and point[1]<P and point[1]**2%P==(point[0]**3+7)%P
    return point

def main(args):
    runner=FixtureProver(args.qualification,args.work,['deposit_authorization'])
    path=Path(args.fixtures).resolve();fixture=json.loads(path.read_text());cases=fixture['cases']
    assert len(cases)==8 and {tuple(c['parities']) for c in cases}=={(a,b,c) for a in [False,True] for b in [False,True] for c in [False,True]}
    for c in cases:
        s=bytes(c['statement']);assert len(s)==589 and s[:4]==b'\x09\0\0\0'
        user=int.from_bytes(bytes(c['user']),'big');a=int.from_bytes(bytes(c['alpha']),'big');b=int.from_bytes(bytes(c['beta']),'big')
        server=read_point(s[429:493]);nonce=read_point(s[493:557])
        raw_internal=add(server,mul(user));internal,_=normal(raw_internal)
        tweak=int.from_bytes(tagged('TapTweak',b32(internal[0])),'big');assert tweak<N
        raw_output=add(internal,mul(tweak));output,_=normal(raw_output)
        raw_nonce=add(add(nonce,mul(a)),mul(b,server))
        assert [bool(p[1]&1) for p in [raw_internal,raw_output,raw_nonce]]==c['parities']
        z=int.from_bytes(bytes(c['partial']),'big');challenge=int.from_bytes(s[557:589],'big')
        assert z<N and mul(z)==add(nonce,mul(challenge,server))
        signature=bytes(c['signature']);rx=int.from_bytes(signature[:32],'big');sy=int.from_bytes(signature[32:],'big')
        ry=pow((rx**3+7)%P,(P+1)//4,P);ry=ry if ry%2==0 else P-ry
        assert (ry*ry-rx**3-7)%P==0 and sy<N
        assert b32(output[0])==bytes(c['input_output_key'])
        e=int.from_bytes(tagged('BIP0340/challenge',signature[:32]+b32(output[0])+bytes(c['expected_message'])),'big')%N
        assert mul(sy)==add((rx,ry),mul(e,output))
    (runner.work/'prepared-fixture.json').write_text(json.dumps(fixture)+'\n')
    cfg=b32(mul(even_secret('origin attestation'))[0])+b''.join(bytes.fromhex(pin['recursive_hash']) for pin in runner.manifest['roles'])
    assert len(cfg)==224
    deposits={}
    for seed in range(512):
        f=Fixtures(cfg,parity_seed=seed,deployment=bytes.fromhex(runner.qualification['deployment_id']));origin=f.origin();s=origin['statement']
        server=read_point(s[429:493]);nonce=read_point(s[493:557])
        user=int.from_bytes(origin['user'],'big');a=int.from_bytes(origin['alpha'],'big');b=int.from_bytes(origin['beta'],'big')
        raw_internal=add(server,mul(user));internal,_=normal(raw_internal)
        tweak=int.from_bytes(tagged('TapTweak',b32(internal[0])),'big');assert tweak<N
        raw_output=add(internal,mul(tweak));raw_nonce=add(add(nonce,mul(a)),mul(b,server))
        parities=tuple(bool(p[1]&1) for p in [raw_internal,raw_output,raw_nonce])
        deposits.setdefault(parities,dict(seed=seed,parities=parities,values=serialize_values(f.deposit(origin))))
        if len(deposits)==8:break
    assert len(deposits)==8, 'full deposit parity fixture coverage incomplete'
    prepared=[deposits[p] for p in sorted(deposits)]
    (runner.work/'prepared-deposits.json').write_text(json.dumps(prepared)+'\n')
    if args.prepare_only:return
    for c in prepared:
        label=''.join('1' if flag else '0' for flag in c['parities'])
        runner.prove('deposit_authorization','deposit-'+label,c['values'])
    runner.report(dict(synthetic_native_fixture=True,native_equation_vectors=8,synthetic_deposit_parity_vectors=8,deposit_proofs=8,
        independent_group_equations_checked=True,fixture_sha256=digest(path),live_signer_flow=False))

if __name__=='__main__':
    os.umask(0o077);parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification',default='work/plan-c-proof-qualification');parser.add_argument('--work',default='work/plan-c-parity')
    parser.add_argument('--fixtures',default='work/plan-c-recovery-parity-fixtures.json');parser.add_argument('--prepare-only',action='store_true')
    main(parser.parse_args())
