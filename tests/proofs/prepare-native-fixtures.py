#!/usr/bin/env python3
"""Prepare pinned native verifier inputs from a completed synthetic qualification.

No proof generation and no wallet access. These fixtures exercise native suite
and deployment validation; they are not a production deployment configuration.
"""
import argparse,json,os
from pathlib import Path
from plan_c_deployment import deployment
from plan_c_suite import ROLES
from support import digest
from packed_inputs import decode_public

def main(args):
    source,suite,output,bb,crs=map(lambda p:Path(p).resolve(),
        (args.qualification,args.suite,args.output,args.bb,args.crs))
    report=json.loads((source/'report.json').read_text())
    manifest=json.loads((suite/'suite-manifest.json').read_text())
    assembly=json.loads((suite/'assembly-report.json').read_text())
    assert manifest==report['manifest']
    assert assembly['manifest_sha256']==digest(suite/'suite-manifest.json')
    assert assembly['source_report_sha256']==digest(source/'report.json')
    assert digest(bb)==report['toolchain']['bb_sha256']==assembly['bb_sha256']
    dep,identity=deployment(manifest)
    assert dep==report['deployment'] and identity.hex()==report['deployment_id']
    assert not output.exists(), 'use a fresh native fixture output directory'
    output.mkdir(mode=0o700,parents=True)
    scratch=output/'lineage-scratch';scratch.mkdir(mode=0o700)
    cases=[];statements={};proofs={}
    for role,_,public,_ in ROLES:
        pin=next(p for p in manifest['roles'] if p['role']==role)
        for name,field in [('circuit.json','compiled_artifact_sha256'),('vk','vk_sha256'),('vk.json','metadata_sha256')]:
            assert digest(suite/role/name)==pin[field]
        label=report['positive'][role]
        assert Path(label).name==label
        assert any(c['case']==label and c['role']==role and c['accepted'] and c['external_verification'] for c in report['cases'])
        proof=source/label/'proof';raw=(source/label/'public_inputs').read_bytes()
        assert proof.stat().st_size==14656 and manifest['protocol_version']==10
        statement=decode_public(raw,public)
        assert statement[:4]==b'\x0a\0\0\0' and statement[4:36]==identity
        statements[role]=statement;proofs[role]=proof
        cases.append(dict(role=role,statement=statement.hex(),proof=str(proof)))
    common=dict(deployment=dep,manifest=manifest,keys=str(suite),bb=str(bb),bb_sha256=digest(bb),crs=str(crs))
    lineage=dict(groups=[dict(**common,scratch=str(scratch),cases=cases)])
    deposit=dict(**common,statement=list(statements['deposit_authorization']),
        authorization_proof=str(proofs['deposit_authorization']),other_role_proof=str(proofs['sender_from_origin']))
    for name,value in [('native-lineage.json',lineage),('native-deposit.json',deposit)]:
        (output/name).write_text(json.dumps(value,indent=2)+'\n')
    provenance=dict(synthetic_only=True,deployment_id=identity.hex(),
        qualification_sha256=digest(source/'report.json'),assembly_sha256=digest(suite/'assembly-report.json'),
        files={name:digest(output/name) for name in ['native-lineage.json','native-deposit.json']})
    (output/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    print(json.dumps(dict(directory=str(output),**provenance)))

if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification',default='work/single-proof-qualification')
    parser.add_argument('--suite',default='work/single-proof-suite')
    parser.add_argument('--output',default='work/single-proof-native-fixtures')
    parser.add_argument('--bb',default='work/tools/bb');parser.add_argument('--crs',default='work/crs')
    main(parser.parse_args())
