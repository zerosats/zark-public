#!/usr/bin/env python3
"""Record compiled ACIR recursion calls, expanded BB gates and exact input pins.

Run sequentially during an allocated circuit-work slot. Each command has a
bounded timeout; a timeout is a failed inspection, never a zero gate count.
"""
import argparse,base64,gzip,hashlib,json,os,re,subprocess,time
from pathlib import Path
from plan_c_suite import ROLES
from acir_structure import inspect

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def main(args):
    root=Path(__file__).resolve().parents[2];work=Path(args.work).resolve()
    manifest=json.loads((work/'manifest.json').read_text());qualification=json.loads((work/'report.json').read_text())
    assert qualification['manifest']==manifest
    logs=work/'inspection';logs.mkdir(exist_ok=True)
    # Never invoke nargo against a qualified target: even `info` can rewrite
    # its file_map. Decode the pinned bytecode, then cross-check BB's opcode count.
    previous={row['role']:row for row in json.loads((logs/'partial.json').read_text())} if (logs/'partial.json').exists() else {}
    env=dict(os.environ,HARDWARE_CONCURRENCY='4',BB_HARDWARE_CONCURRENCY='4',RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4')
    crs=root/'work/crs'
    # The global BB -c option applies to gates too. Refuse an absent local CRS
    # instead of silently falling back to BB's default cache/download location.
    assert (crs/'bn254_g1.dat').is_file() and (crs/'bn254_g1_compressed.dat').is_file()
    records=[];commands=[]
    for (role,package,public,expected),pin in zip(ROLES,manifest['roles']):
        original=work/'circuits'/package;artifact=original/'target'/(package.replace('-','_')+'.json')
        assert pin['role']==role and digest(artifact)==pin['compiled_artifact_sha256']
        structure=inspect(artifact);calls=[]
        for function in structure['functions']:
            for recursion in function['recursions']:
                assert recursion['kind']=='RecursiveAggregation'
                payload=recursion['payload'];assert len(payload)==6
                assert payload[5]=={'Constant':bytes(31)+b'\1'}, 'conditional recursive verifier'
                call=dict(vk_fields=len(payload[0]),proof_fields=len(payload[1]),public_fields=len(payload[2]),proof_type=payload[4],predicate=1)
                assert call['vk_fields']==115 and call['proof_fields']==458 and call['proof_type']==6
                calls.append(call)
        assert len(calls)==expected,(role,len(calls),expected)
        cached=previous.get(role,{})
        if cached:assert cached['compiled_artifact_sha256']==pin['compiled_artifact_sha256']
        acir=logs/(role+'-acir.txt');native_hash=None
        if acir.exists() and cached.get('compiled_acir_dump_sha256')==digest(acir):
            text=acir.read_text();native_hash=digest(acir)
            assert text.count('BLACKBOX::RECURSIVE_AGGREGATION ')==len(calls)
            native_count=re.search(r'\|\s*main\s*\|\s*(\d+)\s*\|',text)
            assert native_count and int(native_count[1])==structure['functions'][0]['acir_opcodes']
        command=[str(root/'work/tools/bb'),'-c',str(crs),'gates','-b',str(artifact),'-t','noir-recursive']
        start=time.monotonic();gates=None;gate_error=None
        try:
            if (args.resume or args.acir_only) and cached.get('backend_gates') is not None:
                gates=cached['backend_gates']
            elif args.acir_only:gate_error={'not_run':'acir-only'}
            else:
                result=subprocess.run(command,cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=args.timeout)
                (logs/(role+'-gates.stdout')).write_text(result.stdout);(logs/(role+'-gates.stderr')).write_text(result.stderr)
                if result.returncode==0:gates=json.loads(result.stdout)
                else:gate_error=dict(exit_code=result.returncode,stderr=result.stderr)
        except subprocess.TimeoutExpired as error:
            def decoded(value):return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
            (logs/(role+'-gates.stdout')).write_text(decoded(error.stdout));(logs/(role+'-gates.stderr')).write_text(decoded(error.stderr))
            gate_error=dict(timeout_seconds=args.timeout)
        executed=not (args.acir_only or (args.resume and cached.get('backend_gates') is not None))
        commands.append(dict(role=role,kind='expanded_backend_gates',argv=command,executed=executed,
            elapsed_seconds=time.monotonic()-start if executed else None,error=gate_error))
        if gates is not None:
            assert [f['acir_opcodes'] for f in gates['functions']]==[f['acir_opcodes'] for f in structure['functions']]
        bytecode=base64.b64decode(json.loads(artifact.read_text())['bytecode'])
        proof=work/qualification['positive'][role]
        records.append(dict(role=role,compiled_artifact_sha256=digest(artifact),artifact_bytes=artifact.stat().st_size,
            compressed_acir_bytes=len(bytecode),uncompressed_acir_bytes=len(gzip.decompress(bytecode)),
            public_statement_bytes=public,serialized_public_input_bytes=(proof/'public_inputs').stat().st_size,
            proof_bytes=(proof/'proof').stat().st_size,vk_bytes=(work/(role+'-key/vk')).stat().st_size,
            compiled_recursive_verifiers=calls,compiled_acir_dump_sha256=native_hash,
            acir_functions=[{k:f[k] for k in ['name','acir_opcodes','blackboxes']} for f in structure['functions']],
            backend_gates=gates,backend_gates_error=gate_error))
        print(role,'recursive_verifiers',len(calls),'gates',json.dumps(gates),flush=True)
        (logs/'partial.json').write_text(json.dumps(records,indent=2)+'\n')
    report=dict(manifest_sha256=digest(work/'manifest.json'),qualification_report_sha256=digest(work/'report.json'),
        tools=qualification['toolchain'],dependencies=qualification['dependencies'],
        crs={p.name:dict(bytes=p.stat().st_size,sha256=digest(p)) for p in sorted((root/'work/crs').glob('*.dat'))},
        decoder_sha256=digest(root/'tests/proofs/acir_structure.py'),roles=records,commands=commands,scope='compiled/backend structure, not a performance benchmark')
    (work/'compiled-report.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',default='work/plan-c-proof-qualification');parser.add_argument('--timeout',type=int,default=90)
    parser.add_argument('--acir-only',action='store_true');parser.add_argument('--resume',action='store_true')
    main(parser.parse_args())
