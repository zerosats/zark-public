#!/usr/bin/env python3
"""Fresh offline Plan C proof jobs, three repetitions, precompiled qualified keys.

Run only in an exclusive proof slot. This measures deterministic synthetic
witnesses, not live signer/network/Bitcoin latency. Every repetition freshly
proves one deposit, Ps1, Pr1, Ps2, Pr2 and the final recipient exit.
"""
import argparse,base64,hashlib,json,os,platform,shutil,statistics,subprocess,tomllib
from pathlib import Path
from perf_support import measure,streamed_digest
from plan_c_suite import ROLES
from support import digest,fields,toml
from source_inventory import verify_qualification_sources

JOBS=[('deposit','deposit_authorization'),('sender-1','sender_from_origin'),('receiver-1','receiver_authorization'),
    ('sender-2','sender_from_transfer'),('receiver-2','receiver_authorization'),('exit-2','exit_from_transfer')]

def main(args):
    root=Path(__file__).resolve().parents[2];source=Path(args.qualification).resolve();work=Path(args.work).resolve()
    assert work!=source and work not in source.parents and source not in work.parents, 'benchmark work must be separate from qualified artifacts'
    manifest=json.loads((source/'manifest.json').read_text());qualification=json.loads((source/'report.json').read_text())
    assert qualification['manifest']==manifest and manifest['protocol_version'] in (9,10)
    nargo=root/'work/tools/nargo';bb=root/'work/tools/bb';crs=root/'work/crs'
    assert digest(nargo)==qualification['toolchain']['nargo_sha256'] and digest(bb)==qualification['toolchain']['bb_sha256']
    verify_qualification_sources(qualification,source,root)
    work.mkdir(mode=0o700,parents=True,exist_ok=True)
    logs=work/'logs';logs.mkdir(exist_ok=True)
    env=dict(os.environ,HARDWARE_CONCURRENCY='4',BB_HARDWARE_CONCURRENCY='4',RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4')
    shutil.copytree(source/'circuits',work/'circuits',dirs_exist_ok=True,ignore=shutil.ignore_patterns('target','Prover.toml'))
    verify_qualification_sources(qualification,source,root,copied=work)
    roles={role:(package,pin) for (role,package,_,_),pin in zip(ROLES,manifest['roles'])}
    artifacts={}
    measured_roles=list(dict.fromkeys(role for _,role in JOBS))
    for role in measured_roles:
        package,pin=roles[role];artifact=source/'circuits'/package/'target'/(package.replace('-','_')+'.json')
        assert digest(artifact)==pin['compiled_artifact_sha256']
        for name,field in [('vk','vk_sha256'),('vk.json','metadata_sha256')]:assert digest(source/(role+'-key')/name)==pin[field]
        program=work/'circuits'/package;(program/'target').mkdir(exist_ok=True)
        shutil.copyfile(artifact,program/'target'/artifact.name)
        artifacts[role]=artifact
    # Stream CRS hashing instead of allocating its hundreds of MiB at once.
    hardware=dict(platform=platform.platform(),machine=platform.machine(),logical_cpus=os.cpu_count())
    if platform.system()=='Darwin':
        hardware['memory_bytes']=int(subprocess.check_output(['/usr/sbin/sysctl','-n','hw.memsize'],text=True))
        hardware['cpu']=subprocess.check_output(['/usr/sbin/sysctl','-n','machdep.cpu.brand_string'],text=True).strip()
    setup=dict(qualification_report_sha256=digest(source/'report.json'),manifest_sha256=digest(source/'manifest.json'),
        toolchain=qualification['toolchain'],dependencies=qualification['dependencies'],
        crs={p.name:dict(bytes=p.stat().st_size,sha256=streamed_digest(p)) for p in sorted(crs.glob('*.dat'))},
        hardware=hardware,job_plan=JOBS,repetitions=args.repetitions,threads=4,precompiled=True,preexisting_origin=False,
        rss_sampling_interval_seconds=0.1,wall_definition='sum of execute/prove/verify command wall times, each including sampling-tail overhead',
        compiler_preparation_complete=False,compiler_preparation=[],
        compiler_preparation_scope='compile isolated copies before all measured repetitions; excluded from measured stage totals',
        scope='fresh offline synthetic proof jobs; excludes network, signer and Bitcoin latency')
    (work/'setup.json').write_text(json.dumps(setup,indent=2)+'\n')
    # Refresh compiler metadata/caches in the isolated copies before measuring,
    # as the baseline adapter does in prepare(). Never compile qualified targets.
    # BB continues using the original immutable qualified artifacts and keys.
    for role in measured_roles:
        package,pin=roles[role];program=work/'circuits'/package;artifact=artifacts[role]
        row=measure([nargo,'compile'],program,logs/('setup-'+role+'-compile.log'),env)
        generated=program/'target'/artifact.name
        bytecode=json.loads(artifact.read_text())['bytecode']
        assert json.loads(generated.read_text())['bytecode']==bytecode, 'isolated compiled bytecode changed: '+role
        assert digest(artifact)==pin['compiled_artifact_sha256'], 'qualified artifact changed: '+role
        assert digest(source/(role+'-key/vk'))==pin['vk_sha256']
        row.update(role=role,stage='compile',excluded_from_measurement=True,
            qualified_artifact_sha256=pin['compiled_artifact_sha256'],
            isolated_artifact_sha256=digest(generated),
            compressed_acir_sha256=hashlib.sha256(base64.b64decode(bytecode)).hexdigest(),
            bytecode_equal_to_qualified=True,vk_sha256=pin['vk_sha256'])
        setup['compiler_preparation'].append(row)
        (work/'setup.json').write_text(json.dumps(setup,indent=2)+'\n')
        print('prepared',role,'isolated compiler cache; exact bytecode matched',flush=True)
    setup['compiler_preparation_complete']=True
    (work/'setup.json').write_text(json.dumps(setup,indent=2)+'\n')
    if args.prepare_only:return
    commands=[];jobs=[]
    for repetition in range(1,args.repetitions+1):
        fresh={}
        for fixture,role in JOBS:
            label=f'r{repetition}-{fixture}';out=work/label
            assert not out.exists(),'fresh measurement requires unused job directory: '+str(out)
            out.mkdir()
            values=tomllib.loads((source/'inputs'/(fixture+'.toml')).read_text())
            dependency={'sender-1':('previous_proof','deposit'),'receiver-1':('handover_proof','sender-1'),'sender-2':('previous_proof','receiver-1'),
                'receiver-2':('handover_proof','sender-2'),'exit-2':('current_proof','receiver-2')}.get(fixture)
            if dependency:values[dependency[0]]=fields((fresh[dependency[1]]/'proof').read_bytes())
            inputs=out/'Prover.toml';inputs.write_text(toml(values));inputs.chmod(0o600)
            package,_=roles[role];program=work/'circuits'/package;artifact=artifacts[role];key=source/(role+'-key/vk')
            stages=[('execute',[nargo,'execute',label,'-p',inputs.with_suffix('')],program),
                ('prove',[bb,'prove','-b',artifact,'-w',program/'target'/(label+'.gz'),'-k',key,'-o',out,'-t','noir-recursive','-c',crs],root),
                ('verify',[bb,'verify','-p',out/'proof','-i',out/'public_inputs','-k',key,'-t','noir-recursive','-c',crs],root)]
            rows=[]
            for stage,command,cwd in stages:
                row=measure(command,cwd,logs/(label+'-'+stage+'.log'),env)
                if 'reported_backend_threads' in row:assert row['reported_backend_threads']==4
                row.update(label=label,role=role,stage=stage,repetition=repetition)
                rows.append(row);commands.append(row)
                (work/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
                if stage=='execute':
                    generated=program/'target'/artifact.name
                    assert json.loads(generated.read_text())['bytecode']==json.loads(artifact.read_text())['bytecode']
            assert (out/'proof').stat().st_size==14656
            assert (out/'public_inputs').read_bytes()==(source/fixture/'public_inputs').read_bytes()
            fresh[fixture]=out
            jobs.append(dict(repetition=repetition,fixture=fixture,role=role,fresh_proof=True,external_verified=True,
                total_seconds=sum(r['elapsed_seconds'] for r in rows),
                peak_rss_bytes=max(r['peak_rss_bytes'] for r in rows),
                sampled_process_tree_peak_rss_bytes=max(r['sampled_process_tree_peak_rss_bytes'] for r in rows)))
            print(label,jobs[-1]['total_seconds'],'seconds',flush=True)
    summaries={}
    for name,fixtures in [('deposit',['deposit']),('first_transfer',['sender-1','receiver-1']),('second_transfer',['sender-2','receiver-2']),('final_exit',['exit-2'])]:
        repetitions=[]
        for n in range(1,args.repetitions+1):
            rows=[j for j in jobs if j['repetition']==n and j['fixture'] in fixtures]
            assert len(rows)==len(fixtures)
            repetitions.append(dict(repetition=n,fresh_jobs=len(rows),wall_seconds=sum(r['total_seconds'] for r in rows),
                peak_rss_bytes=max(r['peak_rss_bytes'] for r in rows),sampled_process_tree_peak_rss_bytes=max(r['sampled_process_tree_peak_rss_bytes'] for r in rows)))
        times=[r['wall_seconds'] for r in repetitions]
        summaries[name]=dict(repetitions=repetitions,min_seconds=min(times),median_seconds=statistics.median(times),max_seconds=max(times),mean_seconds=statistics.mean(times))
    report=dict(setup=setup,jobs=jobs,commands=commands,summaries=summaries)
    (work/'report.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification',default='work/plan-c-proof-qualification');parser.add_argument('--work',required=True)
    parser.add_argument('--repetitions',type=int,default=3);parser.add_argument('--prepare-only',action='store_true',help='copy and compile isolated programs, verify bytecode; requires an allocated circuit-work slot')
    main(parser.parse_args())
