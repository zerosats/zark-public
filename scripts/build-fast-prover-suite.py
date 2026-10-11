#!/usr/bin/env python3
"""Rebuild the pinned v10 suite from maintained source into a fresh directory.

Requires explicit pinned nargo, original bb, and authenticated local CRS.
Native artifacts preserve the entire fused constrained ACIR and transplant only
interface-checked Brillig. Exact artifact and verification-key pins are mandatory.
"""
import argparse
import hashlib
import json
import os
import platform
import re
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fast_prover.derive import derive

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT/'runtime/fast-prover/source-lock.json'
# Historical debug paths are serialization strings only, never filesystem inputs.
DEBUG_ROOT = '/zark'
ADDED = {'4934057318759504582': {'error_kind':'string','string':'GLV local hint expects normalized finite points'}}

def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()

def require_pin(path, pin):
    if digest(path) != pin: raise ValueError('asset pin mismatch: '+str(path))

def require_deposit_backend_pin(lock, patch):
    hashes = re.findall(r'^\+    return bb::fr\("0x([0-9a-f]{64})"\);$', patch.read_text(), re.MULTILINE)
    if hashes != [lock['roles']['deposit_authorization']['recursive_hash']]:
        raise ValueError('deposit specialization key pin differs from source lock')

def run(argv, cwd, log):
    env=dict(os.environ)
    for key in ('BB_MSM_NEW','BB_MSM_LEGACY','BB_BENCH','BB_MACOS_USER_INITIATED'): env.pop(key,None)
    for key in ('HARDWARE_CONCURRENCY','BB_HARDWARE_CONCURRENCY','RAYON_NUM_THREADS','OMP_NUM_THREADS'): env[key]='8'
    with log.open('wb') as stream:
        subprocess.run(list(map(str,argv)),cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT,
                       timeout=1200,check=True)

def canonicalize(artifact, stage, debug_root=DEBUG_ROOT):
    value=json.loads(artifact.read_text())
    root=stage.resolve()/'circuits'
    for entry in value['file_map'].values():
        path=Path(entry['path'])
        if path.is_absolute():
            rel=path.relative_to(root)
            if rel.parts[0]=='vendor': entry['path']=debug_root+'/deps/'+str(Path(*rel.parts[1:]))
            else: entry['path']=debug_root+'/circuits/'+str(rel)
    artifact.write_text(json.dumps(value,separators=(',',':')))

def build(args):
    lock=json.loads(LOCK.read_text())
    require_deposit_backend_pin(lock, ROOT/'runtime/fast-prover/barretenberg-deposit-aggregation.patch')
    toolchains=json.loads((ROOT/'runtime/toolchains.json').read_text())
    host={'Darwin-arm64':'darwin-arm64','Linux-x86_64':'linux-x64','Linux-aarch64':'linux-arm64'}.get(platform.system()+'-'+platform.machine())
    if host not in toolchains: raise ValueError('Unsupported build platform')
    require_pin(args.nargo,toolchains[host]['nargo_sha256'])
    require_pin(args.bb,toolchains[host]['verifier_sha256'])
    crs_pins={
        'bn254_g1.dat':'d777711ae9fb1951c47a0eaf7e0ebcaccc39e6731d9b3a560d7ff0c2fcdf2f0d',
        'bn254_g1_compressed.dat':'bf9f1cdbe7b7bb2667c8ee5b887f6ce8b07ec99d60944e17da880ad3717e141b'}
    for name,pin in crs_pins.items(): require_pin(args.crs/name,pin)
    output=args.output.resolve()
    output.mkdir(mode=0o700, exist_ok=args.resume)
    for relative,pin in lock['sources'].items():
        source=ROOT/relative
        require_pin(source,pin['sha256'])
        target=output/'fused'/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists(): require_pin(target,pin['sha256'])
        else: shutil.copyfile(source,target)
    if not (output/'donor').exists(): shutil.copytree(output/'fused',output/'donor')
    # Donors replace only witness-generation bodies with admitted oracles; the
    # derivation below proves the complete constrained Circuit vector unchanged.
    replacements={'glv_msm.nr':'circuits/vendor/noir_bigcurve/src/glv_msm.nr',
                  'glv_batch.nr':'circuits/vendor/noir_bigcurve/src/glv_batch.nr',
                  'batch_hint.nr':'circuits/fixed-generator/src/batch_hint.nr'}
    if set(replacements) != set(lock['donor_sha256']): raise ValueError('donor overlay set differs from source lock')
    for name,target in replacements.items():
        source=ROOT/'runtime/fast-prover/donor'/name
        require_pin(source,lock['donor_sha256'][name])
        shutil.copyfile(source,output/'donor'/target)
    suite=output/'suite'; suite.mkdir(exist_ok=args.resume)
    logs=output/'logs'; logs.mkdir(exist_ok=args.resume)
    roles=[]; programs=[]
    for role,pin in lock['roles'].items():
        package=pin['package']; filename=package.replace('-','_')+'.json'
        program=output/'fused/circuits'/package
        artifact=program/'target'/filename
        dest=suite/role
        if args.resume and all((dest/name).exists() and digest(dest/name)==pin[key]
            for name,key in [('circuit.json','artifact_sha256'),('vk','vk_sha256'),('vk.json','metadata_sha256')]):
            print('Authenticated completed role: '+role,flush=True)
            roles.append(dict(role=role,compiled_artifact_sha256=pin['artifact_sha256'],
                vk_sha256=pin['vk_sha256'],recursive_hash=pin['recursive_hash'],
                metadata_sha256=pin['metadata_sha256'],public_bytes=pin['public_bytes']))
            programs.append(dict(role=role,directory=str(dest),artifact=str(dest/'circuit.json')))
            continue
        print('Compile '+role,flush=True)
        run([args.nargo,'compile','--force'],program,logs/(role+'-compile.log'))
        canonicalize(artifact,output/'fused')
        require_pin(artifact,pin['fused_artifact_sha256'])
        dest.mkdir(exist_ok=args.resume)
        final=dest/'circuit.json'
        if final.exists():
            # Keep failed attempts available, never replace an admitted artifact.
            final.rename(dest/('unadmitted-'+digest(final)+'.json'))
        if pin['native']:
            donor=output/'donor/circuits'/package
            run([args.nargo,'compile','--force'],donor,logs/(role+'-donor.log'))
            # Every native role derives from its own pinned fused artifact.
            evidence=derive(artifact,donor/'target'/filename,final,ADDED)
            (logs/(role+'-derivation.json')).write_text(json.dumps(evidence,indent=2)+'\n')
        else: shutil.copyfile(artifact,final)
        require_pin(final,pin['artifact_sha256'])
        # Recompute both formats using the original verifier, never the tuned prover.
        for fmt in ('binary','json'):
            run([args.bb,'write_vk','-b',final,'-o',dest,'-t','noir-recursive','-c',args.crs,
                 '--output_format',fmt],output,logs/(role+'-vk-'+fmt+'.log'))
        require_pin(dest/'vk',pin['vk_sha256'])
        require_pin(dest/'vk.json',pin['metadata_sha256'])
        roles.append(dict(role=role,compiled_artifact_sha256=pin['artifact_sha256'],
            vk_sha256=pin['vk_sha256'],recursive_hash=pin['recursive_hash'],
            metadata_sha256=pin['metadata_sha256'],public_bytes=pin['public_bytes']))
        programs.append(dict(role=role,directory=str(dest),artifact=str(final)))
        print('Exact artifact and key match: '+role,flush=True)
    manifest=dict(protocol_version=10,noir_version='1.0.0-beta.25',bb_version='5.2.0',
                  verifier_target='noir-recursive',roles=roles)
    (suite/'suite-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (suite/'programs.json').write_text(json.dumps(programs,indent=2)+'\n')

if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('nargo','bb','crs','output'): parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--resume',action='store_true',help='resume only exact authenticated source and completed artifact pins')
    args=parser.parse_args()
    args.nargo=args.nargo.resolve(); args.bb=args.bb.resolve(); args.crs=args.crs.resolve()
    build(args)
