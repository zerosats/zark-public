"""Prove additional fixtures with immutable qualified keys and isolated programs."""
import json,os,shutil
from pathlib import Path
from perf_support import measure
from plan_c_suite import ROLES
from plan_c_fixtures import serialize_values
from support import digest,toml
from packed_inputs import pack_bytes,encode_public
from source_inventory import verify_qualification_sources

class FixtureProver:
    def __init__(self,source,work,roles):
        self.root=Path(__file__).resolve().parents[2];self.source=Path(source).resolve();self.work=Path(work).resolve()
        self.work.mkdir(mode=0o700,parents=True,exist_ok=True);self.logs=self.work/'logs';self.logs.mkdir(exist_ok=True)
        self.manifest=json.loads((self.source/'manifest.json').read_text())
        self.qualification=json.loads((self.source/'report.json').read_text());assert self.qualification['manifest']==self.manifest
        self.env=dict(os.environ,HARDWARE_CONCURRENCY='4',BB_HARDWARE_CONCURRENCY='4',RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4')
        self.nargo=self.root/'work/tools/nargo';self.bb=self.root/'work/tools/bb';self.crs=self.root/'work/crs'
        assert digest(self.nargo)==self.qualification['toolchain']['nargo_sha256']
        assert digest(self.bb)==self.qualification['toolchain']['bb_sha256']
        verify_qualification_sources(self.qualification,self.source,self.root)
        shutil.copytree(self.source/'circuits',self.work/'circuits',dirs_exist_ok=True,ignore=shutil.ignore_patterns('target','Prover.toml'))
        verify_qualification_sources(self.qualification,self.source,self.root,copied=self.work)
        self.artifacts={};self.programs={};self.pins={};self.commands=[];self.cases=[]
        for (role,package,_,_),pin in zip(ROLES,self.manifest['roles']):
            if role not in roles:continue
            artifact=self.source/'circuits'/package/'target'/(package.replace('-','_')+'.json')
            assert digest(artifact)==pin['compiled_artifact_sha256']
            for name,field in [('vk','vk_sha256'),('vk.json','metadata_sha256')]:assert digest(self.source/(role+'-key')/name)==pin[field]
            program=self.work/'circuits'/package;(program/'target').mkdir(exist_ok=True)
            shutil.copyfile(artifact,program/'target'/artifact.name)
            self.artifacts[role]=artifact;self.programs[role]=program;self.pins[role]=pin

    def prove(self,role,label,values):
        artifact=self.artifacts[role];program=self.programs[role]
        abi=json.loads(artifact.read_text())['abi']['parameters'];values=serialize_values(values)
        raw=bytes(int(x) for x in values['statement'])
        if self.manifest['protocol_version']==10:
            values['packed']=pack_bytes(raw,self.pins[role]['public_bytes'])
            public=encode_public(raw,len(raw))
        else: public=b''.join(bytes(31)+bytes([x]) for x in raw)
        values={p['name']:values[p['name']] for p in abi}
        out=self.work/label;assert not out.exists(),'fresh proof directory exists: '+str(out)
        out.mkdir();inputs=out/'Prover.toml';inputs.write_text(toml(values));inputs.chmod(0o600)
        key=self.source/(role+'-key/vk')
        for stage,command,cwd in [
            ('execute',[self.nargo,'execute',label,'-p',inputs.with_suffix('')],program),
            ('prove',[self.bb,'prove','-b',artifact,'-w',program/'target'/(label+'.gz'),'-k',key,'-o',out,'-t','noir-recursive','-c',self.crs],self.root),
            ('verify',[self.bb,'verify','-p',out/'proof','-i',out/'public_inputs','-k',key,'-t','noir-recursive','-c',self.crs],self.root)]:
            row=measure(command,cwd,self.logs/(label+'-'+stage+'.log'),self.env)
            row.update(label=label,role=role,stage=stage);self.commands.append(row)
            (self.work/'commands.json').write_text(json.dumps(self.commands,indent=2)+'\n')
            if stage=='execute':assert json.loads((program/'target'/artifact.name).read_text())['bytecode']==json.loads(artifact.read_text())['bytecode']
        assert (out/'public_inputs').read_bytes()==public and (out/'proof').stat().st_size==14656
        self.cases.append(dict(role=role,label=label,accepted=True,external_verification=True,proof_sha256=digest(out/'proof'),public_inputs_sha256=digest(out/'public_inputs')))
        print(label,'externally verified',flush=True)
        return out

    def report(self,extra):
        value=dict(manifest_sha256=digest(self.source/'manifest.json'),qualification_sha256=digest(self.source/'report.json'),
            toolchain=self.qualification['toolchain'],cases=self.cases,commands=self.commands,**extra)
        (self.work/'report.json').write_text(json.dumps(value,indent=2)+'\n')
