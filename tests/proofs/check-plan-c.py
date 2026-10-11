#!/usr/bin/env python3
"""Compile and qualify all six Plan C roles on isolated synthetic fixtures.

This is offline real-ZK qualification, not live signer/Bitcoin flow qualification
or release authentication. Witness-execution rejection is reported separately
from external proof verification. All private synthetic work stays under work/.
"""
import argparse,copy,hashlib,json,os,re,shutil,subprocess,sys,time
from pathlib import Path
from plan_c_suite import ROLES,LIBRARIES
from plan_c_deployment import deployment
from plan_c_fixtures import Fixtures,serialize_values,even_secret,mul,b32,N
from support import digest,fields,toml
from packed_inputs import pack_bytes,encode_public
from source_inventory import circuit_pins,dependency_pins,check_pins,verify_qualification_sources
from plan_c_origin_cases import check_origin_bindings

class Run:
    def __init__(self,args):
        self.args=args;self.root=Path(__file__).resolve().parents[2]
        self.work=Path(args.work).resolve();self.work.mkdir(parents=True,exist_ok=True);self.work.chmod(0o700)
        self.logs=self.work/'logs';self.logs.mkdir(exist_ok=True)
        self.nargo=Path(args.nargo).resolve();self.bb=Path(args.bb).resolve();self.crs=Path(args.crs).resolve()
        self.env=dict(os.environ, HARDWARE_CONCURRENCY='4',BB_HARDWARE_CONCURRENCY='4',RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4')
        self.commands=[];self.cases=[];self.keys={};self.pins=[];self.positive={}
    def run(self,label,argv,cwd=None,allow=False):
        timed=['/usr/bin/time','-l' if sys.platform=='darwin' else '-v']+list(map(str,argv))
        t=time.monotonic();r=subprocess.run(timed,cwd=cwd or self.root,env=self.env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (self.logs/(label+'.log')).write_text(r.stdout)
        self.commands.append(dict(label=label,argv=list(map(str,argv)),exit_code=r.returncode,elapsed_seconds=round(time.monotonic()-t,4)))
        peak=re.search(r'(\d+)\s+maximum resident set size',r.stdout) if sys.platform=='darwin' else re.search(r'Maximum resident set size \(kbytes\): (\d+)',r.stdout)
        if peak:self.commands[-1]['peak_rss_bytes']=int(peak[1])*(1 if sys.platform=='darwin' else 1024)
        (self.work/'commands.json').write_text(json.dumps(self.commands,indent=2)+'\n')
        print(label,r.returncode,self.commands[-1]['elapsed_seconds'],flush=True)
        if r.returncode and not allow:raise RuntimeError(r.stdout[-7000:])
        return r
    def program(self,role):return self.work/'circuits'/next(p for r,p,_,_ in ROLES if r==role)
    def artifact(self,role):return self.program(role)/'target'/(self.program(role).name.replace('-','_')+'.json')
    def abi(self,role):return json.loads(self.artifact(role).read_text())['abi']['parameters']
    def prepare(self):
        (self.work/'report.json').unlink(missing_ok=True)
        expected_sources=circuit_pins(self.root/'circuits',selected=True)
        for package in LIBRARIES+[p for _,p,_,_ in ROLES]:
            dst=self.work/'circuits'/package
            shutil.copytree(self.root/'circuits'/package,dst,dirs_exist_ok=True,ignore=shutil.ignore_patterns('target','Prover.toml'))
        self.sources=circuit_pins(self.work/'circuits')
        check_pins(expected_sources,self.sources,'staged circuit')
        self.dependencies=dependency_pins(self.sources)
        versions=[line for line in self.run('nargo-version',[self.nargo,'--version']).stdout.splitlines() if line.startswith(('nargo version','noirc version','(git version'))]
        assert versions[0]=='nargo version = 1.0.0-beta.25'
        assert self.run('bb-version',[self.bb,'--version']).stdout.splitlines()[0]=='5.2.0'
        self.toolchain=dict(nargo=versions,bb='5.2.0',nargo_sha256=digest(self.nargo),bb_sha256=digest(self.bb),verifier_target='noir-recursive (ZK)',threads=4)
        for role,_,public,recursions in ROLES:
            self.run(role+'-compile',[self.nargo,'compile'],self.program(role))
            abi=self.abi(role)
            assert sum(p['type']['length'] for p in abi if p['visibility']=='public')==(public+30)//31,(role,'public ABI')
            if self.args.compile_only:continue
            out=self.work/(role+'-key');out.mkdir(exist_ok=True)
            artifact_hash=digest(self.artifact(role));stamp=out/'artifact.sha256'
            reuse=self.args.resume and stamp.exists() and stamp.read_text()==artifact_hash and (out/'vk').exists() and (out/'vk.json').exists()
            if not reuse:
                command=[self.bb,'write_vk','-b',self.artifact(role),'-o',out,'-t','noir-recursive','-c',self.crs]
                self.run(role+'-vk-json',command+['--output_format','json'])
                self.run(role+'-vk',command);stamp.write_text(artifact_hash)
            metadata=json.loads((out/'vk.json').read_text());vk=metadata['vk']
            assert len(vk)==115 and int(vk[1],16)==(public+30)//31+8
            assert b''.join(int(x,16).to_bytes(32,'big') for x in vk)==(out/'vk').read_bytes()
            self.keys[role]=metadata
            self.pins.append(dict(role=role,compiled_artifact_sha256=artifact_hash,vk_sha256=digest(out/'vk'),metadata_sha256=digest(out/'vk.json'),recursive_hash=metadata['hash'][2:],public_bytes=public))
        verify_qualification_sources(dict(sources=self.sources,dependencies=self.dependencies),self.work,self.root)
        if not self.args.compile_only:
            (self.work/'manifest.json').write_text(json.dumps(dict(protocol_version=10,noir_version='1.0.0-beta.25',bb_version='5.2.0',verifier_target='noir-recursive',roles=self.pins),indent=2)+'\n')
    def values(self,role,values):
        values=serialize_values(values)
        values['packed']=[str(x) for x in pack_bytes(values['statement'],len(values['statement']))]
        return {p['name']:values[p['name']] for p in self.abi(role)}
    def execute(self,role,label,v,allow=False):
        path=self.work/'inputs'/(label+'.toml');path.parent.mkdir(exist_ok=True);path.write_text(toml(v));path.chmod(0o600)
        return self.run(label+'-execute',[self.nargo,'execute',label,'-p',path.with_suffix('')],self.program(role),allow)
    def verify(self,role,label,allow=False):
        out=self.work/label
        return self.run(label+'-verify',[self.bb,'verify','-p',out/'proof','-i',out/'public_inputs','-k',self.work/(role+'-key/vk'),'-t','noir-recursive','-c',self.crs],allow=allow)
    def prove(self,role,label,allow=False):
        out=self.work/label;out.mkdir(exist_ok=True)
        return self.run(label+'-prove',[self.bb,'prove','-b',self.artifact(role),'-w',self.program(role)/'target'/(label+'.gz'),'-k',self.work/(role+'-key/vk'),'-o',out,'-t','noir-recursive','-c',self.crs],allow=allow)
    def valid(self,role,label,values):
        v=self.values(role,values);public=bytes(v['statement'])
        expected=encode_public(public,len(public));out=self.work/label
        reuse=self.args.resume and (out/'proof').exists() and (out/'public_inputs').exists() and (out/'public_inputs').read_bytes()==expected
        if reuse:reuse=self.verify(role,label,True).returncode==0
        if not reuse:self.execute(role,label,v);self.prove(role,label);self.verify(role,label)
        assert (out/'public_inputs').read_bytes()==expected
        assert (out/'proof').stat().st_size==14656
        self.cases.append(dict(case=label,role=role,accepted=True,external_verification=True,reused=reuse))
        self.positive[role]=label
        return dict(role=role,label=label,values=v,statement=public)
    def recursive(self,entry,prefix):return {prefix+'_vk':self.keys[entry['role']]['vk'],prefix+'_proof':fields((self.work/entry['label']/'proof').read_bytes())}
    def negative(self,role,label,values):
        v=self.values(role,values);r=self.execute(role,label,v,True);stage='witness_execution'
        if not r.returncode:
            r=self.prove(role,label,True);stage='proving'
            if not r.returncode:r=self.verify(role,label,True);stage='external_verification'
        assert r.returncode,label+' unexpectedly accepted'
        assert r.returncode > 0, label+' terminated by a signal rather than rejecting the witness/proof'
        assert not any(x in r.stdout.lower() for x in ['out of memory','bad_alloc','no space left','permission denied','failed to download','terminated by signal']), label+' failed for an environmental reason'
        self.cases.append(dict(case=label,role=role,accepted=False,rejection_stage=stage))
    def main(self):
        self.prepare()
        if self.args.compile_only:return
        cfg=b32(mul(even_secret('origin attestation'))[0])+b''.join(bytes.fromhex(self.keys[r]['hash'][2:]) for r,_,_,_ in ROLES)
        assert len(cfg)==224
        deployment_config,deployment_id=deployment(json.loads((self.work/'manifest.json').read_text()))
        (self.work/'deployment.json').write_text(json.dumps(deployment_config,indent=2)+'\n')
        (self.work/'deployment-id').write_text(deployment_id.hex()+'\n')
        f=Fixtures(cfg,deployment=deployment_id);origin=f.origin()
        deposit=f.deposit(origin)
        previous=self.valid('deposit_authorization','deposit',deposit)
        old=origin;hist=[(origin,previous)];saved=[]
        for index in range(1,8):
            sv,rv,new=f.handover(old,index)
            sv.update(self.recursive(previous,'previous'))
            if index==1:sv.update(f.origin_predecessor(old,'previous'))
            else:sv.update(previous_authorization=f.authorization(old),previous_partial=old['partial'])
            role='sender_from_origin' if index==1 else 'sender_from_transfer'
            sender=self.valid(role,'sender-'+str(index),sv)
            rv.update(self.recursive(sender,'handover'))
            receiver=self.valid('receiver_authorization','receiver-'+str(index),rv)
            saved.append((role,copy.deepcopy(sv),copy.deepcopy(rv),sender))
            old=new;previous=receiver;hist.append((new,receiver))
        for index,(owner,cert) in enumerate(hist):
            ev=f.exit(owner,index);ev.update(self.recursive(cert,'current'))
            role='exit_from_origin' if index==0 else 'exit_from_transfer'
            if index:ev.update(previous_authorization=f.authorization(owner),previous_partial=owner['partial'])
            else:ev.update(f.origin_predecessor(owner,'current'))
            self.valid(role,'exit-'+str(index),ev)
        # A mathematically coherent eighth handover is forbidden by the fixed schedule.
        sv,_,_=f.handover(old,8);sv.update(self.recursive(previous,'previous'));sv.update(previous_authorization=f.authorization(old),previous_partial=old['partial'])
        self.negative('sender_from_transfer','eighth-transfer',sv)
        role,sv,rv,sender=saved[-1]
        mutations=[('wrong-token',role,sv,'token',0),('wrong-previous-partial',role,sv,'previous_partial',31),('wrong-previous-state',role,sv,'previous_statement',100),
            ('wrong-recipient','receiver_authorization',rv,'claim_secret',31),('wrong-delta','receiver_authorization',rv,'delta',31),('wrong-next-owner','receiver_authorization',rv,'next_capability',31),
            ('wrong-deployment','receiver_authorization',rv,'statement',4),('wrong-scope','receiver_authorization',rv,'statement',204),('wrong-refresh','receiver_authorization',rv,'statement',269),('wrong-config','receiver_authorization',rv,'statement',876)]
        for label,role,v,field,offset in mutations:
            v=copy.deepcopy(serialize_values(v));v[field][offset]^=1;self.negative(role,label,v)
        v=copy.deepcopy(rv);v['handover_vk']=self.keys['deposit_authorization']['vk'];self.negative('receiver_authorization','wrong-sender-role',v)
        for label,role,v,field in [('wrong-handover-proof','receiver_authorization',rv,'handover_proof'),
                ('wrong-previous-proof','sender_from_transfer',sv,'previous_proof')]:
            v=copy.deepcopy(v);v[field][250]='0x'+(int(v[field][250],16)^1).to_bytes(32,'big').hex()
            self.negative(role,label,v)
        # The inner primitive accepts opaque refresh bytes, so rebind its digest
        # too: only the fused relation's exact refresh check should reject this.
        from plan_c_fixtures import h
        v=copy.deepcopy(rv);s=bytearray(v['statement']);s[269]^=1;s[589:621]=h('ZARK/private-handoff/signing/v1',bytes(s[:589]));v['statement']=bytes(s)
        self.negative('receiver_authorization','rebound-wrong-refresh',v)
        # A fully consistent Bitcoin recovery at the wrong schedule slot must
        # fail before issuance, even though all recovery hashes are recomputed.
        actual=hist[-1][0]
        bad=f.recovery('owner7',actual['user_scalar'],actual['server_scalar'],int.from_bytes(actual['capability'],'big'),actual['delay']+1,
            actual['statement'][:237],actual['session_auth_point'],actual['statement'][269:301],actual['statement'][301:333])
        v=copy.deepcopy(rv);v['statement']=f.authorization(bad);v['delay']=bad['delay']
        self.negative('receiver_authorization','coherent-wrong-delay',v)
        for label,field in [('wrong-delay','delay'),('wrong-old-delay','old_delay'),('wrong-amount','amount'),('wrong-fee','fee')]:
            v=copy.deepcopy(rv);v[field]+=1;self.negative('receiver_authorization',label,v)
        # Canonical owner key and scalar boundaries cannot alias an existing
        # commitment, including the odd-Y representative of the same x-only key.
        for label,value in [('zero-owner',bytes(32)),('noncanonical-owner',b32(N)),
                ('odd-owner',b32(N-int.from_bytes(rv['next_capability'],'big')))]:
            v=copy.deepcopy(rv);v['next_capability']=value;self.negative('receiver_authorization',label,v)
        for label,value in [('zero-previous-partial',bytes(32)),('noncanonical-previous-partial',b32(N))]:
            v=copy.deepcopy(sv);v['previous_partial']=value;self.negative('sender_from_transfer',label,v)
        for label,field in [('wrong-exit-deposit','deposit_txid'),('wrong-exit-owner','capability'),('wrong-exit-partial','previous_partial')]:
            v=copy.deepcopy(serialize_values(ev));v[field][0]^=1;self.negative('exit_from_transfer',label,v)
        v=copy.deepcopy(ev);v['deposit_amount']+=1;self.negative('exit_from_transfer','wrong-exit-deposit-amount',v)
        for label,field in [('wrong-deposit-owner','capability'),('wrong-deposit-outpoint','parent_txid'),
                ('wrong-deposit-recovery-outpoint','txid'),('wrong-deposit-session','session_auth_point'),
                ('wrong-deposit-parent-blinding','parent_alpha'),('wrong-deposit-recovery-blinding','alpha')]:
            v=serialize_values(deposit);v[field][0]^=1;self.negative('deposit_authorization',label,v)
        for label,field in [('wrong-deposit-amount','parent_amount'),('wrong-deposit-recovery-amount','amount'),
                ('wrong-deposit-activation-fee','activation_fee'),('wrong-deposit-recovery-fee','fee'),
                ('wrong-deposit-delay','delay')]:
            v=copy.deepcopy(deposit);v[field]+=1;self.negative('deposit_authorization',label,v)
        # Exact role hashes are authenticated by the native verifier. A base
        # circuit can enforce their canonical shape, not choose its own trust pin.
        v=serialize_values(deposit);v['statement'][845:877]=[0]*32
        self.negative('deposit_authorization','malformed-deposit-config',v)
        for label,offset in [('wrong-deposit-bootstrap-owner',877+301),
                ('wrong-deposit-bootstrap-context',877+4)]:
            v=serialize_values(deposit);v['statement'][offset]^=1;self.negative('deposit_authorization',label,v)
        for label,target,source,size in [('reused-deposit-signer-nonce',877+493,493,64),
                ('reused-deposit-blind-commitment',877+461,397,32)]:
            v=serialize_values(deposit);v['statement'][target:target+size]=v['statement'][source:source+size]
            self.negative('deposit_authorization',label,v)
        wrong_origin=f.recovery('owner0',origin['user_scalar'],origin['server_scalar'],int.from_bytes(origin['capability'],'big'),origin['delay']-1,
            origin['statement'][:237],origin['session_auth_point'],origin['statement'][269:301],origin['statement'][301:333])
        self.negative('deposit_authorization','coherent-wrong-deposit-delay',f.deposit(wrong_origin))
        origin_sender=saved[0][1]
        check_origin_bindings(self,f,origin,hist[0][1])
        for label,field in [('wrong-origin-recovery-partial','previous_partial'),('wrong-origin-activation-partial','previous_activation_partial'),
                ('wrong-origin-attestation','previous_origin_signature'),('wrong-origin-server-salt','previous_server_salt')]:
            v=serialize_values(origin_sender);v[field][0]^=1;self.negative('sender_from_origin',label,v)
        # Errors that cancel in an unweighted sum of the origin equations must
        # still reach and fail the randomized batch equation itself. The recovery
        # partial is also bound by the issuance commitment (authorized_state), so
        # only the activation partial and attestation scalar isolate the batch.
        def shifted(v,field,delta,start=0):
            scalar=(int.from_bytes(bytes(v[field][start:start+32]),'big')+delta)%N
            v[field][start:start+32]=list(b32(scalar))
        batch_cases=[('cancelling-origin-activation-and-attestation',[('previous_activation_partial',1,0),('previous_origin_signature',-1,32)]),
            ('shifted-origin-activation-partial',[('previous_activation_partial',1,0)]),
            ('wrong-origin-attestation-scalar',[('previous_origin_signature',1,32)])]
        for label,shifts in batch_cases:
            v=serialize_values(copy.deepcopy(origin_sender))
            for field,delta,start in shifts:shifted(v,field,delta,start)
            self.negative('sender_from_origin',label,v)
            assert 'batched origin partials and attestation' in (self.logs/(label+'-execute.log')).read_text(),label+' did not reach the batch equation'
        deposit_cases=[c for c in self.cases if c['accepted'] and c['role']=='deposit_authorization']
        assert len(deposit_cases)==1 and deposit_cases[0]['case']=='deposit'
        assert all(c['role'] in {r for r,_,_,_ in ROLES} for c in self.cases)
        report=dict(toolchain=self.toolchain,sources=self.sources,dependencies=self.dependencies,manifest=json.loads((self.work/'manifest.json').read_text()),deployment=deployment_config,deployment_id=deployment_id.hex(),cases=self.cases,positive=self.positive,commands=self.commands,
            qualification=dict(synthetic_fixture=True,chain_backing_verified=False,live_signer_flow=False,independent_audit=False,fresh_jobs_per_deposit=1,fresh_jobs_per_transfer=2,expected_jobs_two_coin_batch=4))
        verify_qualification_sources(report,self.work,self.root)
        (self.work/'report.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',default='work/plan-c-proof-qualification');p.add_argument('--compile-only',action='store_true');p.add_argument('--resume',action='store_true')
    p.add_argument('--nargo',default='work/tools/nargo');p.add_argument('--bb',default='work/tools/bb');p.add_argument('--crs',default='work/crs')
    Run(p.parse_args()).main()
