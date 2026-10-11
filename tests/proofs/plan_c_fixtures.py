"""Deterministic synthetic v9 circuit witnesses; never use these keys for funds.

Independent integer/group implementation for Noir qualification. These fixtures
do not establish live chain backing, signer state-machine correctness or privacy
between separate processes. Every generated recovery signature is checked here.
"""
import hashlib

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def sha(data): return hashlib.sha256(data).digest()
from application_hash import h
def b32(n): return n.to_bytes(32, 'big')
def le(n, size=4): return n.to_bytes(size, 'little')
def add(a, b):
    if a is None: return b
    if b is None: return a
    x,y=a;u,v=b
    if x==u and (y+v)%P==0: return None
    k=((3*x*x)*pow(2*y,-1,P) if a==b else (v-y)*pow(u-x,-1,P))%P
    q=(k*k-x-u)%P
    return q,(k*(x-q)-y)%P
def mul(n, a=G):
    r=None
    while n:
        if n&1:r=add(r,a)
        a=add(a,a);n>>=1
    return r
def point(a):
    assert a is not None
    return b32(a[0])+b32(a[1])
def normal(a):
    assert a is not None
    sign=1 if a[1]%2==0 else -1
    return (a[0],a[1]*sign%P),sign
def secret(label): return int.from_bytes(sha(('synthetic Plan C '+label).encode()),'big')%(N-1)+1
def even_secret(label):
    n=secret(label)
    return n if mul(n)[1]%2==0 else N-n
def salt(label): return sha(('synthetic Plan C salt '+label).encode())
def tagged(tag,data):
    t=sha(tag.encode());return sha(t+t+data)
def key(user,server):
    internal,p=normal(add(mul(user),mul(server)))
    tweak=int.from_bytes(tagged('TapTweak',b32(internal[0])),'big');assert tweak<N
    output,q=normal(add(internal,mul(tweak)))
    return internal,output,tweak,p,q
def sighash(txid,vout,amount,fee,q,payout,delay):
    hashes=sha(txid+le(vout))+sha(le(amount,8))+sha(bytes([34,81,32])+q)+sha(le(delay))
    hashes+=sha(le(amount-fee,8)+bytes([34,81,32])+payout)
    return tagged('TapSighash',b'\0\0'+le(2)+le(0)+hashes+bytes(5))
def blinded(user,server,k,alpha,beta,message):
    _,q,t,p_sign,q_sign=key(user,server)
    nonce,r_sign=normal(add(add(mul(k),mul(alpha)),mul(beta,mul(server))))
    e=int.from_bytes(tagged('BIP0340/challenge',b32(nonce[0])+b32(q[0])+message),'big')%N
    challenge=(beta+r_sign*p_sign*q_sign*e)%N
    partial=(k+challenge*server)%N
    completed=(r_sign*(partial+alpha)+e*q_sign*(p_sign*user+t))%N
    assert mul(partial)==add(mul(k),mul(challenge,mul(server)))
    assert mul(completed)==add(nonce,mul(e,q))
    return b32(challenge),b32(partial),b32(nonce[0])+b32(completed)
def serialize_values(value):
    if isinstance(value,bytes):return list(value)
    if isinstance(value,dict):return {k:serialize_values(v) for k,v in value.items()}
    if isinstance(value,list):return [serialize_values(v) for v in value]
    return value

class Fixtures:
    def __init__(self, config, parity_seed=None, deployment=None):
        self.config=config
        deployment=salt('deployment') if deployment is None else deployment
        assert len(deployment)==32 and deployment!=bytes(32)
        self.domain=le(10)+deployment+salt('coin')
        self.schedule=dict(initial=25,gap=3,margin=1)
        self.policy=h('ZARK/private-handoff/policy/v1',le(10),le(25),le(3),le(1),le(8))
        self.funding_salt=salt('funding');self.deposit_txid=salt('deposit')
        self.deposit_vout=1;self.deposit_amount=1_000_000;self.amount=999_000
        suffix='' if parity_seed is None else ' parity '+str(parity_seed)
        self.u0=secret('user0'+suffix);self.s0=secret('server0'+suffix)
        self.internal,self.output,*_=key(self.u0,self.s0)
        raw=le(2)+b'\1'+self.deposit_txid+le(1)+b'\0'+le(0xffffffff)+b'\1'+le(self.amount,8)+bytes([34,81,32])+b32(self.output[0])+le(0)
        self.txid=sha(sha(raw))
        self.funding=self.funding_commit(self.funding_salt,self.txid,0,self.amount)
    def funding_commit(self,salt_,txid,vout,amount):
        return h('ZARK/private-handoff/funding/v1',self.domain,salt_,txid,le(vout),le(amount,8),b32(self.output[0]),b32(self.internal[0]))
    def owner_cap(self,secret_):
        assert mul(secret_)[1]%2==0
        return h('ZARK/private-handoff/owner-capability/v1',self.domain,b32(mul(secret_)[0]))
    def context(self,label,previous,recipient=None,revision=0):
        operation=salt(label+' op');session=even_secret(label+' session')
        recipient=recipient or salt(label+' recipient')
        return self.domain+previous+operation+recipient+b32(mul(session)[0])+le(revision,8)+bytes(33),point(mul(session))
    @staticmethod
    def intent(context):return context[:164]+context[196:237]
    def recovery(self,label,user,server,capability,delay,context,session_point,refresh,previous_cap,zero_partial=False):
        a,b,k=[secret(label+' '+s) for s in ['alpha','beta','nonce']]
        payout=mul(even_secret(label+' payout'));backup_salt=salt(label+' backup');nonce_salt=salt(label+' nonce salt')
        fee=500
        backup=h('ZARK/private-handoff/recovery/v1',self.domain,self.funding,backup_salt,b32(payout[0]),le(fee,8),le(delay))
        message=sighash(self.txid,0,self.amount,fee,b32(self.output[0]),b32(payout[0]),delay)
        if zero_partial:
            # Choose an even completed nonce, then solve the blinding scalars
            # for c=-k/s. This is a valid zero response, not a mutated witness.
            r=even_secret(label+' zero partial nonce')
            _,q,_,p_sign,q_sign=key(user,server)
            e=int.from_bytes(tagged('BIP0340/challenge',b32(mul(r)[0])+b32(q[0])+message),'big')%N
            c=(-k*pow(server,-1,N))%N
            b=(c-p_sign*q_sign*e)%N
            a=(r-k-b*server)%N
            assert a and b and mul(r)[1]%2==0
        nonce_commit=h('ZARK/private-handoff/nonce/v1',context,self.funding,backup,b32(a),b32(b),nonce_salt)
        challenge,partial,signature=blinded(user,server,k,a,b,message)
        if zero_partial:assert partial==bytes(32)
        cap=self.owner_cap(capability)
        signing=context+self.funding+refresh+previous_cap+cap+backup+nonce_commit+point(mul(server))+point(mul(k))+challenge
        assert len(signing)==589
        binding=h('ZARK/private-handoff/signing/v1',signing)
        server_salt=salt(label+' server')
        server_commit=h('ZARK/private-handoff/server-share/v1',self.domain,point(mul(server)),server_salt)
        issuance=h('ZARK/private-handoff/issuance/v1',binding,partial)
        state=h('ZARK/private-handoff/state/v1',self.domain,self.funding,cap,backup,server_commit,self.policy,issuance)
        return dict(statement=signing,binding_digest=binding,user=b32(user),alpha=b32(a),beta=b32(b),
            funding_salt=self.funding_salt,backup_salt=backup_salt,nonce_salt=nonce_salt,txid=self.txid,
            vout=0,amount=self.amount,fee=fee,destination=point(payout),delay=delay,session_auth_point=session_point,
            partial=partial,signature=signature,capability=b32(capability),server=point(mul(server)),server_salt=server_salt,
            issuance_digest=issuance,state=state,recovery_commit=backup,server_scalar=server,user_scalar=user,
            server_commit=server_commit,cap_commit=cap)
    def certificate(self,r):return self.domain+self.funding+r['state']+self.policy+self.config
    def authorization(self,r):return r['statement']+r['binding_digest']+self.policy+self.config
    def origin(self):
        previous=h('ZARK/private-handoff/origin-predecessor/v1',self.domain)
        ctx,session=self.context('origin',previous)
        refresh=h('ZARK/private-handoff/origin-refresh/v1',ctx,self.funding,point(mul(self.s0)))
        return self.recovery('owner0',self.u0,self.s0,even_secret('owner0 auth'),self.schedule['initial'],ctx,session,refresh,h('ZARK/private-handoff/origin-capability/v1',self.domain))
    def handover(self,old,index,zero_partial=False):
        label='owner'+str(index);op=salt(label+' receive op')
        claim_secret=even_secret(label+' claim');claim_salt=salt(label+' claim salt')
        claim_key=point(mul(claim_secret))
        recipient=h('ZARK/private-handoff/recipient/v1',self.domain,op,claim_key[:32],claim_salt)
        ctx,session=self.context(label+' receive',old['state'],recipient,revision=index)
        assert ctx[100:132]==op
        intent=self.intent(ctx);intent_digest=h('ZARK/private-handoff/intent/v1',intent)
        mask=secret(label+' mask');masked=(old['user_scalar']+mask)%N
        user=secret(label+' user');delta=(masked-user)%N;server=(old['server_scalar']-mask+delta)%N
        assert user and masked and server
        mask_salt=salt(label+' mask salt');masked_salt=salt(label+' masked salt');bridge_salt=salt(label+' bridge')
        delta_salt=salt(label+' delta');token=salt(label+' token')
        cm=h('ZARK/private-handoff/mask/v1',intent_digest,b32(mask),mask_salt)
        cz=h('ZARK/private-handoff/masked-share/v1',intent_digest,b32(masked),masked_salt)
        bridge=h('ZARK/private-handoff/bridge/v1',intent_digest,self.funding,le(old['delay']),self.policy,bridge_salt)
        cd=h('ZARK/private-handoff/delta/v1',ctx,b32(delta),delta_salt)
        auth=even_secret(label+' auth')
        claim=ctx+cm+cz+bridge+cd+self.owner_cap(auth);assert len(claim)==397
        token_cm=h('ZARK/private-handoff/draft-access/v1',intent,token)
        raw=intent+self.funding+cm+cz+bridge+old['cap_commit']+old['server_commit']+self.policy+token_cm
        assert len(raw)==461
        sender={k:old[k] for k in ['server','server_salt','user','capability','funding_salt','txid','vout','amount','destination','fee','delay','backup_salt','issuance_digest']}
        sender['funding_output_key']=b32(self.output[0])
        sender.update(statement=raw+self.config,token=token,mask=b32(mask),mask_salt=mask_salt,masked_share=b32(masked),masked_share_salt=masked_salt,bridge_salt=bridge_salt,previous_statement=self.certificate(old),**self.schedule)
        refresh=h('ZARK/private-handoff/refresh/v1',ctx,cm,cz,bridge,cd,point(mul(server)))
        new=self.recovery(label,user,server,auth,old['delay']-3,ctx,session,refresh,old['cap_commit'],zero_partial=zero_partial)
        receiver={k:new[k] for k in ['user','alpha','beta','nonce_salt','funding_salt','txid','vout','amount','backup_salt','fee','delay','session_auth_point']}
        receiver.update(statement=self.authorization(new),handover=raw+self.config,claim=claim,claim_secret=b32(claim_secret),claim_point=claim_key,claim_salt=claim_salt,next_capability=b32(auth),
            masked_share=b32(masked),masked_share_salt=masked_salt,delta=b32(delta),delta_salt=delta_salt,payout=new['destination'],old_delay=old['delay'],bridge_salt=bridge_salt,**self.schedule)
        return sender,receiver,new
    def bootstrap(self,origin):
        ctx=origin['statement'][:237];parent_salt=salt('parent funding')
        parent_funding=self.funding_commit(parent_salt,self.deposit_txid,self.deposit_vout,self.deposit_amount)
        a,b,k=[secret('bootstrap '+s) for s in ['alpha','beta','nonce']];nonce_salt=salt('bootstrap nonce')
        cap=origin['cap_commit']
        cm=h('ZARK/private-handoff/bootstrap-nonce/v1',ctx,parent_funding,self.funding,cap,b32(a),b32(b),nonce_salt)
        message=sighash(self.deposit_txid,self.deposit_vout,self.deposit_amount,1000,b32(self.output[0]),b32(self.output[0]),0xffffffff)
        challenge,partial,signature=blinded(self.u0,self.s0,k,a,b,message)
        s=ctx+parent_funding+self.funding+cap+point(mul(self.s0))*2+cm+point(mul(k))+challenge
        assert len(s)==589
        return dict(statement=s,binding_digest=h('ZARK/private-handoff/bootstrap-signing/v1',s),parent_user=b32(self.u0),active_user=b32(self.u0),alpha=b32(a),beta=b32(b),
            parent_funding_salt=parent_salt,active_funding_salt=self.funding_salt,nonce_salt=nonce_salt,txid=self.deposit_txid,vout=self.deposit_vout,amount=self.deposit_amount,fee=1000,
            capability=origin['capability'],session_auth_point=origin['session_auth_point'],partial=partial,signature=signature)
    def deposit(self,origin):
        bootstrap=self.bootstrap(origin)
        values={name:origin[name] for name in ['user','alpha','beta','funding_salt','backup_salt','nonce_salt','txid','vout','amount','fee','destination','delay','session_auth_point','capability']}
        values.update(statement=self.authorization(origin)+bootstrap['statement'],
            parent_alpha=bootstrap['alpha'],parent_beta=bootstrap['beta'],parent_funding_salt=bootstrap['parent_funding_salt'],
            parent_nonce_salt=bootstrap['nonce_salt'],parent_txid=bootstrap['txid'],parent_vout=bootstrap['vout'],
            parent_amount=bootstrap['amount'],activation_fee=bootstrap['fee'],**self.schedule)
        assert len(values['statement'])==1466
        return values
    def origin_signature(self,r):
        a=even_secret('origin attestation');k=even_secret('origin attestation nonce')
        pk=mul(a);nonce=mul(k)
        message=h('ZARK/private-handoff/origin/v1',self.certificate(r)[:164])
        e=int.from_bytes(tagged('BIP0340/challenge',b32(nonce[0])+b32(pk[0])+message),'big')%N
        return dict(origin_key_point=point(pk),origin_nonce_point=point(nonce),origin_signature=b32(nonce[0])+b32((k+e*a)%N))
    def origin_predecessor(self,r,prefix):
        return {prefix+'_'+name:value for name,value in dict(
            authorization=self.deposit(r)['statement'],partial=r['partial'],
            activation_partial=self.bootstrap(r)['partial'],server_salt=r['server_salt'],
            **self.origin_signature(r)).items()}
    def exit(self,r,index):
        label='exit'+str(index);op=salt(label+' op')
        recipient=h('ZARK/private-handoff/exit-intent/v1',self.domain,op)
        ctx,session=self.context(label,r['state'],recipient,revision=index+1)
        a,b,k=[secret(label+' '+s) for s in ['alpha','beta','nonce']]
        payout=mul(even_secret(label+' payout'));exit_salt=salt(label+' exit');nonce_salt=salt(label+' nonce salt');fee=500
        ex=h('ZARK/private-handoff/exit/v1',self.domain,self.funding,exit_salt,b32(payout[0]),le(fee,8))
        cm=h('ZARK/private-handoff/exit-nonce/v1',ctx,self.funding,ex,b32(a),b32(b),nonce_salt)
        terminal=h('ZARK/private-handoff/exit-capability/v1',ctx)
        refresh=h('ZARK/private-handoff/exit-share/v1',ctx,self.funding,r['server'])
        message=sighash(self.deposit_txid,self.deposit_vout,self.deposit_amount,fee,b32(self.output[0]),b32(payout[0]),0xffffffff)
        challenge,_,_=blinded(r['user_scalar'],r['server_scalar'],k,a,b,message)
        s=ctx+self.funding+refresh+r['cap_commit']+terminal+ex+cm+r['server']+point(mul(k))+challenge
        return dict(statement=s+h('ZARK/private-handoff/signing/v1',s)+self.policy+self.config,current=self.certificate(r),capability=r['capability'],
            current_recovery=r['recovery_commit'],current_issuance=r['issuance_digest'],server_salt=r['server_salt'],user=r['user'],alpha=b32(a),beta=b32(b),
            funding_salt=self.funding_salt,exit_salt=exit_salt,nonce_salt=nonce_salt,txid=self.txid,vout=0,amount=self.amount,fee=fee,destination=point(payout),
            session_auth_point=session,deposit_txid=self.deposit_txid,deposit_vout=self.deposit_vout,deposit_amount=self.deposit_amount)
