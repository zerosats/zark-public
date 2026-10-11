import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Controller } from './controller.mjs';
import { coinTerms, total, validateGroupManifest } from './multi-swap.mjs';
import { readPrivate, writePrivateImmutable } from './storage.mjs';
import { startRelay } from '../relay/server.mjs';
import { RelayClient } from '../relay/client.mjs';

const sha = v => createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(v)).digest('hex');
const address = value => `tzark1${sha(value).replace(/[1bio]/g, 'q').repeat(3).slice(0,164)}`;
const dep = sha('deployment');
const ctx = (coin, op) => `0a000000${dep}${coin}${sha('previous')}${op}${sha('claim')}${sha('session')}0100000000000000${'00'.repeat(33)}`;
function manifest(drafts, expiry) {
  return { id: [...Buffer.from(sha('manifest'), 'hex')], deployment: [...Buffer.from(dep, 'hex')], expires_at: expiry,
    members: drafts.toSorted((a,b) => a.coin.localeCompare(b.coin)).map(d => ({ revision: d.revision,
      ...Object.fromEntries([['coin',36],['previous_state',68],['operation',100],['recipient_claim',132],['sender_session',164]].map(([field,offset]) => [field,[...Buffer.from(d.context.slice(offset*2,offset*2+64),'hex')]])) })) };
}
class Wallet {
  constructor(home, name, coins, shared) { Object.assign(this,{home,name,coins,shared}); this.drafts=[]; this.boxes=new Map(); this.next=0; this.groupCalls=0; }
  async snapshot() { return {coins:this.coins.map(c => ({...c,status:'available',ownerOperation:`owner-${c.id}`}))}; }
  async validateAddress() { return {valid:true,kind:'zark'}; }
  async newAddress() { const invitationPath=path.join(this.home,`invitation-${this.next++}`), a=address(invitationPath); await mkdir(invitationPath,{mode:0o700}); this.boxes.set(invitationPath,a); return {address:a,invitationPath}; }
  async mailCrypto(r) {
    if(r.op==='sign_peer') return {signature:sha([this.boxes.get(r.invitation),r.recipient,r.message])};
    if(r.op==='verify_peer') return {verified:r.signature===sha([r.address,r.recipient,r.message])};
    throw new Error('Unexpected crypto');
  }
  async batchDraft({coin,address}) {
    const saved=this.drafts.find(d=>d.coin===coin); if(saved) return saved;
    const operationPath=path.join(this.home,`draft-${coin}`),transferOperation=sha(operationPath);
    await mkdir(operationPath,{mode:0o700}); const d={coin,operationPath,transferOperation,context:ctx(coin,transferOperation),revision:1,address}; this.drafts.push(d); return d;
  }
  async batchManifestMany({drafts,peer,expiresAt,output}) {
    const own=drafts.map(p=>this.drafts.find(d=>d.operationPath===p)); const peers=JSON.parse(await readPrivate(peer));
    await writePrivateImmutable(output,JSON.stringify(manifest([...own,...peers],expiresAt)));
  }
  async batchSend({operationPath,manifestPath}) {
    this.shared.manifest??=JSON.parse(await readPrivate(manifestPath)); this.shared.joined.add(operationPath);
    const d=this.drafts.find(d=>d.operationPath===operationPath); const offerPath=path.join(this.home,`${d.coin}.offer`);
    await writePrivateImmutable(offerPath,JSON.stringify({coin:d.coin,amount:this.coins.find(c=>c.id===d.coin).amountSat,address:d.address})); return {...d,offerPath};
  }
  async swapGroup({operationPath,planPath}) {
    this.groupCalls++; const p=JSON.parse(await readPrivate(planPath));
    assert.equal(p.incoming.length>0&&p.incoming.length<=5,true);
    assert.equal(new Set(p.incoming.map(c=>c.invitation)).size,p.incoming.length);
    for(const leg of p.incoming) {
      const offer=JSON.parse(await readPrivate(leg.offer));
      assert.equal(offer.coin,leg.coin); assert.equal(offer.amount,leg.amount_sat); assert.equal(offer.address,this.boxes.get(leg.invitation));
    }
    assert.equal(p.incoming.reduce((n,v)=>n+v.amount_sat,0),p.outgoing.reduce((n,v)=>n+v.amount_sat,0));
    // Mock only: native tests establish the actual proof/commit security boundary.
    for(const leg of p.incoming) this.shared.ready.add(leg.coin);
    const complete=this.shared.ready.size===this.shared.manifest.members.length;
    return {operation:operationPath,completed:complete,waiting:!complete,incoming:p.incoming.map(v=>({operation:v.operation,coin:v.coin,accepted:complete,recovery_saved:complete})),outgoing:p.outgoing.map(v=>({operation:v.operation,completed:complete}))};
  }
  async batchAbort() { this.shared.aborted=true; return {aborted:true}; }
  async pendingBatchDrafts() { return this.drafts; }
  async swapAbort() { return this.batchAbort(); }
}
async function setup(t,m,n) {
  const root=await mkdtemp(path.join(os.tmpdir(),'zark-multi-test-')); const relay=await startRelay({stateDir:path.join(root,'relay'),port:0});
  t.after(async()=>{await relay.close();await rm(root,{recursive:true,force:true});});
  const shared={ready:new Set(),joined:new Set()};
  async function wallet(name,count) { const home=path.join(root,name);await mkdir(home,{mode:0o700}); const coins=Array.from({length:count},(_,i)=>({id:sha(`${name}${i}`),amountSat:300000/count}));const w=new Wallet(home,name,coins,shared);const c=new Controller({wallet:w,relay:new RelayClient(relay.url),home});await c.initialize();return c; }
  const a=await wallet('alice',m),b=await wallet('bob',n); return {a,b,shared,root};
}
async function tick(c,{approve=true}={}) {for(const s of c.state.swaps)s.due=0;await c.tick();if(approve)for(const s of c.state.swaps)if(s.phase==='approval')await c.action('swapApprove',{swap:s.id});}
async function start(a,b) {await a.action('swapPublish',{coins:a.wallet.coins.map(c=>c.id)}); const offer=(await b.relay.listOffers())[0];assert.equal(offer.swapVersion,2);await b.action('swapJoin',{coins:b.wallet.coins.map(c=>c.id),offer:offer.id});}

test('poll drains a full mailbox of malformed swap messages and accepts later valid traffic', async t => {
  const {a,b}=await setup(t,1,1); await start(a,b);
  const box=b.state.invitations[0], sender=a.state.invitations[0], s=b.state.swaps[0];
  s.due=Number.MAX_SAFE_INTEGER;
  const bad=[{}, {address:sender.address,signature:'bad',message:{kind:'swap2-terms',payload:{}}}];
  for (const [kind,extra] of [
    ['swap2-terms',{coins:a.wallet.coins,slots:[null]}],
    ['swap2-terms',{coins:a.wallet.coins,slots:[{coin:[s.coins[0].id],address:'bad'}]}],
    ['swap2-terms',{coins:[{id:[a.wallet.coins[0].id],amountSat:300000}],slots:[]}],
    ['swap2-drafts',{agreementId:sha('agreement'),drafts:[null]}],
    ['swap2-manifest',{agreementId:sha('agreement'),manifest:{}}],
    ['swap2-coin',{agreementId:sha('agreement'),coin:sha('coin'),transferOperation:sha('op'),amountSat:1,envelope:'%%%'}],
  ]) {
    const message={kind,payload:{swapId:s.offerId,version:2,...extra}};
    bad.push({address:sender.address,message,signature:sha([sender.address,box.address,message])});
  }
  for(let i=0;i<32;i++) await a.relay.send(box.address,{id:`bad-${i}`,kind:'swap2',payload:bad[i%bad.length]});
  assert.equal((await b.relay.poll(box.mailbox)).length,32);
  await b.poll(); await b.poll();
  assert.deepEqual(await b.relay.poll(box.mailbox),[]);
  assert.equal(b.state.tasks.length,0); assert.equal(s.peerCoins,undefined);
  for(let i=0;i<14;i++){await tick(a);await tick(b);}
  assert.equal(a.state.swaps[0].phase,'complete'); assert.equal(s.phase,'complete');
});

test('poll retains swap messages across native and storage failures, then retries', async t => {
  const {a,b}=await setup(t,1,1); await start(a,b);
  const box=a.state.invitations[0]; a.state.swaps[0].due=Number.MAX_SAFE_INTEGER;
  const crypto=a.wallet.mailCrypto.bind(a.wallet);
  a.wallet.mailCrypto=async()=>{throw new Error('Native process unavailable');};
  await a.poll(); assert.equal((await a.relay.poll(box.mailbox)).length,1);
  a.wallet.mailCrypto=crypto;
  const save=a.save.bind(a); a.save=async()=>{throw new Error('Disk full');};
  await assert.rejects(a.poll(),/Disk full/); assert.equal((await a.relay.poll(box.mailbox)).length,1);
  a.save=save;
  await a.poll(); assert.deepEqual(await a.relay.poll(box.mailbox),[]);
});

test('a valid manifest arriving before local readiness stays queued until ready', async t => {
  const {a,b}=await setup(t,1,1); let delayed;
  const send=a.relay.send.bind(a.relay);
  a.relay.send=async(address,message)=>{
    if(message.payload?.message?.kind==='swap2-manifest'){delayed={address,message};return {};}
    return send(address,message);
  };
  await start(a,b);
  for(let i=0;i<8&&!delayed;i++){await tick(a);await tick(b);}
  assert.ok(delayed);
  const s=b.state.swaps[0], box=b.state.invitations[0];
  s.approved=false; s.due=Number.MAX_SAFE_INTEGER;
  await send(delayed.address,delayed.message);
  await b.poll();
  assert.ok((await b.relay.poll(box.mailbox)).some(m=>m.id===delayed.message.id));
  s.approved=true;
  await b.poll();
  assert.ok(!(await b.relay.poll(box.mailbox)).some(m=>m.id===delayed.message.id));
  for(let i=0;i<10;i++){await tick(a);await tick(b);}
  assert.equal(s.phase,'complete');
});

test('Receive reuses live mailboxes but replaces expired ones, including after restart', async t => {
  const {a}=await setup(t,1,1); const events=[]; a.emit=v=>events.push(v);
  await a.action('receive'); const first=a.state.invitations[0];
  await a.action('receive'); assert.equal(a.state.invitations.length,1);
  first.mailbox.expiresAt=Date.now(); await a.save();
  const restarted=new Controller({wallet:a.wallet,relay:a.relay,home:a.home,emit:v=>events.push(v)});
  await restarted.initialize(); await restarted.action('receive');
  assert.equal(restarted.state.invitations.length,2);
  assert.equal(restarted.state.invitations[0].retired,true);
  const fresh=restarted.state.invitations[1];
  assert.notEqual(fresh.address,first.address);
  assert.ok(fresh.mailbox.expiresAt>Date.now());
  assert.equal(events.findLast(v=>v.receiveKind==='zark').receiveAddress,fresh.address);
  await restarted.action('receive'); assert.equal(restarted.state.invitations.length,2);
});

for(let m=1;m<=5;m++) for(let n=1;n<=5;n++) test(`${m}-for-${n} uses unique invitations and waits for exact native group completion`,async t=>{
  const {a,b,shared}=await setup(t,m,n); await start(a,b);
  for(let i=0;i<14;i++){await tick(a);await tick(b);}
  assert.equal(a.state.swaps[0].phase,'complete',a.state.swaps[0].error);
  assert.equal(b.state.swaps[0].phase,'complete',b.state.swaps[0].error);
  assert.equal(shared.ready.size,m+n);
  assert.equal(a.state.swaps[0].slots.length,n);assert.equal(b.state.swaps[0].slots.length,m);
  assert.notEqual(a.state.invitations[0].address,a.state.swaps[0].slots[0].address);
  const board=(await a.relay.getOffer(a.state.swaps[0].offerId,a.state.swaps[0].token));
  assert.equal(board.amountSat,300000);assert.equal('coins' in board,false);
});

test('multi selection rejects invalid bounds, repeats and unsafe totals',()=>{
  const c={id:sha('coin'),amountSat:10};
  for(const coins of [[],Array(6).fill(c),[c,c],[{...c,amountSat:Number.MAX_SAFE_INTEGER}]]) assert.throws(()=>coinTerms(coins));
  assert.throws(()=>total([{amountSat:Number.MAX_SAFE_INTEGER},{amountSat:1}]));
});
test('approval is explicit and restart preserves private frozen agreement',async t=>{
  const {a,b}=await setup(t,1,3);await start(a,b);
  for(let i=0;i<5;i++){await tick(a,{approve:false});await tick(b,{approve:false});}
  assert.equal(a.state.swaps[0].phase,'approval');assert.equal(a.wallet.drafts.length,0);assert.equal(b.wallet.groupCalls,0);
  const restarted=new Controller({wallet:a.wallet,relay:a.relay,home:a.home});await restarted.initialize();
  for(let i=0;i<14;i++){await tick(restarted);await tick(b);}
  assert.equal(restarted.state.swaps[0].phase,'complete');
});
test('false or partial native completion cannot unlock outgoing coins',async t=>{
  const {a,b}=await setup(t,2,2);await start(a,b);
  a.wallet.swapGroup=async()=>({completed:true,incoming:[],outgoing:[]});
  for(let i=0;i<12;i++){await tick(a);await tick(b);}
  assert.notEqual(a.state.swaps[0].phase,'complete');
  await assert.rejects(a.coin(a.wallet.coins[0].id),/unavailable/);
  const incoming=b.wallet.coins[0];a.wallet.coins.push(incoming);
  await assert.rejects(a.coin(incoming.id),/unavailable/);
});
test('wrong authenticated peer cannot replace negotiation terms',async t=>{
  const {a,b}=await setup(t,1,1);await start(a,b);await tick(a,{approve:false});
  const s=a.state.swaps[0],box=a.state.invitations.find(v=>v.id===s.id),before=JSON.stringify(s.peerCoins);
  await assert.rejects(a.multiSwap.message(box,{payload:{address:s.peerAddress,signature:'bad',message:{kind:'swap2-hello',payload:{swapId:s.offerId,version:2}}}}),/signature/);
  assert.equal(JSON.stringify(s.peerCoins),before);
  const boxB=b.state.invitations[0];
  const inner={kind:'swap2-hello',payload:{swapId:s.offerId,version:2,address:boxB.address,coins:b.wallet.coins}};
  const signed=await b.wallet.mailCrypto({op:'sign_peer',invitation:boxB.invitationPath,recipient:box.address,message:inner});
  for(const alter of [v=>v.payload.coins[0].amountSat++,v=>v.payload.address=address('other'),v=>v.kind='swap2-drafts']){
    const changed=structuredClone(inner);alter(changed);
    await assert.rejects(a.multiSwap.message(box,{payload:{address:boxB.address,signature:signed.signature,message:changed}}),/signature/);
  }
});
test('manifest validation rejects missing extra duplicate and changed members',()=>{
  const ds=Array.from({length:4},(_,i)=>({coin:sha(`coin${i}`),context:ctx(sha(`coin${i}`),sha(`op${i}`)),revision:1}));
  const good=manifest(ds,2000000000);validateGroupManifest(good,ds.slice(0,1),ds.slice(1));
  for(const mutate of [m=>m.members.pop(),m=>m.members.push(m.members[0]),m=>m.members[1]=m.members[0],m=>m.members[0].revision++]){const bad=structuredClone(good);mutate(bad);assert.throws(()=>validateGroupManifest(bad,ds.slice(0,1),ds.slice(1)));}
});

test('missing final offer prevents group readiness and resumes after delayed delivery',async t=>{
  const {a,b}=await setup(t,1,3);const send=b.relay.send.bind(b.relay);let delayed;
  b.relay.send=async(address,message)=>{
    if(message.kind==='swap2' && message.payload.message.kind==='swap2-coin' && message.payload.message.payload.coin===b.wallet.coins[2].id){delayed={address,message};return {};}
    return send(address,message);
  };
  await start(a,b);for(let i=0;i<12;i++){await tick(a);await tick(b);}
  assert.equal(a.wallet.groupCalls,0);assert.notEqual(b.state.swaps[0].phase,'complete');
  assert.ok(delayed);await send(delayed.address,delayed.message);b.relay.send=send;
  for(let i=0;i<5;i++){await tick(a);await tick(b);}
  assert.equal(a.state.swaps[0].phase,'complete');assert.equal(b.state.swaps[0].phase,'complete');
});
test('native amount rejection retains every lock and never completes either side',async t=>{
  const {a,b}=await setup(t,1,3);await start(a,b);
  a.wallet.swapGroup=async()=>{throw new Error('Coin amount does not match');};
  for(let i=0;i<12;i++){await tick(a);await tick(b);}
  assert.notEqual(a.state.swaps[0].phase,'complete');assert.notEqual(b.state.swaps[0].phase,'complete');
  for(const c of b.wallet.coins)await assert.rejects(b.coin(c.id),/unavailable/);
});
test('expiry abort releases all local draft guards only after every abort confirms',async t=>{
  const {a,b}=await setup(t,3,1);await start(a,b);
  for(let i=0;i<4;i++){await tick(a);await tick(b,{approve:false});}
  const s=a.state.swaps[0];assert.equal(s.drafts.length,3);
  s.expiresAt=Math.floor(Date.now()/1000)-1;const paths=[];
  a.wallet.batchAbort=async p=>{paths.push(p);if(paths.length===2)throw new Error('Offline');return {aborted:true};};
  await tick(a);assert.notEqual(s.phase,'cancelled');
  a.wallet.batchAbort=async p=>{paths.push(p);return {aborted:true};};
  await tick(a);assert.equal(s.phase,'cancelled');assert.deepEqual(paths.slice(-3),s.drafts.map(d=>d.operationPath));
});

test('committed group recovers after expiry with messaging unavailable',async t=>{
  const {a,b}=await setup(t,1,3);const group=a.wallet.swapGroup.bind(a.wallet);
  a.wallet.swapGroup=async args=>({...await group(args),completed:false});await start(a,b);
  // Leave A with a native pending group while B commits the shared batch.
  for(let i=0;i<12 && !a.state.swaps[0].groupPlan;i++){await tick(a);await tick(b);}
  const s=a.state.swaps[0];assert.ok(s.groupPlan);assert.equal(s.phase,'recovering');
  a.wallet.swapGroup=group;
  s.expiresAt=Math.floor(Date.now()/1000)-1;
  a.wallet.swapAbort=async()=>{throw new Error('Already committed');};
  a.relay.send=async()=>{throw new Error('Relay offline');};
  a.relay.health=async()=>{throw new Error('Relay offline');};
  await tick(a);assert.equal(s.phase,'complete');
});
