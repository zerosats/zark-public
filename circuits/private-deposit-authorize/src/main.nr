//! Single pre-issuance proof: no recursive proof witnesses or post-signing proof jobs.
use bitcoin_relations::{join,part};
fn main(
    packed:pub [Field;48], statement:[u8;1466],
    user:[u8;32],alpha:[u8;32],beta:[u8;32],
    funding_salt:[u8;32],backup_salt:[u8;32],nonce_salt:[u8;32],
    txid:[u8;32],vout:u32,amount:u64,fee:u64,destination:[u8;64],delay:u32,
    session_auth_point:[u8;64],
    parent_alpha:[u8;32],parent_beta:[u8;32],parent_funding_salt:[u8;32],parent_nonce_salt:[u8;32],
    parent_txid:[u8;32],parent_vout:u32,parent_amount:u64,activation_fee:u64,
    capability:[u8;32],initial:u32,gap:u32,margin:u32,
) {
    packing::bind::<1466,48>(statement,packed);
    let authorization=part::<1466,877>(statement,0);
    let activation=part::<1466,589>(statement,877);
    lineage::authorization(authorization);
    let signing=part::<877,589>(authorization,0);
    let context=part::<589,237>(signing,0);
    assert(context==part::<589,237>(activation,0), "shared deposit context");
    assert(part::<589,32>(signing,237)==part::<589,32>(activation,269), "shared active funding");
    assert(part::<589,32>(signing,333)==part::<589,32>(activation,301), "shared owner capability");
    assert(part::<589,64>(signing,429)==part::<589,64>(activation,397), "shared deposit authority");
    assert(part::<589,64>(signing,493)!=part::<589,64>(activation,493), "independent signer nonces");
    assert(part::<589,32>(signing,397)!=part::<589,32>(activation,461), "independent blind commitments");
    let activation_digest=lineage::digest(join("ZARK/private-handoff/bootstrap-signing/v1".as_bytes(),activation));
    let (active_txid,keys)=bootstrap::authorize(activation,activation_digest,user,user,parent_alpha,parent_beta,
        parent_funding_salt,funding_salt,parent_nonce_salt,parent_txid,parent_vout,parent_amount,activation_fee,
        capability,session_auth_point);
    assert(txid==active_txid, "recovery spends exact activation");
    assert(vout==0, "recovery activation output index");
    assert(amount==parent_amount-activation_fee, "recovery activation amount");
    // Same server share (shared deposit authority above) and same owner bytes:
    // reuse bootstrap's checked BIP341 key derivation instead of repeating it.
    let _=recovery::authorize_with_keys(signing,part::<877,32>(authorization,589),user,alpha,beta,
        funding_salt,backup_salt,nonce_salt,txid,vout,amount,fee,destination,delay,session_auth_point,keys);
    let domain=part::<589,68>(signing,0);
    assert(part::<589,32>(signing,301)==lineage::digest(join(
        "ZARK/private-handoff/origin-capability/v1".as_bytes(),domain)), "origin capability sentinel");
    assert(part::<589,32>(signing,269)==lineage::digest(join(join(join(
        "ZARK/private-handoff/origin-refresh/v1".as_bytes(),context),part::<589,32>(signing,237)),
        part::<589,64>(signing,429))), "origin allocation");
    assert(lineage::policy(initial,gap,margin)==part::<877,32>(authorization,621), "initial recovery policy");
    assert(delay==initial, "initial recovery delay");
}
