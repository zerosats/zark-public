use bitcoin_relations::{join,part,le32,read_scalar};
use bignum::BigNum;
fn main(
    packed:pub [Field;29], statement:[u8;877],
    handover:[u8;685],handover_vk:[Field;115],handover_proof:[Field;458],
    claim:[u8;397],claim_secret:[u8;32],claim_point:[u8;64],claim_salt:[u8;32],
    session_auth_point:[u8;64],next_capability:[u8;32],alpha:[u8;32],beta:[u8;32],nonce_salt:[u8;32],
    masked_share:[u8;32],masked_share_salt:[u8;32],user:[u8;32],delta:[u8;32],delta_salt:[u8;32],
    funding_salt:[u8;32],txid:[u8;32],vout:u32,amount:u64,
    payout:[u8;64],backup_salt:[u8;32],fee:u64,delay:u32,
    old_delay:u32,bridge_salt:[u8;32],initial:u32,gap:u32,margin:u32,
) {
    packing::bind::<877,29>(statement,packed);
    // recovery::authorize below checks the same signing digest exactly.
    lineage::authorization_metadata(statement);lineage::handover(handover);
    let cfg = part::<877,224>(statement,653);
    assert(cfg == part::<685,224>(handover,461), "handover configuration");
    lineage::verify_sender(handover,handover_vk,handover_proof,cfg);
    let claim_hashes = transfer::claim::claim(claim,claim_secret,claim_point,claim_salt,session_auth_point,
        masked_share,masked_share_salt,user,delta,delta_salt,next_capability);
    let checked_recovery = recovery::authorize(part::<877,589>(statement,0),part::<877,32>(statement,589),
        user,alpha,beta,funding_salt,backup_salt,nonce_salt,txid,vout,amount,fee,payout,delay,session_auth_point);
    let signing = part::<877,589>(statement,0);
    let funding = part::<877,32>(statement,237);let policy = lineage::policy(initial,gap,margin);
    assert(policy == part::<877,32>(statement,621), "authorization policy");
    assert(part::<685,68>(handover,0) == part::<877,68>(statement,0), "handover domain");
    assert(part::<685,32>(handover,205) == funding, "handover funding");
    assert(part::<685,32>(handover,397) == policy, "handover policy");
    let context = part::<589,237>(signing,0);
    assert(context == part::<397,237>(claim,0), "claim/recovery context");
    assert(bitcoin_relations::intent10(context) == part::<685,205>(handover,0), "handover intent");
    let previous_cap = part::<685,32>(handover,333);let next_cap = part::<397,32>(claim,365);
    assert(previous_cap == part::<589,32>(signing,301), "previous capability");
    assert(next_cap == part::<589,32>(signing,333), "next capability");
    assert(previous_cap != next_cap, "capability rotation");
    let cm = part::<685,32>(handover,237);let cz = part::<685,32>(handover,269);
    let bridge = part::<685,32>(handover,301);let cd = part::<397,32>(claim,333);
    assert(cm == part::<397,32>(claim,237), "mask commitment link");
    assert(cz == part::<397,32>(claim,269), "masked share commitment link");
    assert(bridge == part::<397,32>(claim,301), "bridge commitment link");
    let server = part::<589,64>(signing,429);
    let refresh = lineage::digest(join(join(join(join(join(join(
        "ZARK/private-handoff/refresh/v1".as_bytes(),context),cm),cz),bridge),cd),server));
    assert(refresh == part::<589,32>(signing,269), "actual refresh binding");
    lineage::nonzero(masked_share_salt);lineage::nonzero(delta_salt);lineage::nonzero(bridge_salt);
    let z = read_scalar(masked_share);let u = read_scalar(user);let d = read_scalar(delta);
    assert(!z.is_zero());assert(!u.is_zero());assert(z == u+d, "shared recipient scalar");
    // Exact claim/recovery context equality and commitment links above make
    // these the same SHA inputs. Retain comparisons using constrained outputs.
    let intent = claim_hashes.0;
    assert(claim_hashes.1 == cz, "recipient masked share opening");
    assert(claim_hashes.2 == cd, "recipient delta opening");
    lineage::schedule::predecessor(initial,gap,margin,old_delay);
    assert(delay == old_delay-gap, "exact recovery decrement before issuance");
    assert(lineage::digest(join(join(join(join(join("ZARK/private-handoff/bridge/v1".as_bytes(),intent),
        funding),le32(old_delay)),policy),bridge_salt)) == bridge, "authenticated bridge opening");
    // authorize checked the same domain, funding, salt, payout, fee and
    // delay, including their canonical/range/parity/nonzero constraints.
    assert(checked_recovery.recovery_commitment ==
        part::<589,32>(signing,365), "new recovery opening");
}
