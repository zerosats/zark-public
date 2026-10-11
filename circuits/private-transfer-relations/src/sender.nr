use bigcurve::{BigCurve, Secp256k1, Secp256k1Scalar};
use bignum::BigNum;
use bitcoin_relations::{add, join, le32, le64, normalize, part, read_point, read_scalar};


fn nonzero(bytes: [u8;32]) { assert(bitcoin_relations::is_nonzero(bytes), "zero identifier, salt or commitment"); }

// Only call from a sender role that recursively authenticates the predecessor
// under the pinned deployment's role keys and binds its domain and funding
// commitment to this statement. That predecessor established the TapTweak
// relation; opening the same commitment lets us reuse its output key. This
// helper alone does not establish that a supplied output key is a Taproot key.
pub fn sender_with_authenticated_funding(
    statement: [u8;461], token:[u8;32],
    server: [u8;64], server_salt: [u8;32], user: [u8;32], capability: [u8;32],
    mask: [u8;32], mask_salt: [u8;32], masked_share: [u8;32], masked_share_salt: [u8;32],
    funding_salt: [u8;32], funding_output_key: [u8;32], txid: [u8;32], vout: u32, amount: u64,
    destination: [u8;64], fee: u64, delay: u32, backup_salt: [u8;32],
    issuance_digest: [u8;32], bridge_salt: [u8;32], initial: u32, gap: u32, margin: u32,
) {
    let intent = part::<461,205>(statement,0);
    assert(part::<205,4>(intent,0) == [10,0,0,0], "sender handover protocol version");
    for i in 0..5 { nonzero(part::<205,32>(intent,4+i*32)); }
    for i in 0..7 { nonzero(part::<461,32>(statement,205+i*32)); }
    nonzero(server_salt); nonzero(capability);
    nonzero(mask_salt); nonzero(masked_share_salt); nonzero(funding_salt);
    nonzero(txid); nonzero(backup_salt); nonzero(issuance_digest); nonzero(bridge_salt);
    bitcoin_relations::handover_intent10(intent);
    assert(bitcoin_relations::draft_token_commit(intent,token)==part::<461,32>(statement,429), "draft token commitment");
    let intent_digest = bitcoin_relations::application_digest(join("ZARK/private-handoff/intent/v1".as_bytes(),intent));
    let funding = part::<461,32>(statement,205);
    let previous_capability = part::<461,32>(statement,333);
    let server_commitment = part::<461,32>(statement,365);
    let policy = part::<461,32>(statement,397);

    let s = read_point(server);
    let u = read_scalar(user);
    let m = read_scalar(mask);
    let z = read_scalar(masked_share);
    assert(!u.is_zero(), "zero sender user share");
    assert(!m.is_zero(), "zero mask"); assert(!z.is_zero(), "zero masked share");
    assert(z == u + m, "masked share does not preserve sender share");
    let message = join(join(join("ZARK/private-handoff/mask/v1".as_bytes(),intent_digest),mask),mask_salt);
    assert(bitcoin_relations::application_digest(message) == part::<461,32>(statement,237), "mask commitment");
    let message = join(join(join("ZARK/private-handoff/masked-share/v1".as_bytes(),intent_digest),masked_share),masked_share_salt);
    assert(bitcoin_relations::application_digest(message) == part::<461,32>(statement,269), "masked share commitment");
    assert(bitcoin_relations::owner_capability(part::<205,68>(intent,0),capability) == previous_capability, "current owner auth opening");
    let message = join(join(join("ZARK/private-handoff/server-share/v1".as_bytes(),part::<205,68>(intent,0)),server),server_salt);
    assert(bitcoin_relations::application_digest(message) == server_commitment, "server share opening");

    assert(amount > 0); assert(amount <= 2_100_000_000_000_000, "Bitcoin amount bound");
    assert(fee > 0); assert(fee <= 10_000); assert(amount > fee + 330, "recovery output below policy");
    let (internal, _) = normalize(add(s,fixed_generator::mul_generator(u.to_be_bytes())));
    let message = join(join(join(join("ZARK/private-handoff/funding/v1".as_bytes(),part::<205,68>(intent,0)),funding_salt),txid),le32(vout));
    let message = join(join(join(message,le64(amount)),funding_output_key),internal.x.to_be_bytes());
    assert(bitcoin_relations::application_digest(message) == funding, "funding opening and jointly controlled key");

    lineage::schedule::predecessor(initial,gap,margin,delay);
    assert(lineage::policy(initial,gap,margin) == policy, "recovery policy opening");
    let payout = read_point(destination);
    assert(payout.y.to_be_bytes()[31] & 1 == 0, "old recovery payout parity");
    let message = join(join(join("ZARK/private-handoff/recovery/v1".as_bytes(),part::<205,68>(intent,0)),funding),backup_salt);
    let message = join(join(join(message,payout.x.to_be_bytes()),le64(fee)),le32(delay));
    let recovery = bitcoin_relations::application_digest(message);
    nonzero(recovery);
    let message = join(join(join(join("ZARK/private-handoff/state/v1".as_bytes(),part::<205,68>(intent,0)),funding),previous_capability),recovery);
    let message = join(join(join(message,server_commitment),policy),issuance_digest);
    assert(bitcoin_relations::application_digest(message) == part::<205,32>(intent,68), "claimed predecessor state opening");
    let message = join(join(join(join(join("ZARK/private-handoff/bridge/v1".as_bytes(),intent_digest),funding),le32(delay)),policy),bridge_salt);
    assert(bitcoin_relations::application_digest(message) == part::<461,32>(statement,301), "common predecessor bridge");
    // No signature or history certificate is checked here. Native callers must
    // pin their canonical prior state and later recursively authenticate it.
}
