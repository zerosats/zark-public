//! Whole-coin terminal exit authorization. Live current entitlement, durable
//! terminal issuance and live chain checks remain host duties. A direct exit
//! spends the deposit; the exact unpublished activation is reconstructed here.
use bigcurve::{BigCurve,Secp256k1,Secp256k1Scalar};
use bignum::BigNum;
use std::ops::Neg;
use bitcoin_relations::{add,challenge_scalar,join,le32,le64,normalize,part,read_point,read_scalar,tagged};

pub fn exit(
    statement: [u8;877],
    current:[u8;388],
    capability:[u8;32],current_recovery:[u8;32],current_issuance:[u8;32],server_salt:[u8;32],
    user:[u8;32],alpha:[u8;32],beta:[u8;32],
    funding_salt:[u8;32],exit_salt:[u8;32],nonce_salt:[u8;32],
    txid:[u8;32],vout:u32,amount:u64,fee:u64,destination:[u8;64],session_auth_point:[u8;64],
    deposit_txid:[u8;32],deposit_vout:u32,deposit_amount:u64,
) {
    lineage::authorization(statement);lineage::certificate(current);
    let cfg = part::<877,224>(statement,653);
    assert(cfg == part::<388,224>(current,164), "exit lineage configuration");
    assert(part::<877,68>(statement,0) == part::<388,68>(current,0), "exit lineage domain");
    assert(part::<877,32>(statement,68) == part::<388,32>(current,100), "exact current state");
    assert(part::<877,32>(statement,237) == part::<388,32>(current,68), "exit lineage funding");
    assert(part::<877,32>(statement,621) == part::<388,32>(current,132), "exit lineage policy");
    let signing = part::<877,589>(statement,0);
    for i in 0..6 {
        lineage::nonzero(part::<589,32>(signing,4+i*32));
        lineage::nonzero(part::<589,32>(signing,237+i*32));
    }
    let context = part::<589,237>(signing,0);
    bitcoin_relations::context10(context);
    assert(context[204]==0, "exit single scope");
    assert(part::<237,8>(context,196)!=[0;8], "exit starting revision");
    let domain = part::<589,68>(signing,0);
    let deployment = part::<589,32>(signing,4);let coin = part::<589,32>(signing,36);
    let funding = part::<589,32>(signing,237);let exit = part::<589,32>(signing,365);
    let server_bytes = part::<589,64>(signing,429);
    assert(part::<589,32>(signing,132) == lineage::digest(join(join(
        "ZARK/private-handoff/exit-intent/v1".as_bytes(),domain),part::<589,32>(signing,100))), "exit intent domain");
    assert(part::<589,32>(signing,333) == lineage::digest(join(
        "ZARK/private-handoff/exit-capability/v1".as_bytes(),context)), "terminal capability");
    assert(part::<589,32>(signing,269) == lineage::digest(join(join(join(
        "ZARK/private-handoff/exit-share/v1".as_bytes(),context),funding),server_bytes)), "current exit share binding");
    lineage::nonzero(capability);
    let current_cap = bitcoin_relations::owner_capability(domain,capability);
    assert(current_cap == part::<589,32>(signing,301), "current capability opening");
    assert(current_cap != part::<589,32>(signing,333), "terminal capability transition");
    let server_commit = lineage::server_commit(deployment,coin,server_bytes,server_salt);
    assert(lineage::state_commit(deployment,coin,funding,current_cap,current_recovery,server_commit,
        part::<877,32>(statement,621),current_issuance) == part::<589,32>(signing,68), "current state opening");

    let session = read_point(session_auth_point);
    assert(session.x.to_be_bytes() == part::<589,32>(signing,164), "exit session lift");
    assert(session.y.to_be_bytes()[31] & 1 == 0, "exit session parity");
    let server = read_point(server_bytes);let server_nonce = read_point(part::<589,64>(signing,493));
    let submitted = read_scalar(part::<589,32>(signing,557));
    let u = read_scalar(user);let a = read_scalar(alpha);let b = read_scalar(beta);
    assert(!u.is_zero());assert(!a.is_zero());assert(!b.is_zero());
    lineage::nonzero(funding_salt);lineage::nonzero(exit_salt);lineage::nonzero(nonce_salt);lineage::nonzero(txid);
    assert(amount > 0 & amount <= 2_100_000_000_000_000, "exit funding amount");
    assert(fee > 0 & fee <= 10000, "exit fee");assert(amount > fee+330, "exit dust policy");
    let (internal,internal_negated) = normalize(add(server,fixed_generator::mul_generator(u.to_be_bytes())));
    let tweak = read_scalar(tagged("TapTweak".as_bytes(),internal.x.to_be_bytes()));
    let (output,output_negated) = normalize(add(internal,fixed_generator::mul_generator(tweak.to_be_bytes())));
    let q = output.x.to_be_bytes();
    let payout = read_point(destination);assert(payout.y.to_be_bytes()[31] & 1 == 0, "exit payout parity");
    let data = join(join(join(join("ZARK/private-handoff/funding/v1".as_bytes(),domain),funding_salt),txid),le32(vout));
    assert(lineage::digest(join(join(join(data,le64(amount)),q),internal.x.to_be_bytes())) == funding,
        "current jointly controlled funding opening");
    // Ownership of the recovery output also controls the deposit because
    // bootstrap fixes BOTH outputs to this same joint key. Reconstruct the
    // exact activation txid authenticated by the current lineage. This binds
    // the direct spend to the original deposit rather than a caller-selected
    // unrelated outpoint. Bitcoin verifies the actual deposit amount/script.
    lineage::nonzero(deposit_txid);
    assert(vout == 0, "activation output index");
    assert(deposit_amount <= 2_100_000_000_000_000, "deposit amount bound");
    assert(deposit_amount > amount, "positive activation fee");
    assert(deposit_amount-amount <= 10000, "activation fee bound");
    let activation_input = join(join(join(deposit_txid,le32(deposit_vout)),[0]),le32(0xffffffff));
    let activation_prefix = join(join(le32(2),[1]),activation_input);
    let activation_output = join(join(le64(amount),[34,81,32]),q);
    let activation_raw = join(join(join(activation_prefix,[1]),activation_output),le32(0));
    assert(recovery::digest(recovery::digest(activation_raw)) == txid,
        "direct exit must spend the exact deposit behind this coin");
    let data = join(join(join("ZARK/private-handoff/exit/v1".as_bytes(),domain),funding),exit_salt);
    assert(lineage::digest(join(join(data,payout.x.to_be_bytes()),le64(fee))) == exit, "exact exit destination and fee");
    assert(lineage::digest(join(join(join(join(join(join(
        "ZARK/private-handoff/exit-nonce/v1".as_bytes(),context),funding),exit),alpha),beta),nonce_salt)) ==
        part::<589,32>(signing,397), "exit blinding commitment");
    let (nonce,nonce_negated) = normalize(add(add(server_nonce,fixed_generator::mul_generator(a.to_be_bytes())),
        bigcurve::glv::mul(server,b)));
    // Same BIP341 one-input/one-output SIGHASH_DEFAULT construction as recovery,
    // with a literal final sequence and nLockTime=0. No relative delay is signed.
    let message = recovery::recovery_sighash(deposit_txid,deposit_vout,deposit_amount,fee,q,payout.x.to_be_bytes(),0xffffffff);
    let e = challenge_scalar(tagged("BIP0340/challenge".as_bytes(),join(join(nonce.x.to_be_bytes(),q),message)));
    let negate_e = internal_negated != output_negated != nonce_negated;
    assert(b + if negate_e { e.neg() } else { e } == submitted, "blinded immediate Bitcoin exit challenge");
}
