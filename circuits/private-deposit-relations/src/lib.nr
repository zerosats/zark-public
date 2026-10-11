//! Exact activation relation inlined by the single deposit authorization.
//! The signer atomically issues both authorized responses; the wallet verifies
//! and saves both complete signatures before it may publish external funding.
use bigcurve::{BigCurve,Secp256k1,Secp256k1Scalar};
use bignum::BigNum;
use std::ops::Neg;
use bitcoin_relations::{add,challenge_scalar,join,le32,le64,normalize,part,read_point,read_scalar,tagged};

fn funding(domain:[u8;68],salt:[u8;32],txid:[u8;32],vout:u32,amount:u64,
           internal:Secp256k1,output:Secp256k1) -> [u8;32] {
    let data = join(join(join(join("ZARK/private-handoff/funding/v1".as_bytes(),domain),salt),txid),le32(vout));
    recovery::application_digest(join(join(join(data,le64(amount)),output.x.to_be_bytes()),internal.x.to_be_bytes()))
}

pub fn authorize(
    statement: [u8;589],binding_digest: [u8;32],
    parent_user:[u8;32],active_user:[u8;32],alpha:[u8;32],beta:[u8;32],
    parent_funding_salt:[u8;32],active_funding_salt:[u8;32],nonce_salt:[u8;32],
    txid:[u8;32],vout:u32,amount:u64,fee:u64,
    capability:[u8;32],session_auth_point:[u8;64],
) -> ([u8;32],recovery::CheckedKeys) {
    assert(part::<589,4>(statement,0) == [10,0,0,0], "bootstrap protocol version");
    for i in 0..6 {
        assert(bitcoin_relations::is_nonzero(part::<589,32>(statement,4+i*32)), "zero bootstrap context");
    }
    let context = part::<589,237>(statement,0);
    bitcoin_relations::context10(context);
    assert(context[204]==0, "bootstrap single scope");
    assert(part::<237,8>(context,196)==[0;8], "bootstrap revision");
    let domain = part::<589,68>(statement,0);
    assert(part::<589,32>(statement,68) == recovery::application_digest(join(
        "ZARK/private-handoff/origin-predecessor/v1".as_bytes(),domain)), "fresh origin predecessor");
    assert(recovery::application_digest(join("ZARK/private-handoff/bootstrap-signing/v1".as_bytes(),statement)) ==
        binding_digest, "bootstrap binding digest");
    let session = read_point(session_auth_point);
    assert(session.x.to_be_bytes() == part::<589,32>(statement,164), "bootstrap session lift");
    assert(session.y.to_be_bytes()[31] & 1 == 0, "bootstrap session parity");
    let parent_f = part::<589,32>(statement,237);
    let active_f = part::<589,32>(statement,269);
    let initial_cap = part::<589,32>(statement,301);
    let nonce_commitment = part::<589,32>(statement,461);
    assert((bitcoin_relations::is_nonzero(parent_f)) & (bitcoin_relations::is_nonzero(active_f)) & (bitcoin_relations::is_nonzero(initial_cap)) & (bitcoin_relations::is_nonzero(nonce_commitment)),
        "zero bootstrap commitment");
    assert(parent_f != active_f, "distinct bootstrap outputs");
    let parent_server_bytes = part::<589,64>(statement,333);
    let active_server_bytes = part::<589,64>(statement,397);
    assert(parent_server_bytes == active_server_bytes, "one deposit and recovery authority");
    assert(parent_user == active_user, "one deposit and recovery owner");
    let parent_nonce = read_point(part::<589,64>(statement,493));
    let submitted = read_scalar(part::<589,32>(statement,557));
    let a = read_scalar(alpha);let b = read_scalar(beta);
    assert(!a.is_zero() & !b.is_zero(), "nonzero bootstrap blinding");
    assert((bitcoin_relations::is_nonzero(parent_funding_salt)) & (bitcoin_relations::is_nonzero(active_funding_salt)) & (bitcoin_relations::is_nonzero(nonce_salt)), "nonzero bootstrap salts");
    assert(parent_funding_salt != active_funding_salt, "distinct bootstrap funding salts");
    assert(bitcoin_relations::is_nonzero(txid), "nonzero parent transaction id");
    assert(bitcoin_relations::is_nonzero(capability), "nonzero initial capability opening");
    assert(bitcoin_relations::owner_capability(domain,capability) ==
        initial_cap, "initial capability opening");
    assert((amount > 0) & (amount <= 2_100_000_000_000_000), "bootstrap amount");
    assert((fee > 0) & (fee <= 10000), "bootstrap fee");
    assert(amount > fee+330, "bootstrap active output dust policy");
    let active_amount = amount-fee;
    // Checked once here and returned so the deposit's recovery authorization
    // can reuse it; recovery::authorize_with_keys rebinds its exact bytes.
    let keys = recovery::derive_keys(parent_server_bytes,parent_user);
    let parent_server = keys.server();
    let (parent_internal,parent_output,parent_negated) = (keys.internal(),keys.output(),keys.negated());
    // The byte equalities above require the same server and user shares for
    // parent and active funding. Reuse their checked key derivation; the
    // outpoints, amounts and salts still bind distinct funding commitments.
    let active_internal = parent_internal;
    let active_output = parent_output;
    assert(funding(domain,parent_funding_salt,txid,vout,amount,parent_internal,parent_output) == parent_f,
        "actual joint parent funding");

    // Fixed 94-byte non-witness activation serialization: version 2, one empty
    // scriptSig input, final sequence, one P2TR output, locktime 0. SHA256d bytes
    // have the same consensus order as native Txid::to_byte_array().
    let input = join(join(join(txid,le32(vout)),[0]),le32(0xffffffff));
    let prefix = join(join(le32(2),[1]),input);
    let txout = join(join(le64(active_amount),[34,81,32]),active_output.x.to_be_bytes());
    let raw = join(join(join(prefix,[1]),txout),le32(0));
    let active_txid = recovery::digest(recovery::digest(raw));
    assert(funding(domain,active_funding_salt,active_txid,0,active_amount,active_internal,active_output) == active_f,
        "exact activation transaction and active funding");
    assert(recovery::application_digest(join(join(join(join(join(join(join(
        "ZARK/private-handoff/bootstrap-nonce/v1".as_bytes(),context),parent_f),active_f),initial_cap),alpha),beta),nonce_salt)) ==
        nonce_commitment, "bootstrap blinding commitment");
    let (nonce,nonce_negated) = normalize(add(add(parent_nonce,
        fixed_generator::mul_generator(a.to_be_bytes())),bigcurve::glv::mul(parent_server,b)));
    let message = recovery::recovery_sighash(txid,vout,amount,fee,
        parent_output.x.to_be_bytes(),active_output.x.to_be_bytes(),0xffffffff);
    let e = challenge_scalar(tagged("BIP0340/challenge".as_bytes(),
        join(join(nonce.x.to_be_bytes(),parent_output.x.to_be_bytes()),message)));
    assert(b + if parent_negated != nonce_negated { e.neg() } else { e } == submitted,
        "blinded exact activation challenge");
    (active_txid,keys)
}
