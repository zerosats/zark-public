//! Application lineage helpers. Live signer entitlement and chain safety are external gates.
pub mod schedule;
use bitcoin_relations::{add,challenge_scalar,join,le32,le64,normalize,part,read_point,read_scalar,tagged};
use bigcurve::{BigCurve,Secp256k1,Secp256k1Scalar};
use bignum::{BigNum,Secp256k1_Fr};

pub fn nonzero(x:[u8;32]) {
    assert(bitcoin_relations::is_nonzero(x), "zero lineage value");
}
pub fn field(bytes:[u8;32]) -> Field {
    nonzero(bytes);
    let mut x = 0 as Field;
    for byte in bytes { x = x*256 + byte as Field; }
    assert(x.to_be_bytes::<32>() == bytes, "noncanonical role hash");
    x
}
pub fn role(config:[u8;224],index:u32) -> [u8;32] { part(config,32+32*index) }
// Check each unordered pair once; role hashes remain canonical and nonzero.
pub fn config(config:[u8;224]) {
    nonzero(part::<224,32>(config,0));
    for i in 0..6 {
        let _ = field(role(config,i));
        for j in 0..6 {
            if i < j { assert(role(config,i) != role(config,j), "duplicate role hash"); }
        }
    }
}
pub fn certificate(s:[u8;388]) {
    assert(part::<388,4>(s,0) == [10,0,0,0], "lineage version");
    for i in 0..5 { nonzero(part::<388,32>(s,4+32*i)); }
    config(part(s,164));
}
pub fn handover(s:[u8;685]) {
    assert(part::<685,4>(s,0) == [10,0,0,0], "handover lineage version");
    bitcoin_relations::handover_intent10(part::<685,205>(s,0));
    for i in 0..8 { nonzero(part::<685,32>(s,205+32*i)); }
    config(part(s,461));
}
// Metadata only: callers must separately constrain the signing digest.
pub fn authorization_metadata(s:[u8;877]) {
    assert(part::<877,4>(s,0) == [10,0,0,0], "issuance authorization version");
    config(part(s,653));nonzero(part::<877,32>(s,621));
}
pub fn authorization(s:[u8;877]) {
    authorization_metadata(s);
    assert(digest(join("ZARK/private-handoff/signing/v1".as_bytes(),part::<877,589>(s,0))) ==
        part::<877,32>(s,589), "issuance signing digest");
}
pub fn verify<let N:u32,let K:u32>(vk:[Field;115],proof:[Field;458],bytes:[u8;N],allowed:[u8;32]) {
    let approved = field(allowed);
    let inputs = packing::pack::<N,K>(bytes);
    common::verify_zk(vk,proof,inputs,approved,approved);
}
pub fn digest<let N:u32>(bytes:[u8;N]) -> [u8;32] { recovery::application_digest(bytes) }
pub fn policy(initial:u32,gap:u32,margin:u32) -> [u8;32] {
    schedule::validate(initial,gap,margin);
    digest(join(join(join(join(join("ZARK/private-handoff/policy/v1".as_bytes(),[10,0,0,0]),
        le32(initial)),le32(gap)),le32(margin)),le32(schedule::OWNER_LIMIT)))
}
pub fn recovery_commit(deployment:[u8;32],coin:[u8;32],funding:[u8;32],
                       payout:[u8;64],fee:u64,delay:u32,salt:[u8;32]) -> [u8;32] {
    nonzero(salt);
    assert(fee > 0 & fee <= 10000, "recovery fee");
    assert(delay > 0 & delay <= 65535, "recovery delay");
    let p = read_point(payout);
    assert(p.y.to_be_bytes()[31] & 1 == 0, "recovery payout parity");
    digest(join(join(join(join(join(join(join(join("ZARK/private-handoff/recovery/v1".as_bytes(),
        [10,0,0,0]),deployment),coin),funding),salt),p.x.to_be_bytes()),le64(fee)),le32(delay)))
}
pub fn server_commit(deployment:[u8;32],coin:[u8;32],server:[u8;64],salt:[u8;32]) -> [u8;32] {
    nonzero(salt);
    let _ = read_point(server);
    digest(join(join(join(join(join("ZARK/private-handoff/server-share/v1".as_bytes(),
        [10,0,0,0]),deployment),coin),server),salt))
}
pub fn state_commit(deployment:[u8;32],coin:[u8;32],funding:[u8;32],capability:[u8;32],
                    backup:[u8;32],server:[u8;32],policy:[u8;32],issuance:[u8;32]) -> [u8;32] {
    nonzero(deployment);nonzero(coin);nonzero(funding);nonzero(capability);
    nonzero(backup);nonzero(server);nonzero(policy);nonzero(issuance);
    digest(join(join(join(join(join(join(join(join(join("ZARK/private-handoff/state/v1".as_bytes(),
        [10,0,0,0]),deployment),coin),funding),capability),backup),server),policy),issuance))
}
pub fn funding_commit(deployment:[u8;32],coin:[u8;32],server:[u8;64],user:[u8;32],
                      salt:[u8;32],txid:[u8;32],vout:u32,amount:u64) -> [u8;32] {
    nonzero(salt);nonzero(txid);
    assert(amount > 0 & amount <= 2_100_000_000_000_000, "funding amount");
    let u = read_scalar(user); assert(!u.is_zero());
    let s = read_point(server);
    let (internal,_) = normalize(add(s,fixed_generator::mul_generator(u.to_be_bytes())));
    let tweak = read_scalar(tagged("TapTweak".as_bytes(),internal.x.to_be_bytes()));
    let (output,_) = normalize(add(internal,fixed_generator::mul_generator(tweak.to_be_bytes())));
    digest(join(join(join(join(join(join(join(join(join("ZARK/private-handoff/funding/v1".as_bytes(),
        [10,0,0,0]),deployment),coin),salt),txid),le32(vout)),le64(amount)),output.x.to_be_bytes()),internal.x.to_be_bytes()))
}
// BIP340 lifts, parities and challenge for the origin attestation. Its group
// equation sG = R + eP is checked by the batch in verify_origin_predecessor.
fn origin_attestation(key:[u8;32],key_point:[u8;64],nonce_point:[u8;64],signature:[u8;64],message:[u8;32])
    -> (Secp256k1,Secp256k1,Secp256k1_Fr,[u8;32]) {
    let p = read_point(key_point); let r = read_point(nonce_point);
    assert(p.x.to_be_bytes() == key, "origin key lift");
    assert(p.y.to_be_bytes()[31] & 1 == 0, "origin key parity");
    assert(r.x.to_be_bytes() == part::<64,32>(signature,0), "origin nonce lift");
    assert(r.y.to_be_bytes()[31] & 1 == 0, "origin nonce parity");
    let challenge = tagged("BIP0340/challenge".as_bytes(),join(join(r.x.to_be_bytes(),key),message));
    (p,r,challenge_scalar(challenge),challenge)
}

// Big-endian 128-bit batch weight from one half of an application digest.
fn weight(bytes:[u8;32],offset:u32) -> Field {
    let mut x = 0 as Field;
    for i in 0..16 { x = x*256 + bytes[offset+i] as Field; }
    x
}

// Connects an authorized pre-issuance statement to its exact completed state.
// This does not itself verify the authorization or completed-state proof roles.
pub fn authorized_state(certificate:[u8;388],authorization:[u8;877],partial:[u8;32],server_salt:[u8;32]) {
    assert(part::<388,68>(certificate,0) == part::<877,68>(authorization,0), "issued domain");
    assert(part::<388,32>(certificate,68) == part::<877,32>(authorization,237), "issued funding");
    assert(part::<388,32>(certificate,132) == part::<877,32>(authorization,621), "issued policy");
    assert(part::<388,224>(certificate,164) == part::<877,224>(authorization,653), "issued configuration");
    let deployment = part::<388,32>(certificate,4);let coin = part::<388,32>(certificate,36);
    let server = server_commit(deployment,coin,part::<877,64>(authorization,429),server_salt);
    let signing_digest = part::<877,32>(authorization,589);nonzero(signing_digest);let _ = read_scalar(partial);
    let issuance = digest(join(join("ZARK/private-handoff/issuance/v1".as_bytes(),signing_digest),partial));
    assert(state_commit(deployment,coin,part::<388,32>(certificate,68),part::<877,32>(authorization,333),
        part::<877,32>(authorization,365),server,part::<388,32>(certificate,132),issuance) ==
        part::<388,32>(certificate,100), "exact authorized state and issuance");
}


pub fn verify_origin_predecessor(current:[u8;388],auth:[u8;1466],vk:[Field;115],proof:[Field;458],
    partial:[u8;32],activation_partial:[u8;32],salt:[u8;32],origin_key_point:[u8;64],
    origin_nonce_point:[u8;64],origin_signature:[u8;64],cfg:[u8;224]) {
    certificate(current);
    assert(part::<388,224>(current,164) == cfg, "origin predecessor configuration");
    verify::<1466,48>(vk,proof,auth,role(cfg,0));
    let recovery_auth=part::<1466,877>(auth,0);
    // The pinned deposit-authorization proof above already constrains
    // authorization(recovery_auth) for these exact packed bytes. Keep the
    // post-issuance batch, authorized_state and the origin signature: none is
    // established by the pre-issuance deposit proof.
    let bootstrap=part::<1466,589>(auth,877);
    // The recursively verified deposit binds both issued partials to one server
    // share; restate the byte equality so one decoded point serves both.
    let server_bytes=part::<877,64>(recovery_auth,429);
    assert(server_bytes == part::<589,64>(bootstrap,333), "one origin authority");
    let recovery_nonce=part::<877,64>(recovery_auth,493);let recovery_challenge=part::<877,32>(recovery_auth,557);
    let activation_nonce=part::<589,64>(bootstrap,493);let activation_challenge=part::<589,32>(bootstrap,557);
    authorized_state(current,recovery_auth,partial,salt);
    let message=digest(join("ZARK/private-handoff/origin/v1".as_bytes(),part::<388,164>(current,0)));
    let (origin_key,origin_nonce,e,challenge)=origin_attestation(part::<224,32>(cfg,0),origin_key_point,
        origin_nonce_point,origin_signature,message);
    // Randomized batch of three Schnorr-type equations, each D_i = 0:
    //   D1 = z1 G - R1 - c1 X   (issued recovery partial)
    //   D2 = z2 G - R2 - c2 X   (issued activation partial)
    //   D3 = s G - R - e P      (origin attestation)
    // checked as D1 + w2 D2 + w3 D3 = 0 with 128-bit weights hashed from every
    // encoding the D_i depend on. If any D_i != 0, at most 2^128 of the 2^256
    // weight pairs satisfy the sum in the prime-order group, so each hash query
    // succeeds with probability at most 2^-128. This deliberately trades the
    // three exact equations for computational soundness; the weights must keep
    // covering every point and scalar encoding below.
    let weights=digest(join(join(join(join(join(join(join(join(join(join(join(
        "ZARK/private-handoff/origin-batch/v1".as_bytes(),server_bytes),recovery_nonce),recovery_challenge),partial),
        activation_nonce),activation_challenge),activation_partial),origin_key_point),origin_nonce_point),
        origin_signature),challenge));
    let w2=weight(weights,0);let w3=weight(weights,16);
    let fw2=Secp256k1_Fr::from(w2);let fw3=Secp256k1_Fr::from(w3);
    let z1=read_scalar(partial);let z2=read_scalar(activation_partial);
    let s=read_scalar(part::<64,32>(origin_signature,32));
    let c1=read_scalar(recovery_challenge);let c2=read_scalar(activation_challenge);
    let lhs=fixed_generator::mul_generator((z1+fw2*z2+fw3*s).to_be_bytes());
    let rhs=add(read_point(recovery_nonce),bigcurve::glv_batch::msm([read_point(server_bytes),origin_key],
        [c1+fw2*c2,fw3*e],[read_point(activation_nonce),origin_nonce],[w2,w3]));
    assert(lhs == rhs, "batched origin partials and attestation");
}

pub fn verify_transfer_predecessor(current:[u8;388],auth:[u8;877],vk:[Field;115],proof:[Field;458],partial:[u8;32],salt:[u8;32],cfg:[u8;224]) {
    certificate(current);
    // The pinned receiver-authorization proof below already constrains
    // authorization(auth), including the signing digest, for these exact bytes.
    // Do not omit recursive verification, actual partial verification, or the
    // authorized_state relation: the partial was issued AFTER that prior proof.
    assert(part::<388,224>(current,164) == cfg, "predecessor configuration");
    verify::<877,29>(vk,proof,auth,role(cfg,3));
    recovery::verify_partial(read_point(part::<877,64>(auth,429)),
        read_point(part::<877,64>(auth,493)),read_scalar(part::<877,32>(auth,557)),partial);
    authorized_state(current,auth,partial,salt);
}

pub fn verify_sender(statement:[u8;685],vk:[Field;115],proof:[Field;458],cfg:[u8;224]) {
    handover(statement);
    assert(part::<685,224>(statement,461) == cfg, "sender configuration");
    let actual=common::hash(vk);
    assert((actual==field(role(cfg,1))) | (actual==field(role(cfg,2))), "sender role");
    let inputs=packing::pack::<685,23>(statement);
    std::verify_proof_with_type(vk,proof,inputs,actual,6);
}

mod validation_tests;
