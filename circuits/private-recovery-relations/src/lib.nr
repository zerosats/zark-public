//! Isolated v9 recovery signing relation; NOT ownership or history verification.
//! Refresh/capability/previous-state fields are digest-bound opaque values.
use bigcurve::{BigCurve, Secp256k1, Secp256k1Scalar};
use bignum::BigNum;
use std::ops::Neg;
use bitcoin_relations::{Authorization, add, challenge_scalar, join, le32, le64, normalize, part, read_point, read_scalar, tagged};
mod sha_fixed;

pub fn digest<let N: u32>(bytes: [u8;N]) -> [u8;32] { sha_fixed::digest(bytes) }

// Keep digest() SHA for BIP341 components and activation transaction IDs.
pub fn application_digest<let N:u32>(bytes:[u8;N]) -> [u8;32] { bitcoin_relations::application_digest(bytes) }

// Same canonical native P2TR one-input/one-output BIP341 SIGHASH_DEFAULT
// transaction with block-only nSequence and nLockTime=0.
pub fn recovery_sighash(txid: [u8;32], vout: u32, amount: u64, fee: u64,
                       key: [u8;32], payout: [u8;32], delay: u32) -> [u8;32] {
    let prevouts = digest(join(txid, le32(vout)));
    let amounts = digest(le64(amount));
    let scripts = digest(join([34,81,32], key));
    let sequences = digest(le32(delay));
    let outputs = digest(join(join(le64(amount-fee), [34,81,32]), payout));
    let header = join(join([0,0], le32(2)), le32(0));
    let hashes = join(join(join(join(prevouts, amounts), scripts), sequences), outputs);
    tagged("TapSighash".as_bytes(), join(join(header, hashes), [0,0,0,0,0]))
}

/// Checked BIP341 keys for one exact server-share encoding and owner scalar
/// encoding. The fields are private: only derive_keys constructs a value, so a
/// caller cannot declare an arbitrary witness point checked.
pub struct CheckedKeys {
    server_bytes: [u8;64],
    user_bytes: [u8;32],
    server: Secp256k1,
    internal: Secp256k1,
    output: Secp256k1,
    internal_negated: bool,
    output_negated: bool,
}

impl CheckedKeys {
    pub fn server(self) -> Secp256k1 { self.server }
    pub fn internal(self) -> Secp256k1 { self.internal }
    pub fn output(self) -> Secp256k1 { self.output }
    /// Exactly one of the internal and output keys was negated to even y.
    pub fn negated(self) -> bool { self.internal_negated != self.output_negated }
}

pub fn derive_keys(server_bytes: [u8;64], user_bytes: [u8;32]) -> CheckedKeys {
    let server = read_point(server_bytes);
    let u = read_scalar(user_bytes);
    assert(!u.is_zero(), "nonzero user share");
    let (internal, internal_negated) = normalize(add(server, fixed_generator::mul_generator(u.to_be_bytes())));
    let tweak = read_scalar(tagged("TapTweak".as_bytes(), internal.x.to_be_bytes()));
    let (output, output_negated) = normalize(add(internal, fixed_generator::mul_generator(tweak.to_be_bytes())));
    CheckedKeys { server_bytes, user_bytes, server, internal, output, internal_negated, output_negated }
}

pub fn authorize(
    statement: [u8;589], binding_digest: [u8;32],
    user: [u8;32], alpha: [u8;32], beta: [u8;32],
    funding_salt: [u8;32], backup_salt: [u8;32], nonce_salt: [u8;32],
    txid: [u8;32], vout: u32, amount: u64, fee: u64,
    destination: [u8;64], delay: u32, session_auth_point: [u8;64],
) -> Authorization {
    let keys = derive_keys(part::<589,64>(statement,429), user);
    authorize_with_keys(statement,binding_digest,user,alpha,beta,funding_salt,backup_salt,nonce_salt,
        txid,vout,amount,fee,destination,delay,session_auth_point,keys)
}

/// The authorize relation, reusing keys already derived for this statement's
/// exact server encoding and this exact owner encoding (checked below).
pub fn authorize_with_keys(
    statement: [u8;589], binding_digest: [u8;32],
    user: [u8;32], alpha: [u8;32], beta: [u8;32],
    funding_salt: [u8;32], backup_salt: [u8;32], nonce_salt: [u8;32],
    txid: [u8;32], vout: u32, amount: u64, fee: u64,
    destination: [u8;64], delay: u32, session_auth_point: [u8;64], keys: CheckedKeys,
) -> Authorization {
    assert(keys.server_bytes == part::<589,64>(statement,429), "checked keys server share");
    assert(keys.user_bytes == user, "checked keys owner share");
    assert(part::<589,4>(statement,0) == [10,0,0,0], "private recovery protocol version");
    for i in 0..6 {
        assert(bitcoin_relations::is_nonzero(part::<589,32>(statement,4+i*32)), "zero transfer context");
        assert(bitcoin_relations::is_nonzero(part::<589,32>(statement,237+i*32)), "zero signing commitment");
    }
    assert(part::<589,32>(statement,301) != part::<589,32>(statement,333), "capability must rotate");
    let context = part::<589,237>(statement,0);
    bitcoin_relations::context10(context);
    let deployment = part::<589,32>(statement,4);
    let coin = part::<589,32>(statement,36);
    let session = read_point(session_auth_point);
    assert(session.x.to_be_bytes() == part::<589,32>(statement,164), "session auth lift");
    assert(session.y.to_be_bytes()[31] & 1 == 0, "session auth parity");
    assert(application_digest(join("ZARK/private-handoff/signing/v1".as_bytes(),statement)) == binding_digest, "signing binding digest");

    let funding = part::<589,32>(statement,237);
    let recovery = part::<589,32>(statement,365);
    let nonce_commitment = part::<589,32>(statement,397);
    // derive_keys read and checked the server share and nonzero owner scalar.
    let server = keys.server;
    let server_nonce = read_point(part::<589,64>(statement,493));
    let submitted_challenge = read_scalar(part::<589,32>(statement,557));
    let a = read_scalar(alpha);
    let b = read_scalar(beta);
    assert(!a.is_zero()); assert(!b.is_zero());
    assert(bitcoin_relations::is_nonzero(funding_salt)); assert(bitcoin_relations::is_nonzero(backup_salt));
    assert(bitcoin_relations::is_nonzero(nonce_salt)); assert(bitcoin_relations::is_nonzero(txid));
    assert(amount > 0); assert(amount <= 2_100_000_000_000_000);
    assert(fee > 0); assert(fee <= 10_000); assert(amount > fee + 330);
    assert(delay > 0); assert(delay <= 65535, "block-only recovery sequence");

    let internal = keys.internal;
    let output = keys.output;
    let q = output.x.to_be_bytes();
    let payout = read_point(destination);
    assert(payout.y.to_be_bytes()[31] & 1 == 0, "recovery payout parity");

    let data = join("ZARK/private-handoff/funding/v1".as_bytes(),[10,0,0,0]);
    let data = join(join(join(join(data,deployment),coin),funding_salt),txid);
    let data = join(join(join(join(data,le32(vout)),le64(amount)),q),internal.x.to_be_bytes());
    assert(application_digest(data) == funding, "funding opening");
    let data = join("ZARK/private-handoff/recovery/v1".as_bytes(),[10,0,0,0]);
    let data = join(join(join(join(data,deployment),coin),funding),backup_salt);
    let data = join(join(join(data,payout.x.to_be_bytes()),le64(fee)),le32(delay));
    let recovery_commitment = application_digest(data);
    assert(recovery_commitment == recovery, "recovery opening");
    let data = join("ZARK/private-handoff/nonce/v1".as_bytes(),context);
    let data = join(join(join(join(join(data,funding),recovery),alpha),beta),nonce_salt);
    assert(application_digest(data) == nonce_commitment, "blinding commitment");

    let (nonce, nonce_negated) = normalize(add(add(server_nonce,
        fixed_generator::mul_generator(a.to_be_bytes())),
        bigcurve::glv::mul(server,b)));
    let message = recovery_sighash(txid,vout,amount,fee,q,payout.x.to_be_bytes(),delay);
    let e = challenge_scalar(tagged("BIP0340/challenge".as_bytes(),join(join(nonce.x.to_be_bytes(),q),message)));
    let negate_e = keys.negated() != nonce_negated;
    let c = b + if negate_e { e.neg() } else { e };
    assert(c == submitted_challenge, "blinded Bitcoin challenge");
    Authorization { recovery_commitment, server, server_nonce, challenge: c, nonce, output, e }
}

pub fn verify_partial(server:Secp256k1,server_nonce:Secp256k1,challenge:bignum::Secp256k1_Fr,partial:[u8;32]) {
    let z=read_scalar(partial);
    assert(fixed_generator::mul_generator(z.to_be_bytes()) ==
        add(server_nonce,bigcurve::glv::mul(server,challenge)), "signer partial equation");
}

pub fn finalize(ctx: Authorization, partial: [u8;32], signature: [u8;64]) {
    verify_partial(ctx.server,ctx.server_nonce,ctx.challenge,partial);
    assert(part::<64,32>(signature,0) == ctx.nonce.x.to_be_bytes(), "signature nonce");
    let s = read_scalar(part::<64,32>(signature,32));
    assert(fixed_generator::mul_generator(s.to_be_bytes()) ==
        add(ctx.nonce,bigcurve::glv::mul(ctx.output,ctx.e)), "completed Bitcoin signature");
}

// CheckedKeys is reusable only with the exact server and owner encodings it
// was derived from. The two binding assertions run before any other check.
global G_BYTES: [u8;64] = [121,190,102,126,249,220,187,172,85,160,98,149,206,135,11,7,2,155,252,219,45,206,40,217,89,242,129,91,22,248,23,152,72,58,218,119,38,163,196,101,93,164,251,252,14,17,8,168,253,23,180,72,166,133,84,25,156,71,208,143,251,16,212,184];
global TWO_G_BYTES: [u8;64] = [198,4,127,148,65,237,125,109,48,69,64,110,149,192,124,216,92,119,142,75,140,239,60,167,171,172,9,185,92,112,158,229,26,225,104,254,166,61,195,57,163,197,132,25,70,108,234,238,247,246,50,101,50,102,208,225,35,100,49,169,80,207,229,42];

fn owner(value: u8) -> [u8;32] { let mut b = [0 as u8;32]; b[31] = value; b }

fn statement_with_server(server: [u8;64]) -> [u8;589] {
    let mut statement = [0 as u8;589];
    for i in 0..64 { statement[429+i] = server[i]; }
    statement
}

fn reuse(statement: [u8;589], user: [u8;32], keys: CheckedKeys) {
    let _ = authorize_with_keys(statement,[0;32],user,[1;32],[1;32],[1;32],[1;32],[1;32],
        [1;32],0,100000,1000,G_BYTES,10,G_BYTES,keys);
}

#[test(should_fail_with = "checked keys server share")]
fn checked_keys_reject_another_server_share() {
    reuse(statement_with_server(TWO_G_BYTES),owner(5),derive_keys(G_BYTES,owner(5)));
}

#[test(should_fail_with = "checked keys owner share")]
fn checked_keys_reject_another_owner_share() {
    reuse(statement_with_server(G_BYTES),owner(6),derive_keys(G_BYTES,owner(5)));
}

// Control: with the exact encodings both bindings pass, and this deliberately
// incomplete statement is rejected by the next check instead.
#[test(should_fail_with = "private recovery protocol version")]
fn checked_keys_accept_their_exact_encodings() {
    reuse(statement_with_server(G_BYTES),owner(5),derive_keys(G_BYTES,owner(5)));
}

#[test(should_fail_with = "nonzero user share")]
fn derive_keys_rejects_zero_owner() {
    let _ = derive_keys(G_BYTES,owner(0));
}
