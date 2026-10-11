use bigcurve::{BigCurve, Secp256k1, Secp256k1Scalar};
use bignum::{BigNum, Secp256k1_Fq, Secp256k1_Fr};
use std::ops::Neg;
mod sha_fixed;
mod point_addition;
mod byte_checks;
pub use byte_checks::is_nonzero;
pub use point_addition::add;

pub fn join<let A: u32, let B: u32>(a: [u8; A], b: [u8; B]) -> [u8; A + B] {
    let mut out = [0; A + B];
    for i in 0..A { out[i] = a[i]; }
    for i in 0..B { out[A+i] = b[i]; }
    out
}

pub fn part<let N: u32, let M: u32>(a: [u8; N], offset: u32) -> [u8; M] {
    let mut out = [0; M];
    for i in 0..M { out[i] = a[offset+i]; }
    out
}

pub fn le32(v: u32) -> [u8; 4] {
    let mut b = [0; 4];
    for i in 0..4 { b[i] = ((v >> (8*i)) & 255) as u8; }
    b
}
pub fn read_le32(b: [u8; 4]) -> u32 {
    let mut value: u32 = 0;
    for i in 0..4 { value = value | ((b[i] as u32) << (8*i)); }
    value
}
pub fn le64(v: u64) -> [u8; 8] {
    let mut b = [0; 8];
    for i in 0..8 { b[i] = ((v >> (8*i as u64)) & 255) as u8; }
    b
}

pub fn tagged<let N: u32, let T: u32>(tag: [u8; T], msg: [u8; N]) -> [u8; 32] {
    let t = sha_fixed::digest(tag);
    sha_fixed::digest(join(join(t, t), msg))
}

fn read_coordinate(bytes: [u8; 32]) -> Secp256k1_Fq {
    let coordinate = Secp256k1_Fq::from_be_bytes(bytes);
    // BigNum validate_in_field deliberately allows MOD as a representation of
    // zero. Public Bitcoin encodings require a strict integer bound; cmp is
    // integer comparison while BigNum equality is modular.
    assert(coordinate < Secp256k1_Fq::modulus(), "non-canonical coordinate");
    coordinate
}

pub fn read_point(bytes: [u8; 64]) -> Secp256k1 {
    let x = read_coordinate(part::<64,32>(bytes, 0));
    let y = read_coordinate(part::<64,32>(bytes, 32));
    let p = Secp256k1::from_coordinates(x, y, false);
    p.validate_on_curve();
    p
}

pub fn read_scalar(bytes: [u8; 32]) -> Secp256k1_Fr {
    let s = Secp256k1_Fr::from_be_bytes(bytes);
    assert(s < Secp256k1_Fr::modulus(), "non-canonical scalar");
    s
}

pub fn normalize(p: Secp256k1) -> (Secp256k1, bool) {
    assert(!p.is_infinity);
    assert(p.x < Secp256k1_Fq::modulus(), "non-canonical coordinate");
    assert(p.y < Secp256k1_Fq::modulus(), "non-canonical coordinate");
    let odd = p.y.to_be_bytes()[31] & 1 == 1;
    (if odd { p.neg() } else { p }, odd)
}

// SHA256 challenges reduce modulo n; encoded scalars and TapTweak must be < n.
pub fn challenge_scalar(bytes: [u8; 32]) -> Secp256k1_Fr {
    let order: [u8; 32] = [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,254,186,174,220,230,175,72,160,59,191,210,94,140,208,54,65,65];
    let mut sub = [0; 32];
    let mut borrow: u16 = 0;
    for j in 0..32 {
        let i = 31-j;
        let rhs = order[i] as u16 + borrow;
        let lhs = bytes[i] as u16;
        sub[i] = ((lhs + 256 - rhs) & 255) as u8;
        borrow = (lhs < rhs) as u16;
    }
    read_scalar(if borrow == 0 { sub } else { bytes })
}

pub struct Authorization {
    // Exact SHA output already checked by recovery::authorize, not witness input.
    pub recovery_commitment: [u8;32],
    pub server: Secp256k1,
    pub server_nonce: Secp256k1,
    pub challenge: Secp256k1_Fr,
    pub nonce: Secp256k1,
    pub output: Secp256k1,
    pub e: Secp256k1_Fr,
}

#[test]
fn challenge_reduction_boundary() {
    let order: [u8; 32] = [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,254,186,174,220,230,175,72,160,59,191,210,94,140,208,54,65,65];
    assert(challenge_scalar(order).is_zero());
    assert(challenge_scalar([0; 32]).is_zero());
    let mut below = order; below[31] -= 1;
    let mut above = order; above[31] += 1;
    assert(challenge_scalar(below).to_be_bytes() == below);
    assert(challenge_scalar(above) == Secp256k1_Fr::one());
    let max_reduced: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,69,81,35,25,80,183,95,196,64,45,161,115,47,201,190,190];
    assert(challenge_scalar([255; 32]).to_be_bytes() == max_reduced);
}

#[test(should_fail_with = "non-canonical scalar")]
fn scalar_encoding_rejects_order() {
    let _ = read_scalar(Secp256k1_Fr::modulus().to_be_bytes());
}

#[test(should_fail_with = "non-canonical scalar")]
fn scalar_encoding_rejects_above_order() {
    let mut bytes = Secp256k1_Fr::modulus().to_be_bytes(); bytes[31] += 1;
    let _ = read_scalar(bytes);
}

#[test(should_fail_with = "non-canonical scalar")]
fn scalar_encoding_rejects_maximum() {
    let _ = read_scalar([255; 32]);
}

#[test]
fn canonical_encoding_boundaries() {
    let mut scalar_max = Secp256k1_Fr::modulus().to_be_bytes(); scalar_max[31] -= 1;
    assert(read_scalar(scalar_max).to_be_bytes() == scalar_max);
    assert(read_scalar([0; 32]).to_be_bytes() == [0; 32]);
    let mut coordinate_max = Secp256k1_Fq::modulus().to_be_bytes(); coordinate_max[31] -= 1;
    assert(read_coordinate(coordinate_max).to_be_bytes() == coordinate_max);
    assert(read_coordinate([0; 32]).to_be_bytes() == [0; 32]);
}

#[test(should_fail_with = "non-canonical coordinate")]
fn coordinate_encoding_rejects_modulus() {
    let _ = read_coordinate(Secp256k1_Fq::modulus().to_be_bytes());
}

#[test(should_fail_with = "non-canonical coordinate")]
fn coordinate_encoding_rejects_above_modulus() {
    let mut bytes = Secp256k1_Fq::modulus().to_be_bytes(); bytes[31] += 1;
    let _ = read_coordinate(bytes);
}

#[test(should_fail_with = "non-canonical coordinate")]
fn coordinate_encoding_rejects_maximum() {
    let _ = read_coordinate([255; 32]);
}

#[test(should_fail)]
fn point_encoding_rejects_off_curve() {
    let _ = read_point([0; 64]);
}

#[test(should_fail)]
fn normalization_rejects_infinity() {
    let _ = normalize(Secp256k1::point_at_infinity());
}

#[test]
fn policy_integer_encoding_boundaries() {
    assert(read_le32(le32(0)) == 0);
    assert(read_le32(le32(10)) == 10);
    assert(read_le32(le32(2880)) == 2880);
    assert(read_le32(le32(65535)) == 65535);
    assert(read_le32([255;4]) == 4294967295);
}

#[test]
fn affine_add_edge_cases() {
    let g = Secp256k1::one();
    assert(add(g,g.neg()).is_infinity);
    assert(add(g,Secp256k1::point_at_infinity()) == g);
    assert(add(Secp256k1::point_at_infinity(),g) == g);
    assert(add(g,g) == g.mul(Secp256k1Scalar::from_bignum(Secp256k1_Fr::from(2))));
}


pub fn digest<let N:u32>(bytes:[u8;N]) -> [u8;32] { sha_fixed::digest(bytes) }

// Version 10 application commitments only; tagged Bitcoin SHA stays above.
pub fn application_digest<let N:u32>(bytes:[u8;N]) -> [u8;32] { app_hash::digest(bytes) }

pub fn context10(context:[u8;237]) {
    assert(part::<237,4>(context,0) == [10,0,0,0], "context version");
    for i in 0..6 { assert(is_nonzero(part::<237,32>(context,4+32*i)), "empty context field"); }
    let scope = context[204];
    let batch = part::<237,32>(context,205);
    assert(scope <= 1, "context scope");
    assert(if scope == 0 { !is_nonzero(batch) } else { is_nonzero(batch) }, "context batch scope");
}

pub fn intent10(context:[u8;237]) -> [u8;205] {
    context10(context);
    join(part::<237,164>(context,0),part::<237,41>(context,196))
}

pub fn handover_intent10(intent:[u8;205]) {
    assert(part::<205,4>(intent,0) == [10,0,0,0], "handover version");
    for i in 0..5 { assert(is_nonzero(part::<205,32>(intent,4+32*i)), "empty handover intent"); }
    assert(part::<205,8>(intent,164) != [0;8], "handover starting revision");
    let scope = intent[172];
    let batch = part::<205,32>(intent,173);
    assert(scope <= 1, "handover scope");
    assert(if scope == 0 { !is_nonzero(batch) } else { is_nonzero(batch) }, "handover batch scope");
}

// The stored secret is already BIP340-normalized, not a seed or arbitrary sign.
pub fn owner_capability(domain:[u8;68],secret:[u8;32]) -> [u8;32] {
    let a=read_scalar(secret);assert(!a.is_zero(), "zero owner auth secret");
    let point=fixed_generator::mul_generator(a.to_be_bytes());
    assert(!point.is_infinity, "owner auth infinity");
    assert(point.y.to_be_bytes()[31] & 1 == 0, "owner auth secret must be normalized");
    application_digest(join(join("ZARK/private-handoff/owner-capability/v1".as_bytes(),domain),point.x.to_be_bytes()))
}

pub fn draft_token_commit(intent:[u8;205],token:[u8;32]) -> [u8;32] {
    assert(is_nonzero(token), "empty draft token");
    application_digest(join(join("ZARK/private-handoff/draft-access/v1".as_bytes(),intent),token))
}

#[test]
fn v9_intent_excludes_only_session() {
    let mut context=[1 as u8;237];
    for i in 0..4 { context[i]=[10,0,0,0][i]; }
    context[204]=1;
    let first=intent10(context);
    context[164]=2;
    assert(first==intent10(context));
    context[196]=2;
    assert(first!=intent10(context));
    handover_intent10(intent10(context));
}

#[test(should_fail_with = "context batch scope")]
fn single_scope_rejects_batch_digest() {
    let mut context=[1 as u8;237];
    for i in 0..4 { context[i]=[10,0,0,0][i]; }
    context[204]=0;
    context10(context);
}

#[test(should_fail_with = "context batch scope")]
fn batch_scope_requires_batch_digest() {
    let mut context=[1 as u8;237];
    for i in 0..4 { context[i]=[10,0,0,0][i]; }
    context[204]=1;
    for i in 205..237 { context[i]=0; }
    context10(context);
}

#[test(should_fail_with = "handover starting revision")]
fn handover_rejects_origin_revision() {
    let mut intent=[1 as u8;205];
    for i in 0..4 { intent[i]=[10,0,0,0][i]; }
    for i in 164..172 { intent[i]=0; }
    handover_intent10(intent);
}
