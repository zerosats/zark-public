use bigcurve::{BigCurve, Secp256k1, Secp256k1Scalar};
use bignum::BigNum;
use bitcoin_relations::{join, part, read_point, read_scalar};


fn nonzero(bytes: [u8;32]) { assert(bitcoin_relations::is_nonzero(bytes), "zero identifier, salt or commitment"); }

pub fn claim(
    statement: [u8;397],
    claim_secret: [u8;32], claim_point: [u8;64], claim_salt: [u8;32],
    session_auth_point: [u8;64],
    masked_share: [u8;32], masked_share_salt: [u8;32],
    user: [u8;32], delta: [u8;32], delta_salt: [u8;32],
    next_capability: [u8;32],
) -> ([u8;32],[u8;32],[u8;32]) {
    let context = part::<397,237>(statement,0);
    assert(part::<237,4>(context,0) == [10,0,0,0], "claim protocol version");
    for i in 0..6 { nonzero(part::<237,32>(context,4+i*32)); }
    for i in 0..5 { nonzero(part::<397,32>(statement,237+i*32)); }
    nonzero(claim_salt); nonzero(masked_share_salt); nonzero(delta_salt); nonzero(next_capability);
    bitcoin_relations::context10(context);
    let session = read_point(session_auth_point);
    assert(session.x.to_be_bytes() == part::<237,32>(context,164), "session key lift");
    assert(session.y.to_be_bytes()[31] & 1 == 0, "session key parity");

    let secret = read_scalar(claim_secret);
    assert(!secret.is_zero(), "zero claim secret");
    let claimed = read_point(claim_point);
    assert(claimed.y.to_be_bytes()[31] & 1 == 0, "claim key parity");
    let actual = fixed_generator::mul_generator(secret.to_be_bytes());
    assert(!actual.is_infinity);
    assert(actual.x == claimed.x); assert(actual.y == claimed.y);
    let claim_message = join(join(join(
        "ZARK/private-handoff/recipient/v1".as_bytes(), part::<237,68>(context,0)),
        part::<237,32>(context,100)), join(claimed.x.to_be_bytes(), claim_salt));
    assert(bitcoin_relations::application_digest(claim_message) == part::<237,32>(context,132), "recipient claim opening");

    let z = read_scalar(masked_share);
    let u = read_scalar(user);
    let d = read_scalar(delta);
    assert(!z.is_zero(), "zero masked share"); assert(!u.is_zero(), "zero recipient user share");
    assert(z == u + d, "delta does not preserve masked share");

    let intent = bitcoin_relations::application_digest(join("ZARK/private-handoff/intent/v1".as_bytes(), bitcoin_relations::intent10(context)));
    let z_commitment = bitcoin_relations::application_digest(join(join(join(
        "ZARK/private-handoff/masked-share/v1".as_bytes(), intent), masked_share), masked_share_salt));
    assert(z_commitment == part::<397,32>(statement,269), "masked share commitment");
    let delta_commitment = bitcoin_relations::application_digest(join(join(join(
        "ZARK/private-handoff/delta/v1".as_bytes(), context), delta), delta_salt));
    assert(delta_commitment == part::<397,32>(statement,333), "delta commitment");
    let capability_commitment = bitcoin_relations::owner_capability(part::<237,68>(context,0),next_capability);
    assert(capability_commitment == part::<397,32>(statement,365), "next capability commitment");
    // Cm at196 and bridge at260 are opaque authenticated sender-state inputs.
    // Binding them in this digest does not itself establish their provenance.
    // Reuse only after the receiver binds claim context/commitments exactly.
    (intent,z_commitment,delta_commitment)
}
