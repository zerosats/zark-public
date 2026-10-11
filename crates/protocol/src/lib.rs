//! Zark protocol contracts, Bitcoin-blind cryptography and bounded verification.
use anyhow::{Result, anyhow, ensure};
use k256::elliptic_curve::{
    Field, PrimeField,
    ops::Reduce,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub mod address;
mod application_hash;
pub mod assets;
pub mod batch;
pub mod bootstrap;
pub mod certificate;
pub mod deployment;
pub mod deposit;
pub mod exit;
pub mod handoff;
pub mod head;
pub mod lineage;
pub mod local;
pub mod mail;
pub mod network;
pub mod owner_auth;
pub mod proof;
pub mod remote;
pub mod session;
pub mod storage;
pub mod timing;
pub mod verifier;
mod verifier_process;
pub mod wire;

pub fn random32() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn random_scalar() -> Scalar {
    loop {
        let s = Scalar::random(&mut OsRng);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

pub fn scalar(bytes: &[u8]) -> Result<Scalar> {
    let b: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("scalar length"))?;
    Option::from(Scalar::from_repr(b.into())).ok_or_else(|| anyhow!("noncanonical scalar"))
}

pub fn reduce(bytes: [u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into())
}

pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let t = hash(&[tag.as_bytes()]);
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn point_bytes(p: ProjectivePoint) -> Result<[u8; 64]> {
    let encoded = AffinePoint::from(p).to_encoded_point(false);
    ensure!(encoded.as_bytes().len() == 65, "point at infinity");
    Ok(encoded.as_bytes()[1..].try_into()?)
}

pub fn point(bytes: &[u8]) -> Result<ProjectivePoint> {
    ensure!(bytes.len() == 64, "point length");
    let mut sec = [4; 65];
    sec[1..].copy_from_slice(bytes);
    let enc = EncodedPoint::from_bytes(sec)?;
    let p: AffinePoint = Option::from(AffinePoint::from_encoded_point(&enc))
        .ok_or_else(|| anyhow!("invalid point"))?;
    Ok(ProjectivePoint::from(p))
}

pub fn even(p: ProjectivePoint) -> Result<(ProjectivePoint, Scalar)> {
    let odd = point_bytes(p)?[63] & 1 != 0;
    Ok(if odd {
        (-p, -Scalar::ONE)
    } else {
        (p, Scalar::ONE)
    })
}

pub fn hex32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes"))
}

/// V10 proof ABI: injective big-endian chunks of at most 31 bytes. The final
/// chunk is right-aligned, without changing the canonical statement bytes.
pub fn public_fields(statement: &[u8]) -> Vec<u8> {
    statement
        .chunks(31)
        .flat_map(|chunk| {
            let mut field = [0; 32];
            field[32 - chunk.len()..].copy_from_slice(chunk);
            field
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_statement_preserves_chunk_boundaries_and_leading_zeroes() {
        for length in [0usize, 1, 30, 31, 32, 62, 63, 685, 877, 1466] {
            let input: Vec<u8> = (0..length).map(|i| i as u8).collect();
            let packed = public_fields(&input);
            assert_eq!(packed.len(), length.div_ceil(31) * 32);
            for (index, chunk) in input.chunks(31).enumerate() {
                let field = &packed[index * 32..(index + 1) * 32];
                assert!(field[..32 - chunk.len()].iter().all(|b| *b == 0));
                assert_eq!(&field[32 - chunk.len()..], chunk);
            }
        }
        assert_ne!(public_fields(&[1, 0]), public_fields(&[0, 1]));
    }

    #[test]
    fn rejects_noncanonical_scalars_and_invalid_points() {
        assert!(scalar(&[255; 32]).is_err());
        assert!(scalar(&[1; 31]).is_err());
        assert!(point(&[0; 64]).is_err());
        assert!(point_bytes(ProjectivePoint::IDENTITY).is_err());
    }

    #[test]
    fn three_owners_preserve_the_internal_key() {
        let mut server = random_scalar();
        let mut owner = random_scalar();
        let original = ProjectivePoint::GENERATOR * (server + owner);
        for _ in 0..2 {
            let next = random_scalar();
            // These are separate participant computations in the protocol.
            let mask = random_scalar();
            let sender_to_receiver = owner + mask;
            let receiver_to_server = sender_to_receiver - next;
            server = server + receiver_to_server - mask;
            owner = next;
            assert_eq!(ProjectivePoint::GENERATOR * (server + owner), original);
        }
        // This algebra test is NOT a private transfer or erasure demonstration.
    }
}
