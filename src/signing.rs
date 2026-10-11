//! Client-side blinding. No routine takes the server's secret share.
use anyhow::{Result, ensure};
use k256::{ProjectivePoint, Scalar};
use zark_protocol::{even, point_bytes, random_scalar, reduce, scalar, tagged_hash};
use zeroize::Zeroize;

pub struct FundingKey {
    pub internal: ProjectivePoint,
    pub output: ProjectivePoint,
    pub server_coefficient: Scalar,
    user_effective: Scalar,
}

impl FundingKey {
    pub fn new(server: ProjectivePoint, owner: Scalar) -> Result<Self> {
        let (internal, p_sign) = even(server + ProjectivePoint::GENERATOR * owner)?;
        let t = scalar(&tagged_hash("TapTweak", &[&point_bytes(internal)?[..32]]))?;
        let (output, q_sign) = even(internal + ProjectivePoint::GENERATOR * t)?;
        Ok(Self {
            internal,
            output,
            server_coefficient: p_sign * q_sign,
            user_effective: q_sign * (p_sign * owner + t),
        })
    }
    pub fn xonly(&self) -> Result<[u8; 32]> {
        Ok(point_bytes(self.output)?[..32].try_into()?)
    }
}

impl Drop for FundingKey {
    fn drop(&mut self) {
        self.user_effective.zeroize();
    }
}

pub struct Blinding {
    pub alpha: Scalar,
    pub beta: Scalar,
}
impl Default for Blinding {
    fn default() -> Self {
        Self {
            alpha: random_scalar(),
            beta: random_scalar(),
        }
    }
}
impl Drop for Blinding {
    fn drop(&mut self) {
        self.alpha.zeroize();
        self.beta.zeroize();
    }
}

pub struct SigningSession {
    pub challenge: Scalar,
    pub nonce: ProjectivePoint,
    e: Scalar,
    nonce_sign: Scalar,
}

impl Blinding {
    pub fn bind(
        &self,
        key: &FundingKey,
        server: ProjectivePoint,
        server_nonce: ProjectivePoint,
        message: [u8; 32],
    ) -> Result<SigningSession> {
        let (nonce, nonce_sign) =
            even(server_nonce + ProjectivePoint::GENERATOR * self.alpha + server * self.beta)?;
        let e = reduce(tagged_hash(
            "BIP0340/challenge",
            &[&point_bytes(nonce)?[..32], &key.xonly()?, &message],
        ));
        Ok(SigningSession {
            challenge: self.beta + nonce_sign * e * key.server_coefficient,
            nonce,
            e,
            nonce_sign,
        })
    }
    pub fn finish(
        &self,
        key: &FundingKey,
        session: &SigningSession,
        server: ProjectivePoint,
        server_nonce: ProjectivePoint,
        partial: Scalar,
    ) -> Result<[u8; 64]> {
        ensure!(
            ProjectivePoint::GENERATOR * partial == server_nonce + server * session.challenge,
            "invalid server contribution"
        );
        let sig_s = session.nonce_sign * (partial + self.alpha) + session.e * key.user_effective;
        let mut sig = [0; 64];
        sig[..32].copy_from_slice(&point_bytes(session.nonce)?[..32]);
        sig[32..].copy_from_slice(&sig_s.to_bytes());
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};

    #[test]
    fn bip340_signatures_across_random_parities() -> Result<()> {
        let secp = Secp256k1::verification_only();
        for _ in 0..32 {
            let server = random_scalar();
            let owner = random_scalar();
            let server_point = ProjectivePoint::GENERATOR * server;
            let key = FundingKey::new(server_point, owner)?;
            let nonce = random_scalar();
            let rn = ProjectivePoint::GENERATOR * nonce;
            let blinding = Blinding::default();
            let message = [42; 32];
            let session = blinding.bind(&key, server_point, rn, message)?;
            let sig = blinding.finish(
                &key,
                &session,
                server_point,
                rn,
                nonce + session.challenge * server,
            )?;
            secp.verify_schnorr(
                &Signature::from_slice(&sig)?,
                &Message::from_digest(message),
                &XOnlyPublicKey::from_slice(&key.xonly()?)?,
            )?;
            assert!(
                blinding
                    .finish(&key, &session, server_point, rn, Scalar::ZERO)
                    .is_err()
            );
        }
        Ok(())
    }
}
