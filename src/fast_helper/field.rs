//! Canonical secp256k1 base-field values and the circuit's 120/120/16-bit limbs.
use k256::U256;
use k256::elliptic_curve::bigint::{Encoding, Limb};
use std::ops::{Add, Mul, Neg, Sub};

const RADIX_BITS: u32 = 120;
const RADIX: u128 = 1 << RADIX_BITS;
const TOP: u128 = 1 << 16;
/// p = 2^256 - C.
const C: u64 = 0x1_0000_03d1;
const P: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
const BETA: U256 =
    U256::from_be_hex("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");

/// Always fully reduced below p, so equality and zero tests are canonical.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Fp(U256);

impl Fp {
    pub(super) const ZERO: Self = Self(U256::ZERO);
    pub(super) const ONE: Self = Self(U256::ONE);

    pub(super) const fn small(value: u64) -> Self {
        Self(U256::from_u64(value))
    }

    pub(super) const fn beta() -> Self {
        Self(BETA)
    }

    /// A canonical big-endian encoding, or `None` at or above p.
    #[cfg(test)]
    pub(super) fn from_be_bytes(bytes: [u8; 32]) -> Option<Self> {
        let value = U256::from_be_bytes(bytes);
        (value < P).then_some(Self(value))
    }

    /// Range-checked limbs. `canonical` rejects values at or above p; otherwise
    /// a range-bounded representative is reduced (it is below 2^256 < 2p).
    pub(super) fn from_limbs(limbs: [u128; 3], canonical: bool) -> Option<Self> {
        if limbs[0] >= RADIX || limbs[1] >= RADIX || limbs[2] >= TOP {
            return None;
        }
        let low = limbs[0] | (limbs[1] << RADIX_BITS);
        let high = (limbs[1] >> 8) | (limbs[2] << 112);
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&high.to_be_bytes());
        bytes[16..].copy_from_slice(&low.to_be_bytes());
        let value = U256::from_be_bytes(bytes);
        if value < P {
            Some(Self(value))
        } else if canonical {
            None
        } else {
            Some(Self(value.wrapping_sub(&P)))
        }
    }

    pub(super) fn limbs(self) -> [u128; 3] {
        let bytes = self.0.to_be_bytes();
        let high = u128::from_be_bytes(bytes[..16].try_into().expect("high half"));
        let low = u128::from_be_bytes(bytes[16..].try_into().expect("low half"));
        [
            low & (RADIX - 1),
            ((low >> RADIX_BITS) | (high << 8)) & (RADIX - 1),
            high >> 112,
        ]
    }

    pub(super) fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    pub(super) fn invert(self) -> Option<Self> {
        let (inverse, exists) = self.0.inv_odd_mod(&P);
        bool::from(exists).then_some(Self(inverse))
    }
}

impl Add for Fp {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0.add_mod(&rhs.0, &P))
    }
}

impl Sub for Fp {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.sub_mod(&rhs.0, &P))
    }
}

impl Mul for Fp {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(self.0.mul_mod_special(&rhs.0, Limb::from_u64(C)))
    }
}

impl Neg for Fp {
    type Output = Self;
    fn neg(self) -> Self {
        Self(self.0.neg_mod(&P))
    }
}

/// An affine point given by canonical coordinates; curve membership is
/// checked where the reference model checks it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Point {
    pub(super) x: Fp,
    pub(super) y: Fp,
}

impl Point {
    pub(super) fn on_curve(self) -> bool {
        self.y * self.y == self.x * self.x * self.x + Fp::small(7)
    }
}

#[cfg(test)]
#[path = "field_tests.rs"]
mod tests;
