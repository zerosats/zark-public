use super::*;
use k256::elliptic_curve::sec1::ToEncodedPoint;

fn sample(i: u32) -> Fp {
    let bytes = zark_protocol::hash(&[b"zark-fast-helper-field-test", &i.to_be_bytes()]);
    let low = u128::from_be_bytes(bytes[16..].try_into().unwrap());
    let high = u128::from_be_bytes(bytes[..16].try_into().unwrap());
    let limbs = [
        low & (RADIX - 1),
        ((low >> RADIX_BITS) | (high << 8)) & (RADIX - 1),
        high >> 112,
    ];
    Fp::from_limbs(limbs, false).unwrap()
}

fn p_limbs() -> [u128; 3] {
    let mut limbs = (-Fp::ONE).limbs();
    limbs[0] += 1;
    limbs
}

fn generator() -> Point {
    let encoded = k256::AffinePoint::GENERATOR.to_encoded_point(false);
    let coordinate = |bytes: &[u8]| Fp::from_be_bytes(bytes.try_into().unwrap()).unwrap();
    Point {
        x: coordinate(encoded.x().unwrap()),
        y: coordinate(encoded.y().unwrap()),
    }
}

#[test]
fn limbs_are_range_checked_and_only_wire_values_reduce() {
    let p = p_limbs();
    assert_eq!(p[2], TOP - 1);
    assert!(Fp::from_limbs(p, true).is_none());
    assert_eq!(Fp::from_limbs(p, false), Some(Fp::ZERO));
    let mut p_plus_one = p;
    p_plus_one[0] += 1;
    assert_eq!(Fp::from_limbs(p_plus_one, false), Some(Fp::ONE));
    let max = [RADIX - 1, RADIX - 1, TOP - 1];
    assert!(Fp::from_limbs(max, true).is_none());
    assert_eq!(
        Fp::from_limbs(max, false).unwrap().limbs(),
        [0x1_0000_03d0, 0, 0]
    );
    for bad in [[RADIX, 0, 0], [0, RADIX, 0], [0, 0, TOP]] {
        assert!(Fp::from_limbs(bad, false).is_none());
    }
    assert_eq!((-Fp::ONE).limbs()[0], p[0] - 1);
}

#[test]
fn canonical_limbs_round_trip() {
    for i in 0..256 {
        let value = sample(i);
        assert_eq!(Fp::from_limbs(value.limbs(), true), Some(value));
    }
    assert_eq!(Fp::small(1 << 40).limbs(), [1 << 40, 0, 0]);
}

#[test]
fn field_operations_are_consistent() {
    for i in 0..64 {
        let (a, b) = (sample(2 * i), sample(2 * i + 1));
        assert_eq!(a + b - b, a);
        assert_eq!(a - b, -(b - a));
        assert_eq!(a * (b + Fp::ONE), a * b + a);
        assert_eq!(a * a.invert().unwrap(), Fp::ONE);
        assert!((a - a).is_zero());
    }
    assert!(Fp::ZERO.invert().is_none());
    assert_eq!(Fp::small(5) - Fp::small(7), -Fp::small(2));
    let beta = Fp::beta();
    assert!(beta != Fp::ONE && beta * beta * beta == Fp::ONE);
}

#[test]
fn curve_membership_uses_y_squared_equals_x_cubed_plus_seven() {
    let g = generator();
    assert!(g.on_curve());
    assert!(
        Point {
            x: g.x * Fp::beta(),
            y: -g.y
        }
        .on_curve()
    );
    assert!(
        !Point {
            x: g.x,
            y: g.y + Fp::ONE
        }
        .on_curve()
    );
    assert!(
        !Point {
            x: Fp::ZERO,
            y: Fp::ZERO
        }
        .on_curve()
    );
}
