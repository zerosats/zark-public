//! Compare the exact Jacobian transcript against the pre-optimization formulas,
//! including different projective representations of equal/inverse points.
use super::{Entry, Fp, Jacobian, ZERO, checked_add, complete_add, double, raw_add};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};

fn point(scalar: u64, scale: Fp) -> Jacobian {
    let p = (ProjectivePoint::GENERATOR * Scalar::from(scalar))
        .to_affine()
        .to_encoded_point(false);
    let x = Fp::from_be_bytes((*p.x().unwrap()).into()).unwrap();
    let y = Fp::from_be_bytes((*p.y().unwrap()).into()).unwrap();
    Jacobian {
        x: x * scale * scale,
        y: y * scale * scale * scale,
        z: scale,
        infinity: false,
    }
}

fn scale(i: u64) -> Fp {
    let mut bytes = zark_protocol::hash(&[&i.to_le_bytes()]);
    bytes[0] &= 0x7f; // Canonical without reducing; broad coordinate coverage.
    bytes[31] |= 1;
    Fp::from_be_bytes(bytes).unwrap()
}

fn reference_double(p: Jacobian) -> Entry {
    let Jacobian { x, y, z, .. } = p;
    let m = Fp::small(3) * x * x;
    let d = Fp::small(4) * x * y * y;
    let nx = m * m - Fp::small(2) * d;
    let ny = m * (d - nx) - Fp::small(8) * y * y * y * y;
    [m, nx, ny, Fp::small(2) * y * z]
}

fn reference_add(a: Jacobian, b: Jacobian) -> Entry {
    let u1 = a.x * b.z * b.z;
    let u2 = b.x * a.z * a.z;
    let s1 = a.y * b.z * b.z * b.z;
    let s2 = b.y * a.z * a.z * a.z;
    let r = s2 - s1;
    let h = u2 - u1;
    let pp = h * h;
    let x = r * r - pp * (u1 + u2);
    let y = pp * (u1 * s2 - u2 * s1) - x * r;
    [r, x, y, a.z * b.z * h]
}

fn assert_coordinates(point: Jacobian, entry: Entry) {
    assert_eq!([point.x, point.y, point.z], [entry[1], entry[2], entry[3]]);
    assert!(!point.infinity);
}

#[test]
fn optimized_kernels_preserve_exact_projective_transcripts() {
    for i in 1..=256 {
        let a = point(i, scale(i));
        let b = point(i + 1, scale(i + 512));
        let (next, entry) = double(a).unwrap();
        assert_eq!(entry, reference_double(a));
        assert_coordinates(next, entry);
        let expected = reference_add(a, b);
        let (next, entry) = raw_add(a, b);
        assert_eq!(entry, expected);
        assert_coordinates(next, entry);
        let (next, entry) = checked_add(a, b).unwrap().unwrap();
        assert_eq!(entry, expected);
        assert_coordinates(next, entry);
        assert_eq!(complete_add(a, b).unwrap(), expected);

        // Equal points with different z values must still take the tangent
        // branch, and inverse points must retain the zero transcript row.
        let same = point(i, scale(i + 1024));
        let inverse = Jacobian { y: -same.y, ..same };
        assert!(checked_add(a, same).unwrap().is_none());
        assert!(checked_add(a, inverse).unwrap().is_none());
        assert_eq!(complete_add(a, same).unwrap(), reference_double(a));
        assert_eq!(complete_add(a, inverse).unwrap(), ZERO);
    }
}

#[test]
fn exceptional_branches_keep_their_original_transcripts() {
    let finite = point(17, Fp::ONE);
    let infinity = Jacobian {
        infinity: true,
        ..finite
    };
    let zero_y = Jacobian {
        y: Fp::ZERO,
        ..finite
    };
    assert!(double(infinity).is_err());
    assert!(double(zero_y).is_err());
    assert!(checked_add(infinity, finite).is_err());
    assert!(checked_add(finite, infinity).is_err());
    let entry = [Fp::ZERO, finite.x, finite.y, finite.z];
    assert_eq!(complete_add(infinity, finite).unwrap(), entry);
    assert_eq!(complete_add(finite, infinity).unwrap(), entry);
    assert_eq!(complete_add(infinity, infinity).unwrap(), entry);
}

#[test]
#[ignore = "release-mode arithmetic benchmark, separate from RPC encoding"]
fn benchmark_jacobian_kernels() {
    use std::hint::black_box;
    use std::time::Instant;
    type Kernel = fn(Jacobian, Jacobian) -> Entry;
    let inputs: Vec<_> = (1..=64)
        .map(|i| (point(i, scale(i)), point(i + 1, scale(i + 64))))
        .collect();
    let kernels: [(&str, Kernel); 4] = [
        ("old_double", |a, _| reference_double(a)),
        ("new_double", |a, _| double(a).unwrap().1),
        ("old_checked_add", |a, b| {
            assert!(a.x * b.z * b.z != b.x * a.z * a.z);
            reference_add(a, b)
        }),
        ("new_checked_add", |a, b| {
            checked_add(a, b).unwrap().unwrap().1
        }),
    ];
    for round in 0..10 {
        let order: Vec<_> = if round % 2 == 0 {
            (0..4).collect()
        } else {
            (0..4).rev().collect()
        };
        for i in order {
            let (name, kernel) = kernels[i];
            let start = Instant::now();
            for _ in 0..2048 {
                for &(a, b) in &inputs {
                    black_box(kernel(black_box(a), black_box(b)));
                }
            }
            println!(
                "{}",
                serde_json::json!({"kernel":name,"round":round,
                "ns_per_call":start.elapsed().as_nanos() as f64 / (2048 * inputs.len()) as f64})
            );
        }
    }
}
