use super::*;

#[test]
fn embedded_constants_authenticate_and_lie_on_the_curve() {
    let tables = Tables::load().unwrap();
    assert_eq!(tables.bank.len(), BANK_SIZE);
    assert_eq!(tables.fixed.len(), WINDOWS);
    assert!(
        tables
            .bank
            .iter()
            .flatten()
            .chain(tables.fixed.iter().flatten())
            .all(|point| point.on_curve())
    );
}

#[test]
fn table_points_must_be_canonical_and_on_the_curve() {
    let tables = Tables::load().unwrap();
    let valid = tables.bank[0][0];
    let raw = |x: Fp, y: Fp| [x.limbs(), y.limbs()];
    assert_eq!(point(&raw(valid.x, valid.y)).unwrap(), valid);
    assert!(point(&raw(valid.x, valid.y + Fp::ONE)).is_err());
    let mut p = (-Fp::ONE).limbs();
    p[0] += 1;
    assert!(point(&[p, valid.y.limbs()]).is_err());
    assert!(point(&[[1 << 120, 0, 0], valid.y.limbs()]).is_err());
}
