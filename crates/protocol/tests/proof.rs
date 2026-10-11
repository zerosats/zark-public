use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use zark_protocol::{
    assets::read_bounded,
    deployment::{Deployment, Manifest},
    deposit::DepositBinding,
    hash, hex32,
    proof::{ArtifactPin, PROOF_BYTES, Relation},
    random32,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    statement: Vec<u8>,
    deployment: Deployment,
    manifest: Manifest,
    keys: PathBuf,
    bb: PathBuf,
    bb_sha256: String,
    crs: PathBuf,
    authorization_proof: PathBuf,
    other_role_proof: PathBuf,
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires authenticated ZARK_DEPOSIT_PROOF_FIXTURE with a fresh six-role suite"]
fn real_native_deposit_verification_pins_roles_and_canonical_statements() -> Result<()> {
    let fixture: Fixture = serde_json::from_slice(&fs::read(
        std::env::var_os("ZARK_DEPOSIT_PROOF_FIXTURE")
            .context("set an authenticated fresh fused-deposit proof fixture")?,
    )?)?;
    let binding = DepositBinding::decode(&fixture.statement)?;
    let verifier = fixture.deployment.verifier(
        &fixture.manifest,
        &fixture.keys,
        ArtifactPin {
            path: fixture.bb,
            sha256: hex32(&fixture.bb_sha256)?,
        },
        &fixture.crs,
    )?;
    let scratch = Scratch(
        std::env::temp_dir().join(format!("native-private-verify-{}", hex::encode(random32()))),
    );
    fs::DirBuilder::new().mode(0o700).create(&scratch.0)?;
    let authorization = read_bounded(&fixture.authorization_proof, PROOF_BYTES)?;
    let other = read_bounded(&fixture.other_role_proof, PROOF_BYTES)?;
    assert_eq!(authorization.len(), PROOF_BYTES);
    assert_eq!(other.len(), PROOF_BYTES);
    assert_ne!(
        authorization, other,
        "wrong-role fixture must be a distinct proof"
    );
    let result = verifier.deposit_authorization(&binding, &authorization, &scratch.0)?;
    assert_eq!(result.relation(), Relation::DepositAuthorization);
    assert_eq!(result.statement_digest(), hash(&[&binding.encode()?]));
    assert!(
        verifier
            .deposit_authorization(&binding, &other, &scratch.0)
            .is_err()
    );
    assert!(
        verifier
            .deposit_authorization(
                &binding,
                &authorization[..authorization.len() - 1],
                &scratch.0
            )
            .is_err()
    );
    let mut corrupt = authorization.clone();
    corrupt[64] ^= 1;
    assert!(
        verifier
            .deposit_authorization(&binding, &corrupt, &scratch.0)
            .is_err()
    );
    // A coherent context change on both halves must still fail the proof.
    let mut changed = DepositBinding::decode(&fixture.statement)?;
    changed.authorization.signing.context.operation[0] ^= 1;
    changed.bootstrap.context.operation[0] ^= 1;
    assert!(
        verifier
            .deposit_authorization(&changed, &authorization, &scratch.0)
            .is_err()
    );
    let mut changed = DepositBinding::decode(&fixture.statement)?;
    changed.authorization.signing.context.deployment[0] ^= 1;
    changed.bootstrap.context.deployment[0] ^= 1;
    assert!(
        verifier
            .deposit_authorization(&changed, &authorization, &scratch.0)
            .is_err()
    );
    let mut changed = DepositBinding::decode(&fixture.statement)?;
    changed.bootstrap.blinded_challenge[0] ^= 1;
    assert!(
        verifier
            .deposit_authorization(&changed, &authorization, &scratch.0)
            .is_err()
    );
    // A structurally canonical alternative config is not an authenticated suite.
    let mut changed = DepositBinding::decode(&fixture.statement)?;
    changed.authorization.role_hashes[5][31] ^= 1;
    let rejection = verifier.deposit_authorization(&changed, &authorization, &scratch.0);
    let error = match rejection {
        Ok(_) => anyhow::bail!("unauthenticated role hash accepted"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("lineage deployment, policy, origin or role configuration mismatch")
    );
    assert!(fs::read_dir(&scratch.0)?.next().is_none());
    Ok(())
}
