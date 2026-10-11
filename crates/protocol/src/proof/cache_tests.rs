use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn cache_requires_exact_proof_statement_role_and_rechecked_artifacts() -> Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "zark-verification-cache-{}",
        hex::encode(crate::random32())
    ));
    fs::create_dir(&dir)?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let bb = dir.join("bb");
    let vk = dir.join("vk");
    // A synthetic verifier records invocations and can reject without changing
    // its pinned executable. No real proof or wallet state is used here.
    fs::write(
        &bb,
        format!(
            "#!/bin/sh\necho call >> '{}/calls'\ntest ! -f '{}/reject'\n",
            dir.display(),
            dir.display()
        ),
    )?;
    fs::set_permissions(&bb, fs::Permissions::from_mode(0o700))?;
    fs::write(&vk, b"test-vk")?;
    let pin = |path: &Path| -> Result<ArtifactPin> {
        Ok(ArtifactPin {
            path: path.into(),
            sha256: hash(&[&fs::read(path)?]),
        })
    };
    let make = || {
        PinnedVerifier::new(
            [1; 32],
            pin(&bb)?,
            dir.clone(),
            [
                (Relation::SenderFromOrigin, pin(&vk)?),
                (Relation::SenderFromTransfer, pin(&vk)?),
            ],
        )
    };
    let verifier = make()?;
    let proof = vec![1; PROOF_BYTES];
    let verify = |v: &PinnedVerifier, role, statement: &[u8], proof: &[u8]| {
        v.verify(role, &[1; 32], statement, proof, &dir)
    };
    verify(&verifier, Relation::SenderFromOrigin, b"one", &proof)?;
    fs::write(dir.join("reject"), b"")?;
    verify(&verifier, Relation::SenderFromOrigin, b"one", &proof)?;
    assert_eq!(fs::read_to_string(dir.join("calls"))?.lines().count(), 1);
    assert!(verify(&verifier, Relation::SenderFromOrigin, b"two", &proof).is_err());
    assert!(verify(&verifier, Relation::SenderFromTransfer, b"one", &proof).is_err());
    assert!(
        verify(
            &verifier,
            Relation::SenderFromOrigin,
            b"one",
            &vec![2; PROOF_BYTES]
        )
        .is_err()
    );
    assert!(verify(&make()?, Relation::SenderFromOrigin, b"one", &proof).is_err());
    assert!(
        verifier
            .verify(Relation::SenderFromOrigin, &[2; 32], b"one", &proof, &dir)
            .is_err()
    );
    assert!(
        verify(
            &verifier,
            Relation::SenderFromOrigin,
            b"one",
            &proof[..PROOF_BYTES - 1]
        )
        .is_err()
    );
    // Failed verification is not cached.
    fs::remove_file(dir.join("reject"))?;
    verify(&verifier, Relation::SenderFromOrigin, b"two", &proof)?;
    // Even a previously successful cache entry cannot bypass changed pins.
    fs::write(&vk, b"changed-vk")?;
    assert!(verify(&verifier, Relation::SenderFromOrigin, b"one", &proof).is_err());
    fs::write(&vk, b"test-vk")?;
    // Reload is explicit after an asset changes, even if its bytes are restored.
    let verifier = make()?;
    verify(&verifier, Relation::SenderFromOrigin, b"one", &proof)?;
    fs::write(&bb, b"#!/bin/sh\nexit 0\n")?;
    assert!(verify(&verifier, Relation::SenderFromOrigin, b"one", &proof).is_err());
    Ok(())
}
