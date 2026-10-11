use super::*;
use std::{
    fs::FileTimes,
    os::unix::fs::{PermissionsExt, symlink},
};
use zark_protocol::{assets::sha256_bounded, hash, random32};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("work")
            .join(format!("asset-auth-{}", hex::encode(random32())));
        fs::create_dir_all(&root)?;
        fs::write(root.join("tool"), b"honest")?;
        // A newly created six-byte file can still be in the current Linux
        // filesystem clock tick. Ensure the later edit changes its metadata.
        crate::test_support::after_filesystem_tick(&root.join("tool"))?;
        Ok(Self(root))
    }
    fn tool(&self) -> PathBuf {
        self.0.join("tool")
    }
    fn authenticate(&self) -> Result<AuthenticatedAssets> {
        AuthenticatedAssets::authenticate(&[self.tool()], || {
            ensure!(
                sha256_bounded(&self.tool(), 1024)? == hash(&[b"honest"]),
                "test asset pin mismatch"
            );
            Ok(())
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn unchanged_assets_recheck_but_a_new_prover_requires_correct_bytes() -> Result<()> {
    let fixture = Fixture::new()?;
    let assets = fixture.authenticate()?;
    assets.check()?;
    assets.check()?;
    fs::write(fixture.tool(), b"mutant")?;
    assert!(fixture.authenticate().is_err());
    Ok(())
}

#[test]
fn same_length_edit_with_restored_mtime_invalidates_authentication() -> Result<()> {
    let fixture = Fixture::new()?;
    let path = fixture.tool();
    let before = fs::metadata(&path)?.modified()?;
    let assets = fixture.authenticate()?;
    fs::write(&path, b"mutant")?;
    fs::File::open(&path)?.set_times(FileTimes::new().set_modified(before))?;
    assert_eq!(fs::metadata(&path)?.modified()?, before);
    assert!(assets.check().is_err());
    // Restoring the original content does not silently refresh authentication.
    fs::write(&path, b"honest")?;
    assert!(assets.check().is_err());
    fixture.authenticate()?.check()?;
    Ok(())
}

#[test]
fn atomic_replacement_and_permission_changes_invalidate_authentication() -> Result<()> {
    let fixture = Fixture::new()?;
    let path = fixture.tool();
    let assets = fixture.authenticate()?;
    fs::write(fixture.0.join("replacement"), b"honest")?;
    fs::rename(fixture.0.join("replacement"), &path)?;
    assert!(assets.check().is_err());
    let assets = fixture.authenticate()?;
    let mode = fs::metadata(&path)?.permissions().mode();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode ^ 0o100))?;
    assert!(assets.check().is_err());
    Ok(())
}

#[test]
fn configured_symlink_retarget_is_rejected_and_directories_are_not_assets() -> Result<()> {
    let fixture = Fixture::new()?;
    let link = fixture.0.join("link");
    symlink("tool", &link)?;
    let assets = AuthenticatedAssets::authenticate(std::slice::from_ref(&link), || Ok(()))?;
    assets.check()?;
    fs::write(fixture.0.join("replacement"), b"honest")?;
    fs::remove_file(&link)?;
    symlink("replacement", &link)?;
    assert!(assets.check().is_err());
    assert!(
        AuthenticatedAssets::authenticate(std::slice::from_ref(&fixture.0), || Ok(())).is_err()
    );
    Ok(())
}

#[test]
fn mutation_during_full_validation_is_not_cached_as_authenticated() -> Result<()> {
    let fixture = Fixture::new()?;
    let result = AuthenticatedAssets::authenticate(&[fixture.tool()], || {
        assert_eq!(sha256_bounded(&fixture.tool(), 1024)?, hash(&[b"honest"]));
        fs::write(fixture.tool(), b"mutant")?;
        Ok(())
    });
    assert!(result.is_err());
    Ok(())
}
