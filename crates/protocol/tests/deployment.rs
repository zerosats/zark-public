use anyhow::Result;
use k256::schnorr::SigningKey;
use std::{fs, path::PathBuf};
use zark_protocol::{
    deployment::{Deployment, Manifest, ROLE_NAMES, RolePin},
    hash,
    network::{Network, REGTEST_GENESIS},
    random32,
};

struct TestDirectory(PathBuf);
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Result<(TestDirectory, Manifest, Deployment)> {
    let directory = TestDirectory(
        std::env::temp_dir().join(format!("zark-manifest-{}", hex::encode(random32()))),
    );
    fs::create_dir(&directory.0)?;
    let lengths = zark_protocol::deployment::PUBLIC_BYTES;
    let mut roles = Vec::new();
    for (i, name) in ROLE_NAMES.iter().enumerate() {
        // Synthetic encoding fixtures only, never proof verification keys.
        let mut fields = vec![[0u8; 32]; 115];
        fields[0][31] = 20;
        fields[1][28..].copy_from_slice(&(lengths[i].div_ceil(31) + 8u32).to_be_bytes());
        fields[2][31] = (i + 1) as u8;
        let binary: Vec<u8> = fields.iter().flatten().copied().collect();
        let recursive_hash = hex::encode(fields[2]);
        let metadata = serde_json::to_vec(
            &serde_json::json!({"vk":fields.iter().map(|f|format!("0x{}",hex::encode(f))).collect::<Vec<_>>(),
            "hash":format!("0x{recursive_hash}"),"bb_version":"5.2.0","scheme":"ultra_honk"}),
        )?;
        let path = directory.0.join(name);
        fs::create_dir(&path)?;
        let compiled = format!("synthetic ABI fixture for {name}; not executable bytecode");
        fs::write(path.join("circuit.json"), &compiled)?;
        fs::write(path.join("vk"), &binary)?;
        fs::write(path.join("vk.json"), &metadata)?;
        roles.push(RolePin {
            role: name.to_string(),
            compiled_artifact_sha256: hex::encode(hash(&[compiled.as_bytes()])),
            vk_sha256: hex::encode(hash(&[&binary])),
            recursive_hash,
            metadata_sha256: hex::encode(hash(&[&metadata])),
            public_bytes: lengths[i],
        });
    }
    let manifest = Manifest {
        protocol_version: 10,
        noir_version: "1.0.0-beta.25".into(),
        bb_version: "5.2.0".into(),
        verifier_target: "noir-recursive".into(),
        roles,
    };
    let deployment = Deployment {
        protocol_version: 10,
        signer_protocol_version: zark_protocol::deployment::SIGNER_PROTOCOL_VERSION,
        network: Network::Regtest,
        genesis_hash: REGTEST_GENESIS.into(),
        signet_challenge: String::new(),
        initial_delay: 480,
        gap: 60,
        margin: 6,
        origin_key: hex::encode(SigningKey::from_bytes(&[1; 32])?.verifying_key().to_bytes()),
        control_key: hex::encode(SigningKey::from_bytes(&[2; 32])?.verifying_key().to_bytes()),
        suite: hex::encode(manifest.id()?),
    };
    Ok((directory, manifest, deployment))
}

#[test]
fn deployment_binds_suite_roles_policy_origin_control_and_exact_chain() -> Result<()> {
    let (_directory, manifest, deployment) = fixture()?;
    let id = deployment.id()?;
    deployment.lineage_policy(&manifest)?;
    for case in 0..6 {
        let mut changed = deployment.clone();
        match case {
            0 => changed.initial_delay += 1,
            1 => changed.gap += 1,
            2 => changed.margin += 1,
            3 => {
                changed.origin_key =
                    hex::encode(SigningKey::from_bytes(&[3; 32])?.verifying_key().to_bytes())
            }
            4 => {
                changed.control_key =
                    hex::encode(SigningKey::from_bytes(&[4; 32])?.verifying_key().to_bytes())
            }
            _ => changed.suite = "22".repeat(32),
        }
        assert_ne!(changed.id()?, id);
    }
    let mut signet = deployment.clone();
    signet.network = Network::CustomSignet;
    signet.genesis_hash = "22".repeat(32);
    signet.signet_challenge = "51".into();
    let signet_id = signet.id()?;
    assert_ne!(signet_id, id);
    signet.signet_challenge = "52".into();
    assert_ne!(signet.id()?, signet_id);
    signet.signet_challenge.clear();
    assert!(signet.id().is_err());
    let mut changed = deployment.clone();
    changed.protocol_version = 7;
    assert!(changed.id().is_err());
    changed = deployment;
    changed.control_key = changed.origin_key.clone();
    assert!(changed.id().is_err());
    let mut old = manifest.clone();
    old.roles.truncate(5);
    assert!(old.validate().is_err());
    let mut swapped = manifest.clone();
    swapped.roles.swap(4, 2);
    assert!(swapped.validate().is_err());
    let mut changed = manifest.clone();
    changed.roles[4].public_bytes = 420;
    assert!(changed.validate().is_err());
    changed = manifest.clone();
    changed.roles[4].recursive_hash = "ff".repeat(32);
    assert!(changed.validate().is_err());
    changed = manifest.clone();
    changed.roles[4].vk_sha256 = "33".repeat(32);
    assert_ne!(changed.id()?, manifest.id()?);
    let mut json = serde_json::to_value(manifest)?;
    json["skip_lineage"] = true.into();
    assert!(serde_json::from_value::<Manifest>(json).is_err());
    Ok(())
}

#[test]
fn signer_semantics_require_a_fresh_explicit_deployment() -> Result<()> {
    let (_directory, _, deployment) = fixture()?;
    let encoded = serde_json::to_value(&deployment)?;
    let restored: Deployment = serde_json::from_value(encoded.clone())?;
    assert_eq!(restored.id()?, deployment.id()?);
    let mut legacy = encoded;
    legacy
        .as_object_mut()
        .unwrap()
        .remove("signer_protocol_version");
    assert!(serde_json::from_value::<Deployment>(legacy).is_err());
    for version in [0, 1, 2, 3, u32::MAX] {
        let mut incompatible = deployment.clone();
        incompatible.signer_protocol_version = version;
        assert!(incompatible.id().is_err());
    }
    // The old deployment digest must never be silently reinterpreted as the
    // alpha semantics, even when every previous field is unchanged.
    let legacy_id = hash(&[
        b"ZARK/private-deployment/v1",
        &8u32.to_le_bytes(),
        &[0],
        &zark_protocol::hex32(&deployment.genesis_hash)?,
        &0u32.to_le_bytes(),
        &[],
        &zark_protocol::handoff::policy_commitment(deployment.schedule())?,
        &zark_protocol::hex32(&deployment.origin_key)?,
        &zark_protocol::hex32(&deployment.control_key)?,
        &zark_protocol::hex32(&deployment.suite)?,
    ]);
    assert_ne!(deployment.id()?, legacy_id);
    Ok(())
}

#[test]
fn artifact_pins_require_matching_binary_metadata_and_public_abi() -> Result<()> {
    let (directory, mut manifest, _) = fixture()?;
    assert_eq!(manifest.check_artifacts(&directory.0)?.len(), 6);
    let path = directory.0.join("exit_from_transfer/vk");
    let mut bytes = fs::read(&path)?;
    bytes[100] ^= 1;
    fs::write(&path, &bytes)?;
    assert!(manifest.check_artifacts(&directory.0).is_err());
    manifest.roles[5].vk_sha256 = hex::encode(hash(&[&bytes]));
    assert!(
        manifest.check_artifacts(&directory.0).is_err(),
        "updated binary pin cannot disguise mismatched recursive metadata"
    );
    Ok(())
}
