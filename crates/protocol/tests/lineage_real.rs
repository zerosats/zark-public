//! Explicit v9 real-proof qualification; historical v8 fixtures are not accepted.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeSet, fs, path::PathBuf};
use zark_protocol::{
    assets::read_bounded,
    certificate::PredecessorKind,
    deployment::{Deployment, Manifest},
    deposit::DepositBinding,
    hex32,
    lineage::{IssuanceBinding, LineageHandoverBinding},
    proof::{ArtifactPin, PROOF_BYTES},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    role: String,
    statement: String,
    proof: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    deployment: Deployment,
    manifest: Manifest,
    keys: PathBuf,
    bb: PathBuf,
    bb_sha256: String,
    crs: PathBuf,
    scratch: PathBuf,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    groups: Vec<Group>,
}

#[test]
#[ignore = "requires authenticated ZARK_PLAN_C_PROOF_FIXTURE with fresh v9 history/transfer/exit proofs"]
fn native_verifier_accepts_full_private_lineage_and_rejects_substitution() -> Result<()> {
    let fixture: Fixture = serde_json::from_slice(&fs::read(
        std::env::var_os("ZARK_PLAN_C_PROOF_FIXTURE")
            .context("missing authenticated fixture path")?,
    )?)?;
    let roles: BTreeSet<_> = fixture
        .groups
        .iter()
        .flat_map(|group| group.cases.iter().map(|c| c.role.as_str()))
        .collect();
    ensure!(
        roles
            == [
                "deposit_authorization",
                "sender_from_origin",
                "sender_from_transfer",
                "receiver_authorization",
                "exit_from_origin",
                "exit_from_transfer"
            ]
            .into_iter()
            .collect(),
        "qualification must cover each history entry point"
    );
    for group in fixture.groups {
        let verifier = group.deployment.verifier(
            &group.manifest,
            &group.keys,
            ArtifactPin {
                path: group.bb,
                sha256: hex32(&group.bb_sha256)?,
            },
            &group.crs,
        )?;
        for case in group.cases {
            let statement = hex::decode(case.statement)?;
            let proof = read_bounded(&case.proof, PROOF_BYTES)?;
            let check = |p: &[u8]| -> Result<()> {
                match case.role.as_str() {
                    "deposit_authorization" => {
                        verifier.deposit_authorization(
                            &DepositBinding::decode(&statement)?,
                            p,
                            &group.scratch,
                        )?;
                    }
                    "receiver_authorization" => {
                        verifier.receiver_authorization(
                            &IssuanceBinding::decode(&statement)?,
                            p,
                            &group.scratch,
                        )?;
                    }
                    "sender_from_origin" | "sender_from_transfer" => {
                        verifier.sender_handover(
                            if case.role.ends_with("origin") {
                                PredecessorKind::Origin
                            } else {
                                PredecessorKind::Transfer
                            },
                            &LineageHandoverBinding::decode(&statement)?,
                            p,
                            &group.scratch,
                        )?;
                    }
                    "exit_from_origin" | "exit_from_transfer" => {
                        verifier.cooperative_exit(
                            if case.role.ends_with("origin") {
                                PredecessorKind::Origin
                            } else {
                                PredecessorKind::Transfer
                            },
                            &IssuanceBinding::decode(&statement)?,
                            p,
                            &group.scratch,
                        )?;
                    }
                    _ => anyhow::bail!("unknown role"),
                }
                Ok(())
            };
            ensure!(proof.len() == PROOF_BYTES, "proof length");
            check(&proof)?;
            let mut substituted = proof;
            substituted[64] ^= 1;
            ensure!(
                check(&substituted).is_err(),
                "substituted real proof accepted"
            );
        }
    }
    Ok(())
}
