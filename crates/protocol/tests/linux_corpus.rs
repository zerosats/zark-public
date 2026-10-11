//! Explicit Linux qualification using public proof outputs only. No fixture
//! openings, capability secrets, signed recovery records or user wallets.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};
use zark_protocol::{
    deployment::Manifest, hash, proof::PROOF_BYTES, random32, verifier::verify_proof,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    protocol_version: u32,
    scope: String,
    manifest_sha256: String,
    assembly_sha256: String,
    crs_g1_sha256: String,
    crs_compressed_sha256: String,
    suite_id: String,
    files: BTreeMap<String, String>,
}

fn streamed_hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        ensure!(
            total <= 512 * 1024 * 1024,
            "public artifact grew beyond limit"
        );
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn checked_corpus() -> Result<(PathBuf, Manifest)> {
    let root = PathBuf::from(std::env::var("ZARK_PUBLIC_CORPUS")?).canonicalize()?;
    let raw = fs::read(root.join("corpus.json"))?;
    ensure!(
        hex::encode(hash(&[&raw])) == std::env::var("ZARK_CORPUS_SHA256")?,
        "corpus must be authenticated outside its contents"
    );
    let corpus: Corpus = serde_json::from_slice(&raw)?;
    ensure!(
        corpus.version == 2 && corpus.protocol_version == zark_protocol::handoff::PROTOCOL_VERSION,
        "corpus version"
    );
    ensure!(
        corpus.scope == "synthetic-public-relation-qualification-only",
        "corpus scope"
    );
    ensure!(
        zark_protocol::hex32(&corpus.assembly_sha256)? != [0; 32],
        "assembly provenance"
    );
    let raw = fs::read(root.join("suite/suite-manifest.json"))?;
    ensure!(
        hex::encode(hash(&[&raw])) == corpus.manifest_sha256,
        "manifest pin"
    );
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    ensure!(hex::encode(manifest.id()?) == corpus.suite_id, "suite id");
    manifest.check_artifacts(&root.join("suite"))?;
    let mut expected = vec!["suite/suite-manifest.json".to_string()];
    for pin in &manifest.roles {
        for name in ["circuit.json", "vk", "vk.json"] {
            expected.push(format!("suite/{}/{name}", pin.role));
        }
        for name in ["proof", "public_inputs"] {
            expected.push(format!("proofs/{}/{name}", pin.role));
        }
    }
    for name in ["bn254_g1.dat", "bn254_g1_compressed.dat"] {
        expected.push(format!("crs/{name}"));
    }
    expected.sort();
    ensure!(
        corpus.files.keys().eq(expected.iter()),
        "exact public corpus allowlist"
    );
    for (name, digest) in &corpus.files {
        let path = root.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= 512 * 1024 * 1024,
            "public artifact type/size"
        );
        ensure!(
            streamed_hash(&path)? == *digest,
            "public artifact changed: {name}"
        );
    }
    for (name, pin) in [
        ("bn254_g1.dat", &corpus.crs_g1_sha256),
        ("bn254_g1_compressed.dat", &corpus.crs_compressed_sha256),
    ] {
        let decoded = zark_protocol::hex32(pin)?;
        ensure!(
            decoded != [0; 32] && hex::encode(decoded) == *pin,
            "canonical operator CRS pin"
        );
        ensure!(
            corpus.files[&format!("crs/{name}")] == *pin,
            "operator CRS pin mismatch"
        );
    }
    Ok((root, manifest))
}

#[test]
#[ignore = "requires explicit authenticated public corpus export"]
fn public_corpus_has_authenticated_exact_artifacts() -> Result<()> {
    checked_corpus()?;
    Ok(())
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unpack_statement(public: &[u8], statement_len: usize) -> Result<Vec<u8>> {
    ensure!(
        public.len() == statement_len.div_ceil(31) * 32,
        "public ABI"
    );
    let mut statement = Vec::with_capacity(statement_len);
    for field in public.chunks_exact(32) {
        let width = (statement_len - statement.len()).min(31);
        // V10 right-aligns the final partial chunk. Reject padding rather than
        // discarding it, so qualification checks the exact canonical encoding.
        ensure!(
            field[..32 - width].iter().all(|byte| *byte == 0),
            "noncanonical packed public field"
        );
        statement.extend_from_slice(&field[32 - width..]);
    }
    Ok(statement)
}

#[test]
fn packed_corpus_statements_preserve_bytes_and_chunk_boundaries() -> Result<()> {
    for length in [0, 1, 30, 31, 32, 62, 63, 685, 877, 1466] {
        let statement: Vec<_> = (0..length).map(|i| (i % 256) as u8).collect();
        let public = zark_protocol::public_fields(&statement);
        ensure!(unpack_statement(&public, length)? == statement);
    }
    // Explicit boundary vector: a full field then a right-aligned one-byte tail.
    let mut public = [0; 64];
    public[1] = 1;
    public[31] = 2;
    public[63] = 3;
    let mut statement = [0; 32];
    statement[0] = 1;
    statement[30] = 2;
    statement[31] = 3;
    ensure!(unpack_statement(&public, statement.len())? == statement);
    Ok(())
}

#[test]
fn packed_corpus_statements_reject_wrong_shape_and_nonzero_padding() {
    let public = zark_protocol::public_fields(&[0; 32]);
    for length in [0, 1, 31, 63] {
        assert!(unpack_statement(&public[..length], 32).is_err());
    }
    assert!(unpack_statement(&[0; 96], 32).is_err());
    assert!(unpack_statement(&public, 31).is_err());
    assert!(unpack_statement(&public, 63).is_err());
    for padding in std::iter::once(0).chain(32..63) {
        let mut malformed = public.clone();
        malformed[padding] = 1;
        assert!(unpack_statement(&malformed, 32).is_err());
    }
}

#[test]
#[ignore = "requires Linuxamd64 pinned BB and public corpus; run check-zark-linux.sh proofs"]
fn all_six_public_proofs_pass_hardened_verifier_and_reject_changes() -> Result<()> {
    let (root, manifest) = checked_corpus()?;
    let bb = PathBuf::from(std::env::var("ZARK_TEST_BB")?);
    ensure!(
        hex::encode(hash(&[&fs::read(&bb)?]))
            == "fc9279e32471e036827c911ec9f8106ade987aec91d3e9a55cf4d33ebfb6f2cf",
        "pinned Linuxamd64 BB"
    );
    let crs = root.join("crs");
    let scratch = Scratch(
        std::env::temp_dir().join(format!("zark-public-corpus-{}", hex::encode(random32()))),
    );
    fs::DirBuilder::new().mode(0o700).create(&scratch.0)?;
    for (index, pin) in manifest.roles.iter().enumerate() {
        let directory = root.join("proofs").join(&pin.role);
        let proof = fs::read(directory.join("proof"))?;
        let public = fs::read(directory.join("public_inputs"))?;
        ensure!(proof.len() == PROOF_BYTES, "proof ABI");
        let mut statement = unpack_statement(&public, pin.public_bytes as usize)?;
        ensure!(
            statement[..4] == zark_protocol::handoff::PROTOCOL_VERSION.to_le_bytes(),
            "public version"
        );
        let key = root.join("suite").join(&pin.role).join("vk");
        verify_proof(&bb, &key, &crs, &scratch.0, &proof, &statement)
            .with_context(|| format!("valid {} rejected", pin.role))?;
        let mut corrupt = proof.clone();
        corrupt[64] ^= 1;
        ensure!(
            verify_proof(&bb, &key, &crs, &scratch.0, &corrupt, &statement).is_err(),
            "corrupt proof accepted"
        );
        let last = statement.last_mut().context("empty statement")?;
        *last ^= 1;
        ensure!(
            verify_proof(&bb, &key, &crs, &scratch.0, &proof, &statement).is_err(),
            "altered statement accepted"
        );
        *statement.last_mut().context("empty statement")? ^= 1;
        let wrong_key = root
            .join("suite")
            .join(&manifest.roles[(index + 1) % manifest.roles.len()].role)
            .join("vk");
        ensure!(
            verify_proof(&bb, &wrong_key, &crs, &scratch.0, &proof, &statement).is_err(),
            "wrong role accepted"
        );
        eprintln!(
            "{}: valid accepted; corruption, changed public input, wrong role rejected",
            pin.role
        );
    }
    ensure!(
        fs::read_dir(&scratch.0)?.next().is_none(),
        "verifier scratch not cleared"
    );
    Ok(())
}
