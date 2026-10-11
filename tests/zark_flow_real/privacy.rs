//! Synthetic predecessor canaries and path-independence assertions.
use super::*;

fn predecessor_count(label: &str) -> Result<usize> {
    OWNERS
        .windows(2)
        .position(|pair| label == format!("{}-{}", pair[0], pair[1]))
        .map(|index| index + 1)
        .context("privacy test transfer")
}

/// Test-only canaries are read from this fresh run's synthetic predecessor
/// records. They are never passed to receiver code, proof inputs, or reports.
pub(super) struct PrivacyCanaries {
    pub(super) needles: Zeroizing<Vec<Vec<u8>>>,
    pub(super) values: usize,
}
impl PrivacyCanaries {
    pub(super) fn capture(run: &Path, label: &str) -> Result<Self> {
        let owners = &OWNERS[..predecessor_count(label)?];
        let mut result = Self {
            needles: Zeroizing::new(Vec::new()),
            values: 0,
        };
        for (index, owner) in owners.iter().enumerate() {
            let directory = run.join(owner);
            let marker = directory.join("privacy-canary.txt");
            if !marker.exists() {
                write_private(
                    &marker,
                    format!("PRIVATE-PREDECESSOR-{}", hex::encode(random32())).as_bytes(),
                )?;
            }
            result.add(&fs::read(marker)?)?;
            let bytes = Zeroizing::new(fs::read(
                directory.join("own-recovery/recovery-draft.json"),
            )?);
            let record: Value = serde_json::from_slice(&bytes)?;
            for key in [
                "user_secret",
                "payout_secret",
                "alpha",
                "beta",
                "backup_salt",
                "nonce_salt",
            ] {
                let value: Vec<u8> = serde_json::from_value(record[key].clone())?;
                ensure!(value.len() == 32, "synthetic privacy secret shape");
                result.add(&value)?;
            }
            result.add(&hex::decode(
                record["draft_server"]
                    .as_str()
                    .context("synthetic predecessor server point")?,
            )?)?;
            let raw = hex::decode(
                record["state"]["transaction"]
                    .as_str()
                    .context("synthetic predecessor completed recovery")?,
            )?;
            let transaction: Transaction = deserialize(&raw)?;
            result.add(&raw)?;
            result.add(&transaction.output[0].script_pubkey.as_bytes()[2..])?;
            let sender = run
                .join(format!("{owner}-to-{}", OWNERS[index + 1]))
                .join("sender-operation.json");
            let bytes = Zeroizing::new(fs::read(sender)?);
            let record: Value = serde_json::from_slice(&bytes)?;
            for key in ["capability", "session", "server_salt"] {
                let value: Vec<u8> = serde_json::from_value(record[key].clone())?;
                result.add(&value)?;
            }
            for key in ["mask", "salt"] {
                let value: Vec<u8> = serde_json::from_value(record["mask"][key].clone())?;
                result.add(&value)?;
            }
            let encoded = Zeroizing::new(hex::decode(
                record["certificate"]
                    .as_str()
                    .context("predecessor certificate")?,
            )?);
            result.add(&encoded)?;
            let certificate =
                zark_protocol::certificate::OwnerCertificate::decode_private(&encoded)?;
            match &certificate {
                zark_protocol::certificate::OwnerCertificate::OriginIssued {
                    authorization,
                    proof,
                    partial,
                    activation_partial,
                    server_salt,
                    origin_signature,
                } => {
                    for bytes in [
                        authorization.as_slice(),
                        proof.as_slice(),
                        partial.as_slice(),
                        activation_partial.as_slice(),
                        server_salt.as_slice(),
                        origin_signature.as_slice(),
                    ] {
                        result.add(bytes)?;
                    }
                }
                zark_protocol::certificate::OwnerCertificate::TransferIssued {
                    authorization,
                    proof,
                    partial,
                    server_salt,
                } => {
                    result.add(authorization)?;
                    result.add(proof)?;
                    result.add(partial)?;
                    result.add(server_salt)?;
                }
            }
        }
        Ok(result)
    }
    pub(super) fn add(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(bytes.len() >= 32, "privacy canary too short");
        self.needles.push(bytes.to_vec());
        self.needles.push(hex::encode(bytes).into_bytes());
        self.needles.push(serde_json::to_vec(bytes)?);
        self.values += 1;
        Ok(())
    }
    pub(super) fn bytes(&self, bytes: &[u8], kind: &str) -> Result<()> {
        for needle in self.needles.iter() {
            ensure!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "predecessor privacy canary found in {kind}"
            );
        }
        Ok(())
    }
    pub(super) fn document(&self, value: &Value, kind: &str) -> Result<()> {
        self.bytes(&serde_json::to_vec(value)?, kind)
    }
    /// Inspect durable native records and all actual TOML proving inputs. Proof
    /// bytes are externally verified, not treated as a plaintext privacy test.
    pub(super) fn artifacts(&self, path: &Path) -> Result<usize> {
        let mut checked = 0;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let meta = fs::symlink_metadata(entry.path())?;
            ensure!(
                !meta.file_type().is_symlink(),
                "recipient artifact unexpectedly links another directory"
            );
            if meta.is_dir() {
                checked += self.artifacts(&entry.path())?;
                continue;
            }
            if !matches!(
                entry.path().extension().and_then(|s| s.to_str()),
                Some("json" | "toml" | "txt")
            ) {
                continue;
            }
            ensure!(
                meta.len() <= 4 * 1024 * 1024,
                "recipient text artifact exceeds privacy inspection bound"
            );
            let bytes = Zeroizing::new(fs::read(entry.path())?);
            self.bytes(&bytes, "recipient artifact")?;
            match entry.path().extension().and_then(|s| s.to_str()) {
                Some("json") => self.document(
                    &serde_json::from_slice::<Value>(&bytes)?,
                    "recipient JSON record",
                )?,
                Some("toml") => {
                    let document: toml::Value = toml::from_str(std::str::from_utf8(&bytes)?)?;
                    self.document(&serde_json::to_value(document)?, "recipient proving input")?;
                }
                _ => (),
            }
            checked += 1;
        }
        Ok(checked)
    }
}

/// This removes the predecessor files from every path the wallet recorded. The
/// orchestrator still owns the machine/process, so this is path-independence
/// qualification, not an OS sandbox or an independent crypto privacy proof.
pub(super) struct HiddenPredecessors {
    pub(super) moves: Vec<(PathBuf, PathBuf)>,
}
impl HiddenPredecessors {
    pub(super) fn hide(run: &Path, label: &str) -> Result<Self> {
        let mut names = Vec::new();
        for index in 0..predecessor_count(label)? {
            let owner = OWNERS[index];
            names.extend([
                owner.to_owned(),
                format!("{owner}-to-{}", OWNERS[index + 1]),
                format!("proofs/{owner}"),
            ]);
            if index > 0 {
                names.push(format!("{owner}-invitation"));
            }
        }
        let holding = run.join(format!("privacy-held-{}", hex::encode(random32())));
        private_dir(&holding)?;
        let mut result = Self { moves: Vec::new() };
        for (i, name) in names.iter().enumerate() {
            let source = run.join(name);
            let target = holding.join(format!("directory-{i}"));
            ensure!(source.is_dir(), "predecessor privacy source missing");
            fs::rename(&source, &target)?;
            result.moves.push((source, target));
        }
        result.require_hidden()?;
        Ok(result)
    }
    pub(super) fn require_hidden(&self) -> Result<()> {
        for (source, saved) in &self.moves {
            ensure!(
                fs::symlink_metadata(source)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                    && saved.is_dir(),
                "predecessor path became available during recipient proof construction"
            );
        }
        Ok(())
    }
    pub(super) fn restore(&mut self) -> Result<()> {
        while let Some((source, saved)) = self.moves.last() {
            ensure!(
                fs::symlink_metadata(source)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "cannot restore predecessor over another directory"
            );
            fs::rename(saved, source)?;
            self.moves.pop();
        }
        Ok(())
    }
}
impl Drop for HiddenPredecessors {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(super) fn check_peer_schema(
    invitation: &LocalInvitation,
    context: &OfferContext,
    offer: &[u8],
    canaries: &PrivacyCanaries,
) -> Result<()> {
    canaries.bytes(offer, "encrypted peer envelope")?;
    let decrypted = invitation.decrypt_offer(context, offer)?;
    let record: Value = serde_json::from_slice(decrypted.plaintext())?;
    let keys = [
        "schema",
        "version",
        "predecessor",
        "token",
        "handover",
        "proof",
        "backing",
        "activation_input",
        "activation",
        "masked_share",
        "masked_share_salt",
        "bridge_salt",
        "old_delay",
        "claim_salt",
    ];
    let map = record.as_object().context("peer offer object")?;
    ensure!(
        map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)),
        "peer offer includes an unexpected predecessor record"
    );
    for field in ["backing", "activation_input"] {
        let common = record[field]
            .as_object()
            .context("peer common Bitcoin record")?;
        let expected = [
            "deployment",
            "id",
            "funding_salt",
            "internal_point",
            "txid",
            "vout",
            "amount",
        ];
        ensure!(
            common.len() == expected.len() && expected.iter().all(|key| common.contains_key(*key)),
            "unexpected private field in common Bitcoin record"
        );
    }
    canaries.document(&record, "decrypted peer offer")
}

pub(super) fn check_own_export(
    directory: &Path,
    context: &TransferContext,
    own_recovery: &Transaction,
    canaries: &PrivacyCanaries,
) -> Result<()> {
    let path = directory.join("portable-recovery.json");
    let portable = PortableRecovery::read(&path, &context.deployment, &context.coin)?;
    let [activation, recovery] = portable.transactions()?;
    ensure!(
        recovery == *own_recovery
            && recovery.input[0].previous_output.txid == activation.compute_txid(),
        "portable export is not exactly common activation plus recipient's own recovery"
    );
    let bytes = Zeroizing::new(fs::read(&path)?);
    let record: Value = serde_json::from_slice(&bytes)?;
    let keys = [
        "schema",
        "version",
        "protocol_version",
        "deployment",
        "coin",
        "activation_parent",
        "activation",
        "backing",
        "recovery",
        "fee_sat",
        "relative_blocks",
        "payout_secret",
    ];
    let map = record.as_object().context("portable record")?;
    ensure!(
        map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)),
        "portable export contains unexpected history or owner fields"
    );
    canaries.document(&record, "recipient portable recovery")
}
