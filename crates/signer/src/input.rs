//! Bounds for operator-supplied files, checked against bytes actually read.
use anyhow::{Context, Result, ensure};
use std::{fs::File, io::Read, path::Path};

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "input file exceeds byte limit or is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit.checked_add(1).context("input size limit")?)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "input file exceeds byte limit");
    Ok(bytes)
}
