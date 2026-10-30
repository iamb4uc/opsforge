use crate::case::EvidenceFile;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path::Path,
};

#[derive(Debug, Default, Serialize)]
pub struct Verification {
    pub source_issues: Vec<String>,
    pub report_issues: Vec<String>,
    pub unverified: Vec<String>,
}

impl Verification {
    pub fn exit_code(&self) -> i32 {
        i32::from(
            !self.source_issues.is_empty()
                || !self.report_issues.is_empty()
                || !self.unverified.is_empty(),
        )
    }
    fn issue(&mut self, path: &str, reason: &str) {
        let issues = if generated(path) {
            &mut self.report_issues
        } else {
            &mut self.source_issues
        };
        issues.push(format!("{path}: {reason}"));
    }
}

fn generated(path: &str) -> bool {
    path.starts_with("dashboard/")
        || matches!(
            path,
            "report.md" | "summary.txt" | "findings.json" | "normalized/findings.json"
        )
}

fn valid_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.contains(['\\', ':', '\n', '\r', '\0'])
        || path.split('/').any(|s| matches!(s, "" | "." | ".."))
    {
        bail!("unsafe case-relative path: {path:?}");
    }
    Ok(())
}

fn valid_hash(hash: &str) -> Result<()> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid SHA-256 digest");
    }
    Ok(())
}

fn digest(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        size = size
            .checked_add(u64::try_from(count)?)
            .context("file size overflow")?;
    }
    Ok((format!("{:x}", hash.finalize()), size))
}

/// Verify a quiescent saved case without writing to it. This checks consistency,
/// not authenticity; callers must keep the directory unchanged during the read.
pub fn verify(root: &Path) -> Result<Verification> {
    if !fs::symlink_metadata(root)?.is_dir() {
        bail!("case must be a real directory");
    }
    let mut files = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        let kind = entry.file_type();
        if !kind.is_file() && !kind.is_dir() {
            bail!(
                "case contains a link or special file: {}",
                entry.path().display()
            );
        }
        if kind.is_file() {
            let path = entry
                .path()
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF-8 case path")?
                .to_owned();
            valid_path(&path)?;
            files.insert(path);
        }
    }
    let mut result = Verification::default();
    let mut raw = BTreeSet::new();
    for line in
        BufReader::new(File::open(root.join("manifest.jsonl")).context("opening manifest")?).lines()
    {
        let row: EvidenceFile = serde_json::from_str(&line?).context("invalid manifest row")?;
        valid_path(&row.path)?;
        valid_hash(&row.sha256)?;
        if !row.path.starts_with("raw/") || !raw.insert(row.path.clone()) {
            bail!("invalid or duplicate raw manifest path: {}", row.path);
        }
        if !files.contains(&row.path) {
            result.issue(&row.path, "missing");
            continue;
        }
        match digest(&root.join(&row.path)) {
            Ok((hash, size)) if hash.eq_ignore_ascii_case(&row.sha256) && size == row.bytes => {}
            Ok(_) => result.issue(&row.path, "hash or size mismatch"),
            Err(error) => result.issue(&row.path, &format!("unreadable: {error}")),
        }
    }
    for path in files.iter().filter(|p| p.starts_with("raw/")) {
        if !raw.contains(path) {
            result.issue(path, "not recorded in manifest");
        }
    }
    let mut recorded = BTreeSet::new();
    if files.contains("checksums.sha256") {
        for line in BufReader::new(File::open(root.join("checksums.sha256"))?).lines() {
            let line = line?;
            let (hash, path) = line.split_once("  ").context("malformed checksum record")?;
            valid_hash(hash)?;
            valid_path(path)?;
            if path == "checksums.sha256" || !recorded.insert(path.to_owned()) {
                bail!("invalid or duplicate checksum path: {path}");
            }
            if !files.contains(path) {
                result.issue(path, "missing");
                continue;
            }
            match digest(&root.join(path)) {
                Ok((actual, _)) if actual.eq_ignore_ascii_case(hash) => {}
                Ok(_) => result.issue(path, "checksum mismatch"),
                Err(error) => result.issue(path, &format!("unreadable: {error}")),
            }
        }
        for path in &files {
            if path != "checksums.sha256" && !recorded.contains(path) {
                result.issue(path, "not recorded in checksums");
            }
        }
    } else {
        result
            .unverified
            .push("final case checksums are missing".into());
    }
    for path in ["normalized/events.jsonl", "normalized/coverage.jsonl"] {
        if !files.contains(path) {
            result.issue(path, "missing required input");
            continue;
        }
        for (index, line) in BufReader::new(File::open(root.join(path))?)
            .lines()
            .enumerate()
        {
            let line = line?;
            let valid = if path.ends_with("events.jsonl") {
                serde_json::from_str::<crate::case::Event>(&line).is_ok()
            } else {
                serde_json::from_str::<crate::case::Coverage>(&line).is_ok()
            };
            if !valid {
                result.issue(path, &format!("invalid JSONL row {}", index + 1));
            }
        }
    }
    Ok(result)
}
