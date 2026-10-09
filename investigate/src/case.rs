use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Recorded,
    Observed,
    Lead,
    Unattributed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Event {
    pub timestamp: Option<String>,
    pub source: String,
    pub kind: String,
    pub application: Option<String>,
    pub user: Option<String>,
    pub destination: Option<String>,
    pub detail: String,
    pub evidence: String,
    pub level: EvidenceLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer: Option<Transfer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_line: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transfer {
    pub direction: String,
    pub status: String,
    pub protocol: String,
    pub perspective: String,
    pub file: Option<String>,
    pub target: Option<String>,
    pub peer: Option<String>,
    pub bytes: Option<u64>,
    pub bytes_basis: String,
    pub method: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Collected,
    Empty,
    Unavailable,
    Denied,
    Unsupported,
    Failed,
    Skipped,
    Cancelled,
}

impl CoverageState {
    pub(crate) fn from_io(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => Self::Unavailable,
            std::io::ErrorKind::PermissionDenied => Self::Denied,
            std::io::ErrorKind::Interrupted => Self::Cancelled,
            _ => Self::Failed,
        }
    }

    pub(crate) fn from_error(error: &anyhow::Error) -> Self {
        error
            .downcast_ref::<std::io::Error>()
            .map_or(Self::Failed, Self::from_io)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Coverage {
    pub source: String,
    pub state: CoverageState,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceFile {
    pub source: String,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub acquired_at: String,
}

pub struct Case {
    pub root: PathBuf,
    events: BufWriter<File>,
    coverage: BufWriter<File>,
    manifest: BufWriter<File>,
}

fn private_dir(path: &Path) -> Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("creating {}", path.display()))?;
    Ok(())
}

fn append_file(path: &Path) -> Result<BufWriter<File>> {
    Ok(BufWriter::new(
        OpenOptions::new().create_new(true).write(true).open(path)?,
    ))
}

fn validate_root_output_base(base: &Path) -> Result<()> {
    for ancestor in base.ancestors() {
        let metadata = fs::metadata(ancestor)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            anyhow::bail!(
                "case output must be below root-owned directories without group or world write access: {}",
                ancestor.display()
            );
        }
    }
    Ok(())
}

impl Case {
    pub fn new(output_base: &Path) -> Result<Self> {
        fs::create_dir_all(output_base)
            .with_context(|| format!("creating {}", output_base.display()))?;
        let base = fs::canonicalize(output_base)?;
        let uid = std::process::Command::new("id").arg("-u").output()?;
        if !uid.status.success() {
            anyhow::bail!("id -u failed");
        }
        if uid.stdout == b"0\n" {
            validate_root_output_base(&base)?;
        }
        let host = std::process::Command::new("hostname")
            .output()
            .context("reading hostname")?;
        let host = String::from_utf8_lossy(&host.stdout)
            .trim()
            .chars()
            .filter(|character| {
                character.is_ascii_alphanumeric() || *character == '-' || *character == '_'
            })
            .collect::<String>();
        let stamp = jiff::Timestamp::now().strftime("%Y%m%d-%H%M%S");
        let name = format!(
            "{}-investigate-{stamp}",
            if host.is_empty() { "unknown" } else { &host }
        );
        let root = (0..1_000)
            .find_map(|attempt| {
                let candidate = base.join(if attempt == 0 {
                    name.clone()
                } else {
                    format!("{name}-{attempt}")
                });
                match DirBuilder::new().mode(0o700).create(&candidate) {
                    Ok(()) => Some(Ok(candidate)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .context("could not reserve a unique case directory")??;
        for part in ["raw", "normalized", "dashboard"] {
            private_dir(&root.join(part))?;
        }
        let events = append_file(&root.join("normalized/events.jsonl"))?;
        let coverage = append_file(&root.join("normalized/coverage.jsonl"))?;
        let manifest = append_file(&root.join("manifest.jsonl"))?;
        Ok(Self {
            root,
            events,
            coverage,
            manifest,
        })
    }

    pub fn event(&mut self, event: &Event) -> Result<()> {
        crate::runtime::check_cancelled()?;
        serde_json::to_writer(&mut self.events, event)?;
        self.events.write_all(b"\n")?;
        self.events.flush()?;
        Ok(())
    }

    pub fn coverage(&mut self, row: &Coverage) -> Result<()> {
        serde_json::to_writer(&mut self.coverage, row)?;
        self.coverage.write_all(b"\n")?;
        self.coverage.flush()?;
        Ok(())
    }

    pub fn copy_evidence(&mut self, source: &Path, name: &str) -> Result<PathBuf> {
        if name.contains('/') || name == "." || name == ".." {
            anyhow::bail!("invalid evidence name");
        }
        let destination = self.root.join("raw").join(name);
        let mut input = BufReader::new(
            File::open(source).with_context(|| format!("opening {}", source.display()))?,
        );
        let mut output = BufWriter::new(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&destination)?,
        );
        let mut hash = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            crate::runtime::check_cancelled()?;
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count])?;
            hash.update(&buffer[..count]);
            bytes = bytes.saturating_add(u64::try_from(count)?);
        }
        output.flush()?;
        let row = EvidenceFile {
            source: source.display().to_string(),
            path: format!("raw/{name}"),
            bytes,
            sha256: format!("{:x}", hash.finalize()),
            acquired_at: jiff::Timestamp::now().to_string(),
        };
        serde_json::to_writer(&mut self.manifest, &row)?;
        self.manifest.write_all(b"\n")?;
        self.manifest.flush()?;
        Ok(destination)
    }

    pub fn record_existing(&mut self, source: &str, name: &str) -> Result<()> {
        self.record_existing_inner(source, name, true)
    }

    pub(crate) fn record_partial_files(&mut self) -> Result<()> {
        let recorded = BufReader::new(File::open(self.root.join("manifest.jsonl"))?)
            .lines()
            .map(|line| -> Result<String> {
                Ok(serde_json::from_str::<EvidenceFile>(&line?)?.path)
            })
            .collect::<Result<BTreeSet<_>>>()?;
        for entry in fs::read_dir(self.root.join("raw"))? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_str().context("partial raw filename is not UTF-8")?;
            if recorded.contains(&format!("raw/{name}")) {
                continue;
            }
            let source = match name {
                "live-traffic.pcap" => {
                    "tcpdump -i any; collection interrupted; capture completeness unknown; hash covers saved bytes only"
                }
                "live-traffic.log" => "tcpdump capture stderr; collection interrupted",
                "live-traffic-summary.txt" => "tcpdump packet decode; collection interrupted",
                _ => {
                    "source mapping unavailable; incomplete collection; hash covers saved bytes only"
                }
            };
            self.record_existing_inner(source, name, false)?;
        }
        Ok(())
    }

    fn record_existing_inner(
        &mut self,
        source: &str,
        name: &str,
        interruptible: bool,
    ) -> Result<()> {
        if name.contains('/') || name == "." || name == ".." {
            anyhow::bail!("invalid evidence name");
        }
        let path = self.root.join("raw").join(name);
        let mut input = BufReader::new(File::open(&path)?);
        let mut hash = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            if interruptible {
                crate::runtime::check_cancelled()?;
            }
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            bytes = bytes.saturating_add(u64::try_from(count)?);
        }
        let row = EvidenceFile {
            source: source.to_owned(),
            path: format!("raw/{name}"),
            bytes,
            sha256: format!("{:x}", hash.finalize()),
            acquired_at: jiff::Timestamp::now().to_string(),
        };
        serde_json::to_writer(&mut self.manifest, &row)?;
        self.manifest.write_all(b"\n")?;
        self.manifest.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Case, Coverage, CoverageState, Event, EvidenceLevel, validate_root_output_base};

    #[test]
    fn coverage_classifies_io_failures_without_losing_context() {
        for (kind, state) in [
            (std::io::ErrorKind::NotFound, "unavailable"),
            (std::io::ErrorKind::PermissionDenied, "denied"),
            (std::io::ErrorKind::Interrupted, "cancelled"),
            (std::io::ErrorKind::InvalidData, "failed"),
        ] {
            let error = anyhow::Error::new(std::io::Error::from(kind)).context("source collection");
            assert_eq!(
                serde_json::to_value(CoverageState::from_error(&error)).expect("state"),
                state
            );
        }
    }
    use std::fs;

    #[test]
    fn rejects_user_writable_root_output_parent() {
        assert!(validate_root_output_base(std::path::Path::new("/tmp")).is_err());
    }

    #[test]
    fn preserves_incremental_evidence_and_status() {
        let base = std::env::temp_dir().join(format!("opsforge-test-{}", std::process::id()));
        fs::create_dir_all(&base).expect("test directory");
        let source = base.join("sample.log");
        fs::write(&source, b"network activity\n").expect("test source");
        let mut case = Case::new(&base).expect("case");
        case.copy_evidence(&source, "sample.log").expect("copy");
        case.coverage(&Coverage {
            source: "sample".into(),
            state: CoverageState::Collected,
            detail: "ok".into(),
        })
        .expect("status");
        case.event(&Event {
            timestamp: None,
            source: "sample".into(),
            kind: "log".into(),
            application: None,
            user: None,
            destination: None,
            detail: "network activity".into(),
            evidence: "raw/sample.log".into(),
            level: EvidenceLevel::Unattributed,
            transfer: None,
            evidence_line: None,
        })
        .expect("event");
        assert_eq!(
            fs::read(case.root.join("raw/sample.log")).expect("evidence"),
            b"network activity\n"
        );
        assert!(
            fs::read_to_string(case.root.join("normalized/events.jsonl"))
                .expect("events")
                .contains("network activity")
        );
        assert!(
            fs::read_to_string(case.root.join("manifest.jsonl"))
                .expect("manifest")
                .contains("sha256")
        );
        fs::remove_dir_all(&base).expect("remove fixture");
    }
}
