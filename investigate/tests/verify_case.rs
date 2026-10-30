use opsforge_investigate::{report, verify::verify};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("opsforge-verify-{}-{name}", std::process::id()));
        fs::create_dir(&root).expect("unique fixture");
        fs::create_dir(root.join("raw")).unwrap();
        fs::create_dir(root.join("normalized")).unwrap();
        fs::write(root.join("raw/file with spaces"), b"evidence").unwrap();
        let row = serde_json::json!({"source":"fixture", "path":"raw/file with spaces", "bytes":8,"sha256":format!("{:x}",Sha256::digest(b"evidence")),"acquired_at":"2026-01-01T00:00:00Z"});
        fs::write(root.join("manifest.jsonl"), format!("{row}\n")).unwrap();
        fs::write(root.join("normalized/events.jsonl"), "").unwrap();
        fs::write(root.join("normalized/coverage.jsonl"), "").unwrap();
        fs::write(root.join("report.md"), "report").unwrap();
        report::write_checksums(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn pristine_case_verifies_without_changes_or_collection() {
    let fixture = Fixture::new("clean");
    let before = fs::read(fixture.0.join("checksums.sha256")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_opsforge-investigate"))
        .arg("verify")
        .arg(&fixture.0)
        .arg("--json")
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["source_issues"], serde_json::json!([]));
    assert_eq!(
        before,
        fs::read(fixture.0.join("checksums.sha256")).unwrap()
    );
}

#[test]
fn modified_evidence_is_a_source_issue() {
    let fixture = Fixture::new("changed");
    fs::write(fixture.0.join("raw/file with spaces"), "tampered").unwrap();
    let result = verify(&fixture.0).unwrap();
    assert_eq!(result.exit_code(), 1);
    assert!(!result.source_issues.is_empty());
}

#[test]
fn missing_report_is_not_a_source_issue() {
    let fixture = Fixture::new("report");
    fs::remove_file(fixture.0.join("report.md")).unwrap();
    let result = verify(&fixture.0).unwrap();
    assert!(result.source_issues.is_empty());
    assert_eq!(result.report_issues.len(), 1);
}

#[test]
fn missing_checksums_are_unverified() {
    let fixture = Fixture::new("unfinished");
    fs::remove_file(fixture.0.join("checksums.sha256")).unwrap();
    let result = verify(&fixture.0).unwrap();
    assert_eq!(result.exit_code(), 1);
    assert_eq!(result.unverified.len(), 1);
}

#[test]
fn checksum_traversal_is_rejected() {
    let fixture = Fixture::new("traversal");
    fs::write(
        fixture.0.join("checksums.sha256"),
        format!("{}  ../outside\n", "0".repeat(64)),
    )
    .unwrap();
    assert!(verify(&fixture.0).is_err());
}

#[cfg(unix)]
#[test]
fn evidence_symlink_is_rejected() {
    let fixture = Fixture::new("link");
    std::os::unix::fs::symlink("/etc/passwd", fixture.0.join("raw/link")).unwrap();
    assert!(verify(&fixture.0).is_err());
}
