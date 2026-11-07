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
fn nested_checksum_names_are_retained_and_verified() {
    let fixture = Fixture::new("nested-checksums");
    fs::create_dir(fixture.0.join("normalized/import")).unwrap();
    for name in ["checksums.sha256", "checksums.sha256.tmp"] {
        fs::write(fixture.0.join("normalized/import").join(name), "retained").unwrap();
    }
    report::write_checksums(&fixture.0).unwrap();
    assert_eq!(verify(&fixture.0).unwrap().exit_code(), 0);
    fs::write(
        fixture.0.join("normalized/import/checksums.sha256"),
        "changed",
    )
    .unwrap();
    assert!(!verify(&fixture.0).unwrap().source_issues.is_empty());
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

#[test]
fn bundle_rebuild_preserves_source_and_survives_relocation() {
    let fixture = Fixture::new("bundle");
    let before = fs::read(fixture.0.join("checksums.sha256")).unwrap();
    fs::remove_file(fixture.0.join("report.md")).unwrap();
    let output = fixture.0.with_extension("review");
    let result = Command::new(env!("CARGO_BIN_EXE_opsforge-investigate"))
        .arg("rebuild")
        .arg(&fixture.0)
        .arg("--output")
        .arg(&output)
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result);
    assert_eq!(
        fs::read(fixture.0.join("checksums.sha256")).unwrap(),
        before
    );
    assert!(!fixture.0.join("report.md").exists());
    assert_eq!(verify(&output).unwrap().exit_code(), 0);
    let moved = output.with_extension("moved");
    fs::rename(&output, &moved).unwrap();
    assert_eq!(
        fs::read(moved.join("raw/file with spaces")).unwrap(),
        b"evidence"
    );
    assert!(moved.join("dashboard/index.html").is_file());
    fs::remove_dir_all(moved).unwrap();
}

#[test]
fn linked_rebuild_uses_relative_evidence_without_copying_it() {
    use opsforge_investigate::rebuild::{ReviewMode, rebuild};
    let fixture = Fixture::new("linked");
    let output = fixture.0.with_extension("review");
    rebuild(&fixture.0, &output, ReviewMode::Linked, false).unwrap();
    assert!(!output.join("raw").exists());
    let review: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("review.json")).unwrap()).unwrap();
    let base = review["evidence_base"].as_str().unwrap();
    assert_eq!(
        fs::read(
            output
                .join("dashboard")
                .join(base)
                .join("raw/file with spaces")
        )
        .unwrap(),
        b"evidence"
    );
    fs::remove_dir_all(output).unwrap();
}

#[test]
fn rebuild_rejects_tampering_even_with_unverified_override() {
    use opsforge_investigate::rebuild::{ReviewMode, rebuild};
    let fixture = Fixture::new("blocked");
    fs::write(fixture.0.join("raw/file with spaces"), "changed").unwrap();
    let output = fixture.0.with_extension("review");
    assert!(rebuild(&fixture.0, &output, ReviewMode::Bundle, true).is_err());
    assert!(!output.exists());
}

#[test]
fn rebuild_requires_override_for_missing_checksums_and_refuses_overlap() {
    use opsforge_investigate::rebuild::{ReviewMode, rebuild};
    let fixture = Fixture::new("override");
    let output = fixture.0.with_extension("review");
    fs::remove_file(fixture.0.join("checksums.sha256")).unwrap();
    assert!(rebuild(&fixture.0, &output, ReviewMode::Bundle, false).is_err());
    assert!(
        rebuild(
            &fixture.0,
            &fixture.0.join("review"),
            ReviewMode::Bundle,
            true
        )
        .is_err()
    );
    rebuild(&fixture.0, &output, ReviewMode::Bundle, true).unwrap();
    let review: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("review.json")).unwrap()).unwrap();
    assert_eq!(
        review["verification"]["unverified"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(rebuild(&fixture.0, &output, ReviewMode::Bundle, true).is_err());
    fs::remove_dir_all(output).unwrap();
}

#[cfg(windows)]
#[test]
fn rebuilt_files_inherit_private_acl_and_collection_stays_disabled() {
    use opsforge_investigate::rebuild::{ReviewMode, rebuild};
    let fixture = Fixture::new("windows-acl");
    let output = fixture.0.with_extension("review");
    rebuild(&fixture.0, &output, ReviewMode::Bundle, false).unwrap();
    let powershell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let result = Command::new(powershell).args(["-NoProfile", "-NonInteractive", "-Command",
        "$ErrorActionPreference='Stop'; $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; $acl=[IO.File]::GetAccessControl($env:OPSFORGE_TEST_FILE); $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); if ($rules.Count -ne 1 -or $rules[0].IdentityReference -ne $sid -or -not $rules[0].IsInherited) { throw 'copied file did not inherit private ACL' }"])
        .env("OPSFORGE_TEST_FILE", output.join("raw/file with spaces")).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(verify(&output).unwrap().exit_code(), 0);
    let command = Command::new(env!("CARGO_BIN_EXE_opsforge-investigate"))
        .args(["collect", "--non-interactive"])
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(!command.status.success());
    assert!(String::from_utf8_lossy(&command.stderr).contains("collection is not available"));
    fs::remove_dir_all(output).unwrap();
}
