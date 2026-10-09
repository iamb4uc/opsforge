use opsforge_investigate::{
    collect,
    config::{CheckConfig, LinuxCheck, RunConfig},
};
use std::fs;

#[test]
fn selected_check_preserves_findings_inputs_and_reports_without_archives() {
    let base = std::env::temp_dir().join(format!("opsforge-check-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let input = base.join("sources.conf");
    fs::write(
        &input,
        format!("missing|{}/absent.log|critical|60\n", base.display()),
    )
    .expect("input");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    let mut check = CheckConfig::new(LinuxCheck::LogSilence);
    check.input = Some(input.clone());
    config.checks.push(check);
    let root = collect::run(&config, &|_| {}).expect("case");
    assert!(!root.join(".check-tools").exists());
    let row: serde_json::Value = serde_json::from_str(
        fs::read_to_string(root.join("normalized/checks.jsonl"))
            .expect("check result")
            .trim(),
    )
    .expect("json");
    assert_eq!(row["tool"], "log-silence");
    assert_eq!(row["state"], "collected");
    assert_eq!(row["exit_code"], 0);
    assert_eq!(row["findings"][0]["severity"], "critical");
    assert!(
        root.join(row["findings"][0]["evidence"].as_str().expect("path"))
            .is_file()
    );
    let findings: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join("findings.json")).expect("findings"))
            .expect("json");
    assert_eq!(findings, row["findings"]);
    assert_eq!(
        fs::read(root.join("raw/check-log-silence-input.conf")).expect("preserved input"),
        fs::read(input).expect("source")
    );
    let manifest = fs::read_to_string(root.join("manifest.jsonl")).expect("manifest");
    assert!(manifest.contains("stdout.log") && manifest.contains("findings.json"));
    assert!(
        fs::read_to_string(root.join("dashboard/checks.html"))
            .expect("page")
            .contains("Check findings by severity")
    );
    assert!(
        fs::read_to_string(root.join("summary.txt"))
            .expect("summary")
            .contains("Findings: 1")
    );
    for entry in walkdir::WalkDir::new(&root) {
        assert_ne!(entry.expect("entry").file_name(), "evidence.tar.gz");
    }
    fs::remove_dir_all(base).expect("cleanup");
}

#[test]
fn failed_check_keeps_exit_status_and_does_not_evaluate_config_arithmetic() {
    let base = std::env::temp_dir().join(format!("opsforge-bad-check-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let input = base.join("sources.conf");
    fs::write(&input, "bad-age|/etc/passwd|critical|1+1\n").expect("config");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    let mut check = CheckConfig::new(LinuxCheck::LogSilence);
    check.input = Some(input);
    config.checks.push(check);
    let root = collect::run(&config, &|_| {}).expect("case retained");
    let record: serde_json::Value = serde_json::from_str(
        fs::read_to_string(root.join("normalized/checks.jsonl"))
            .expect("result")
            .trim(),
    )
    .expect("json");
    assert_eq!(record["state"], "failed");
    assert_eq!(record["exit_code"], 1);
    let audit: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("raw/checks/log-silence/command.json")).expect("audit"),
    )
    .expect("json");
    assert!(std::path::Path::new(audit["home"].as_str().expect("account home")).is_absolute());
    assert!(
        fs::read_to_string(root.join("raw/checks/log-silence/stderr.log"))
            .expect("stderr")
            .contains("Log age must be a non-negative integer")
    );
    assert!(!root.join(".check-tools").exists());
    fs::remove_dir_all(base).expect("cleanup");
}
