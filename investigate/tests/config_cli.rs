use std::{fs, process::Command};

#[test]
fn dry_run_validates_config_and_overrides_without_creating_a_case() {
    let base = std::env::temp_dir().join(format!("opsforge-config-cli-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture directory");
    let config = base.join("config.json");
    let cases = base.join("cases");
    fs::write(
        &config,
        serde_json::json!({"output_base": cases,
        "capture_duration": "1h", "exfil": false, "imports": ["/retained/log"]})
        .to_string(),
    )
    .expect("fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_opsforge-investigate"))
        .args([
            "--config",
            config.to_str().expect("path"),
            "--dry-run",
            "--duration",
            "2m",
            "--no-capture",
            "--import",
            "/another/log",
        ])
        .output()
        .expect("dry run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let selected: serde_json::Value = serde_json::from_slice(&output.stdout).expect("settings");
    assert_eq!(selected["capture_duration"]["seconds"], 120);
    assert_eq!(selected["exfil"], false);
    assert_eq!(selected["live_capture"], false);
    assert_eq!(selected["imports"].as_array().expect("imports").len(), 2);
    assert!(!cases.exists());
    fs::write(
        &config,
        r#"{"capture_duration":{"seconds":0,"label":"5m"}}"#,
    )
    .expect("bad config");
    let invalid = Command::new(env!("CARGO_BIN_EXE_opsforge-investigate"))
        .args(["--config", config.to_str().expect("path"), "--dry-run"])
        .output()
        .expect("invalid dry run");
    assert!(!invalid.status.success());
    assert!(!cases.exists());
    fs::remove_dir_all(base).expect("fixture cleanup");
}
