use std::{fs, process::Command};

#[test]
fn collect_command_preserves_flat_cli_settings_and_validation() {
    let binary = env!("CARGO_BIN_EXE_opsforge-investigate");
    for flags in [
        vec![
            "--dry-run",
            "--duration",
            "2m",
            "--no-capture",
            "--check",
            "ssh",
        ],
        vec!["--dry-run", "--duration", "0s"],
        vec!["--dry-run", "--check", "tls"],
    ] {
        let flat = Command::new(binary)
            .args(&flags)
            .env("PATH", "")
            .output()
            .unwrap();
        let collect = Command::new(binary)
            .arg("collect")
            .args(&flags)
            .env("PATH", "")
            .output()
            .unwrap();
        assert_eq!(flat.status.success(), flags.contains(&"2m"));
        assert_eq!(flat.status.code(), collect.status.code());
        assert_eq!(flat.stdout, collect.stdout);
        assert_eq!(flat.stderr, collect.stderr);
    }
}

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
            "--check",
            "ssh",
            "--check",
            "firewall",
            "--check",
            "ssh",
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
    assert_eq!(selected["checks"].as_array().expect("checks").len(), 2);
    assert_eq!(selected["checks"][0]["tool"], "ssh");
    assert_eq!(selected["checks"][1]["tool"], "firewall");
    assert!(!cases.exists());
    let missing_targets = Command::new(env!("CARGO_BIN_EXE_opsforge-investigate"))
        .args(["--dry-run", "--check", "tls"])
        .output()
        .expect("missing target configuration");
    assert!(!missing_targets.status.success());
    assert!(String::from_utf8_lossy(&missing_targets.stderr).contains("require explicit targets"));
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
