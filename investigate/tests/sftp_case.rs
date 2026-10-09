use opsforge_investigate::{collect, config::RunConfig};
use std::fs;

#[test]
fn sftp_file_counters_reach_dashboard_with_raw_line_and_unknown_identity() {
    let base = std::env::temp_dir().join(format!("opsforge-sftp-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let log = base.join("auth.log");
    let line = "Oct 9 10:00:00 host sftp-server[42]: close \"/file with spaces.txt\" bytes read 10 written 20\n";
    fs::write(&log, line).expect("log");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(log);
    let root = collect::run(&config, &|_| {}).expect("case");
    let rows: Vec<serde_json::Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .expect("events")
        .lines()
        .map(|line| serde_json::from_str(line).expect("row"))
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["transfer"]["direction"], "download");
    assert_eq!(rows[1]["transfer"]["direction"], "upload");
    assert!(
        rows.iter()
            .all(|row| row["transfer"]["status"] == "observed"
                && row["evidence_line"] == 1
                && row["timestamp"].is_null()
                && row["user"].is_null())
    );
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).expect("raw"),
        line
    );
    let data = fs::read_to_string(root.join("dashboard/events.js")).expect("dashboard");
    assert!(
        data.contains("file with spaces.txt") && data.contains("whole-file completion are unknown")
    );
    fs::remove_dir_all(base).expect("fixture cleanup");
}
