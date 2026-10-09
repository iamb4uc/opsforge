use opsforge_investigate::{collect, config::RunConfig};
use std::fs;

#[test]
fn filezilla_interleaved_import_reaches_report_without_inventing_remote_paths() {
    let base = std::env::temp_dir().join(format!("opsforge-filezilla-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let log = base.join("filezilla.log");
    let lines = "2026-10-09 18:04:30 42 2 Status: Connecting to 127.0.0.1:35589...\n2026-10-09 18:04:30 42 3 Status: Connecting to 127.0.0.1:35589...\n2026-10-09 18:04:30 42 2 Status: Starting upload of /local/upload with spaces.txt\n2026-10-09 18:04:30 42 3 Status: Starting download of /download with spaces.txt\n2026-10-09 18:04:30 42 2 Status: File transfer successful, transferred 26 B in 1 second\n2026-10-09 18:04:30 42 3 Status: File transfer successful, transferred 26 B in 1 second\n2026-10-09 18:04:31 42 3 Status: Starting download of /missing-file.txt\n2026-10-09 18:04:31 42 3 Error: Critical file transfer error\n";
    fs::write(&log, lines).expect("log");
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
    let transfers: Vec<_> = rows
        .iter()
        .filter(|row| row["transfer"].is_object())
        .collect();
    assert_eq!(transfers.len(), 3);
    assert_eq!(
        transfers[0]["transfer"]["file"],
        "/local/upload with spaces.txt"
    );
    assert_eq!(
        transfers[1]["transfer"]["file"],
        "/download with spaces.txt"
    );
    assert_eq!(transfers[0]["transfer"]["status"], "completed");
    assert_eq!(transfers[0]["transfer"]["bytes"], 26);
    assert_eq!(transfers[2]["transfer"]["status"], "failed");
    assert!(transfers[2]["transfer"]["bytes"].is_null());
    assert!(
        transfers
            .iter()
            .all(|row| row["user"].is_null() && row["transfer"]["protocol"] == "unknown")
    );
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).expect("raw"),
        lines
    );
    assert!(
        fs::read_to_string(root.join("dashboard/events.js"))
            .expect("dashboard")
            .contains("opposite-side file path are not inferred")
    );
    fs::remove_dir_all(base).expect("fixture cleanup");
}
