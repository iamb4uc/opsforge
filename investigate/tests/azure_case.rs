use opsforge_investigate::{collect, config::RunConfig};
use std::fs;

#[test]
fn azure_metadata_and_http_outcomes_reach_reports_without_inventing_file_transfers() {
    let base = std::env::temp_dir().join(format!("opsforge-azure-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let metadata = base.join("command.log");
    let metadata_lines = "CMD-LOG-LINE-BEGIN 42 | 2026-10-09 21:09:13,797 | INFO | az_command_data_logger | command args: storage blob upload --file {} --name {}\nCMD-LOG-LINE-BEGIN 42 | 2026-10-09 21:09:14,129 | INFO | az_command_data_logger | exit code: 0\n";
    fs::write(&metadata, metadata_lines).expect("metadata");
    let debug = base.join("debug.log");
    let debug_lines = "INFO: az_command_data_logger: command args: storage blob download --file {} --name {} --debug\nDEBUG: urllib3.connectionpool: http://127.0.0.1:10000 \"GET /account/container/retained%20file.txt HTTP/1.1\" 206 38\nINFO: az_command_data_logger: exit code: 0\nINFO: az_command_data_logger: command args: storage blob download --file {} --name {} --debug\nDEBUG: urllib3.connectionpool: http://127.0.0.1:10000 \"GET /account/container/missing.txt HTTP/1.1\" 404 None\nINFO: az_command_data_logger: exit code: 3\n";
    fs::write(&debug, debug_lines).expect("debug");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.extend([metadata, debug]);
    let root = collect::run(&config, &|_| {}).expect("case");
    let rows: Vec<serde_json::Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .expect("events")
        .lines()
        .map(|line| serde_json::from_str(line).expect("row"))
        .collect();
    assert_eq!(rows.len(), 8);
    let transfers: Vec<_> = rows
        .iter()
        .filter(|row| row["transfer"].is_object())
        .collect();
    assert_eq!(transfers.len(), 2);
    assert_eq!(transfers[0]["transfer"]["status"], "accepted");
    assert_eq!(transfers[1]["transfer"]["status"], "failed");
    assert!(
        transfers
            .iter()
            .all(|row| row["transfer"]["bytes"].is_null()
                && row["transfer"]["file"].is_null()
                && row["timestamp"].is_null()
                && row["transfer"]["perspective"] == "client")
    );
    assert!(
        rows.iter()
            .filter(|row| row["kind"] == "upload-command-result")
            .all(|row| row["transfer"].is_null())
    );
    assert_eq!(transfers[1]["evidence_line"], 5);
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).expect("raw"),
        metadata_lines
    );
    assert!(
        fs::read_to_string(root.join("dashboard/events.js"))
            .expect("dashboard")
            .contains("not a per-file transfer result")
    );
    fs::remove_dir_all(base).expect("fixture cleanup");
}
