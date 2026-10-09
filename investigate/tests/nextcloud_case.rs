use opsforge_investigate::{collect, config::RunConfig};
use std::fs;

#[test]
fn nextcloud_file_results_reach_reports_without_turning_folder_sync_into_downloads() {
    let base = std::env::temp_dir().join(format!("opsforge-nextcloud-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let log = base.join("client.log");
    let lines = "10-09 18:24:05:310 [ info nextcloud.sync.propagator ]:\tCompleted propagation of \"Documents\" by OCC::PropagateLocalMkdir(0xabc) with status OCC::SyncFileItem::Success\n10-09 18:24:09:706 [ info nextcloud.sync.propagator ]:\tCompleted propagation of \"server-file.txt\" by OCC::PropagateDownloadFile(0xabc) with status OCC::SyncFileItem::Success\n10-09 18:24:09:900 [ info nextcloud.sync.propagator ]:\tCompleted propagation of \"client-file.txt\" by OCC::BulkPropagatorJob(0xdef) with status OCC::SyncFileItem::Success\n10-09 18:25:40:595 [ warning nextcloud.sync.propagator ]:\tCould not complete propagation of \"denied-upload.txt\" by OCC::BulkPropagatorJob(0xabc) with status OCC::SyncFileItem::NormalError and error: \"Permission denied\"\n";
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
    assert_eq!(rows.len(), 4);
    assert!(rows[0]["transfer"].is_null());
    assert_eq!(rows[1]["transfer"]["direction"], "download");
    assert_eq!(rows[2]["transfer"]["direction"], "upload");
    assert_eq!(rows[3]["transfer"]["status"], "failed");
    assert!(
        rows.iter()
            .all(|row| row["timestamp"].is_null() && row["transfer"]["bytes"].is_null())
    );
    assert_eq!(rows[3]["evidence_line"], 4);
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).expect("raw"),
        lines
    );
    assert!(
        fs::read_to_string(root.join("dashboard/events.js"))
            .expect("dashboard")
            .contains("month/day-only logs also lack a year")
    );
    fs::remove_dir_all(base).expect("fixture cleanup");
}
