use opsforge_investigate::{collect, config::RunConfig};
use std::fs;

#[test]
fn rsync_import_preserves_metadata_ambiguity_and_raw_lines() {
    let base = std::env::temp_dir().join(format!("opsforge-rsync-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let log = base.join("rsync.log");
    let lines = "2026/10/09 17:38:45 [42] recv UNDETERMINED [127.0.0.1] evidence () report with spaces.txt 35\n2026/10/09 17:38:45 [43] send UNDETERMINED [127.0.0.1] evidence () report with spaces.txt 35\n2026/10/09 17:38:45 [44] >f+++++++++ report with spaces.txt\n2026/10/09 17:38:45 [45] <f..t...... report with spaces.txt\n2026/10/09 17:38:45 [46] recv UNDETERMINED [127.0.0.1] evidence () report with spaces.txt 35\n";
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
    assert_eq!(rows.len(), 5);
    assert_eq!(
        rows.iter()
            .filter(|row| row["transfer"].is_object())
            .count(),
        3
    );
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["evidence_line"], index + 1);
        assert_eq!(row["timestamp"], "2026-10-09T17:38:45");
        if row["transfer"].is_object() {
            assert_eq!(row["transfer"]["status"], "observed");
            assert_eq!(row["transfer"]["bytes"], 35);
            assert!(row["detail"].as_str().expect("detail").contains("metadata"));
        }
    }
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).expect("raw"),
        lines
    );
    assert!(
        fs::read_to_string(root.join("dashboard/events.js"))
            .expect("dashboard")
            .contains("not actual payload")
    );
    fs::remove_dir_all(base).expect("fixture cleanup");
}
