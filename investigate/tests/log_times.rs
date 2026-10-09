use opsforge_investigate::{case::Event, collect, config::RunConfig};
use std::fs;

#[test]
fn imported_log_times_reach_the_timeline_without_inventing_missing_zones() {
    let base = std::env::temp_dir().join(format!("opsforge-log-times-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture directory");
    let imported = base.join("auth.log");
    fs::write(&imported, concat!(
        "2026-10-09T12:00:00+05:30 host sftp-server[1]: close \"file.txt\" bytes read 7 written 0\n",
        "2026-10-09T06:31:00Z host app[2]: connection opened\n",
        "Oct 9 12:00:00 host app[2]: upload\n",
        "2026-10-09T12:00:00 host app[2]: upload\n",
    )).expect("fixture");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(imported);
    let root = collect::run(&config, &|_| {}).expect("case");
    let events: Vec<Event> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .expect("events")
        .lines()
        .map(|line| serde_json::from_str(line).expect("event"))
        .collect();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].timestamp.as_deref(), Some("2026-10-09T06:30:00Z"));
    assert_eq!(events[0].transfer.as_ref().expect("sftp").bytes, Some(7));
    assert_eq!(events[1].timestamp.as_deref(), Some("2026-10-09T06:31:00Z"));
    assert!(events[2].timestamp.is_none());
    assert!(events[3].timestamp.is_none());
    let script = fs::read_to_string(root.join("dashboard/events.js")).expect("report data");
    assert!(script.contains("2026-10-09T06:30:00Z"));
    assert_eq!(events[0].evidence_line, Some(1));
    fs::remove_dir_all(base).expect("remove owned fixture");
}
