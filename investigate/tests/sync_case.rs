use opsforge_investigate::{collect, config::RunConfig};
use std::fs;

#[test]
fn sync_audit_reaches_timeline_without_inventing_uploads_or_bytes() {
    let base = std::env::temp_dir().join(format!("opsforge-sync-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let file = base.join("audit.log");
    let record = serde_json::json!({"id":1,"globalID":1,"type":"ItemFinished","time":"2026-10-09T00:00:00Z","data":{"folder":"lab","item":"file.txt","type":"file","action":"update","error":null}});
    fs::write(&file, format!("{record}\n")).expect("audit");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(file);
    let root = collect::run(&config, &|_| {}).expect("case");
    let event: serde_json::Value = serde_json::from_str(
        fs::read_to_string(root.join("normalized/events.jsonl"))
            .expect("events")
            .trim(),
    )
    .expect("event");
    assert_eq!(event["application"], "Syncthing");
    assert_eq!(event["kind"], "sync-file-update-completed");
    assert_eq!(event["evidence_line"], 1);
    assert!(event.get("transfer").is_none());
    assert!(
        fs::read_to_string(root.join("summary.txt"))
            .expect("summary")
            .contains("Upload records: 0")
    );
    assert!(
        fs::read_to_string(root.join("dashboard/events.js"))
            .expect("dashboard")
            .contains("reuse local blocks")
    );
    fs::remove_dir_all(base).expect("cleanup");
}
