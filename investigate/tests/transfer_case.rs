use opsforge_investigate::{collect, config::RunConfig};
use serde_json::Value;
use std::fs;

#[test]
fn retained_uploads_keep_file_bytes_outcome_and_raw_line_without_promoting_leads() {
    let base = std::env::temp_dir().join(format!("opsforge-transfers-{}", std::process::id()));
    fs::create_dir_all(&base).expect("base");
    let imported = base.join("transfers.log");
    let fixture = concat!(
        "Mon Oct  5 18:38:48 2026 1 127.0.0.1 39 /uploads/customer_export.txt b _ i a anonymous ftp 0 * c\n",
        "127.0.0.1 - operator [05/Oct/2026:18:38:49 +0000] \"PUT /uploads/request.txt HTTP/1.1\" 201 0 \"-\" \"curl\"\n",
        "{\"request_method\":\"POST\",\"request_uri\":\"/form\",\"status\":403,\"request_length\":280,\"body_bytes_sent\":999,\"time_iso8601\":\"2026-10-05T18:38:50Z\",\"remote_addr\":\"192.0.2.3\"}\n",
        "POST https://example.test/upload <script>alert(1)</script>\n"
    );
    fs::write(
        &imported,
        format!("{fixture}{}", "ordinary event\n".repeat(2_501)),
    )
    .expect("fixture");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(imported);
    let root = collect::run(&config, &|_| {}).expect("collect");
    let rows: Vec<Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .expect("events")
        .lines()
        .map(|line| serde_json::from_str(line).expect("row"))
        .collect();
    assert_eq!(rows.len(), 2_505);
    assert_eq!(rows[0]["transfer"]["file"], "/uploads/customer_export.txt");
    assert_eq!(rows[0]["transfer"]["bytes"], 39);
    assert_eq!(rows[0]["transfer"]["status"], "completed");
    assert_eq!(rows[0]["transfer"]["perspective"], "server");
    assert_eq!(rows[0]["evidence_line"], 1);
    assert_eq!(rows[1]["timestamp"], "2026-10-05T18:38:49Z");
    assert_eq!(rows[1]["user"], "operator");
    assert!(rows[1]["transfer"]["bytes"].is_null());
    assert!(rows[1]["transfer"]["file"].is_null());
    assert_eq!(rows[1]["transfer"]["status"], "accepted");
    assert_eq!(rows[2]["transfer"]["bytes"], 280);
    assert_eq!(rows[2]["transfer"]["status"], "failed");
    assert!(rows[3].get("transfer").is_none());
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).expect("raw"),
        format!("{fixture}{}", "ordinary event\n".repeat(2_501))
    );
    let data = fs::read_to_string(root.join("dashboard/events.js")).expect("dashboard data");
    assert!(data.contains("customer_export.txt"));
    assert!(data.contains("\\u003cscript\\u003e"));
    assert_eq!(data.matches("\"evidence\":").count(), rows.len());
    for page in [
        "index",
        "exfil",
        "downloads",
        "timeline",
        "network",
        "collection",
        "evidence",
    ] {
        assert!(root.join(format!("dashboard/{page}.html")).exists());
    }
    fs::remove_dir_all(base).expect("fixture cleanup");
}
