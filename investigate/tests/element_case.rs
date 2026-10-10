use opsforge_investigate::{collect, config::RunConfig};
use serde_json::{Value, json};
use std::fs;

#[test]
fn element_exports_keep_redactions_encryption_and_file_references_separate_from_transfers() {
    let base = std::env::temp_dir().join(format!("opsforge-element-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let path = base.join("export.json");
    let messages = json!([
        {"type":"m.room.message","sender":"@fixture:example.test","event_id":"$file","origin_server_ts":1791549000005_i64,
         "content":{"msgtype":"m.file","filename":"report, résumé.txt<script>","body":"this is a caption","url":"mxc://example.test/media","info":{"size":0,"mimetype":"text/plain"}}},
        {"type":"m.room.message","origin_server_ts":0,"content":{},"unsigned":{"redacted_because":{"event_id":"$redaction"}}},
        {"type":"m.room.encrypted","origin_server_ts":1791549000000_i64,"content":{"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"synthetic ciphertext stays raw"}},
        {"type":"m.room.message","origin_server_ts":"bad timestamp","content":{"msgtype":"m.image","body":"image caption","file":{"v":"v2","url":"mxc://example.test/encrypted","key":{"k":"synthetic descriptor key stays raw"},"hashes":{"sha256":"recorded-ciphertext-hash"}},"info":{"size":9999,"w":10,"h":20}}},
        {"type":"m.room.message","origin_server_ts":1791549000000_i64,"content":{"msgtype":"m.audio","body":"audio caption","url":"https://example.test/private?synthetic=not-fetched","m.new_content":{"msgtype":"m.file","body":"nested raw reference"},"info":{"duration":123}}},
        {"type":"future","content":"not an object"},
        {"type":"m.room.member","origin_server_ts":1791549000000_i64,"redacted_because":null,"content":{"membership":"join"}}
    ]);
    let bytes = serde_json::to_vec_pretty(&json!({"room_name":"Fixture room","exported_by":"Fixture display label","export_date":"ambiguous export date","messages":messages})).expect("fixture");
    fs::write(&path, &bytes).expect("messages");
    let empty = base.join("empty.json");
    fs::write(
        &empty,
        r#"{"room_name":"Empty","exported_by":"fixture","messages":[]}"#,
    )
    .expect("empty");
    let unsupported = base.join("unsupported.json");
    fs::write(
        &unsupported,
        r#"{"room_name":"Unknown","exported_by":"fixture","messages":{}}"#,
    )
    .expect("unsupported");
    let unrelated = base.join("unrelated.json");
    fs::write(&unrelated, r#"{"messages":[],"other_app":true}"#).expect("unrelated");
    let mut config = RunConfig::default_for(base.join("cases"));
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config
        .imports
        .extend([path.clone(), empty, unsupported, unrelated]);
    let root = collect::run(&config, &|_| {}).expect("case");
    let normalized = fs::read_to_string(root.join("normalized/events.jsonl")).expect("events");
    let rows: Vec<Value> = normalized
        .lines()
        .map(|line| serde_json::from_str(line).expect("event"))
        .collect();
    assert_eq!(rows.len(), 10);
    assert_eq!(rows[0]["timestamp"], "2026-10-09T12:30:00.005Z");
    assert_eq!(rows[1]["kind"], "chat-file-reference");
    assert!(
        rows[1]["detail"]
            .as_str()
            .unwrap()
            .contains("this is a caption")
    );
    assert_eq!(rows[2]["timestamp"], "1970-01-01T00:00:00Z");
    assert!(
        rows[2]["detail"]
            .as_str()
            .unwrap()
            .contains("\"redacted\":true")
    );
    assert!(rows[4]["timestamp"].is_null());
    assert!(
        rows[5]["detail"]
            .as_str()
            .unwrap()
            .contains("recorded-ciphertext-hash")
    );
    assert!(
        rows[5]["detail"]
            .as_str()
            .unwrap()
            .contains("\"filename\":null")
    );
    assert!(
        rows[7]["detail"]
            .as_str()
            .unwrap()
            .contains("\"mxc_uri\":null")
    );
    assert!(
        rows[8]["detail"]
            .as_str()
            .unwrap()
            .contains("\"redacted\":false")
    );
    assert_eq!(rows[9]["kind"], "imported-record");
    assert!(rows.iter().all(|row| row["transfer"].is_null()
        && row["user"].is_null()
        && row["destination"].is_null()));
    assert!(!normalized.contains("synthetic descriptor key stays raw"));
    assert!(!normalized.contains("synthetic ciphertext stays raw"));
    assert!(!normalized.contains("synthetic=not-fetched"));
    assert!(!normalized.contains("nested raw reference"));
    assert_eq!(
        fs::read(root.join("raw/import-000-000000")).expect("raw"),
        bytes
    );
    assert_eq!(fs::read(&path).expect("source unchanged"), bytes);
    let coverage = fs::read_to_string(root.join("normalized/coverage.jsonl")).expect("coverage");
    for detail in [
        "encrypted Matrix event content is not decoded",
        "encrypted attachment descriptor",
        "export date and event age are not substituted",
        "nested replacement content",
        "missing or invalid Matrix media URI",
        "unsupported Matrix event",
        "unsupported Element export",
    ] {
        assert!(coverage.contains(detail), "{detail}");
    }
    assert!(coverage.contains("\"state\":\"empty\""));
    assert!(coverage.contains("#/messages/2/content"));
    let dashboard = fs::read_to_string(root.join("dashboard/events.js")).expect("dashboard");
    assert!(dashboard.contains("résumé.txt\\u003cscript\\u003e"));
    fs::remove_dir_all(base).expect("owned fixture cleanup");
}
