use opsforge_investigate::{collect, config::RunConfig};
use serde_json::{Value, json};
use std::fs;

#[test]
fn slack_exports_keep_exact_times_file_metadata_and_partial_schema_gaps() {
    let base = std::env::temp_dir().join(format!("opsforge-slack-case-{}", std::process::id()));
    let channel = base.join("export/general");
    fs::create_dir_all(&channel).expect("export");
    fs::write(base.join("export/channels.json"), "[]").expect("channels");
    fs::write(base.join("export/users.json"), "[]").expect("users");
    let path = channel.join("2026-10-09.json");
    let rows = json!([
        {"type":"message","user":"U_FIXTURE","ts":"1791549000.000005","subtype":"file_share",
         "text":"body stays in raw","files":[
             {"id":"F_FIXTURE","name":"report, résumé.txt<script>","mimetype":"text/plain","size":0,
              "created":1791548990,"url_private_download":"https://example.test/private?secret=fixture-only"},
             {"id":"F_EXTERNAL","is_external":true,"mode":"external","size":9999},
             {"name":"invalid no ID"}]},
        {"type":"message","ts":"0.000000","subtype":"message_deleted","original_ts":"1791548990.000000"},
        {"type":"message","ts":"bad timestamp","files":"not an array"},
        {"type":"future","ts":"1791549000.000000"},
        {"type":"message","ts":"1791549000.123456789","subtype":"message_changed",
         "original_ts":"1791548990.000000","previous":{"text":"old text stays raw"}}
    ]);
    let bytes = serde_json::to_vec_pretty(&rows).expect("fixture");
    fs::write(&path, &bytes).expect("messages");
    let empty = channel.join("2026-10-08.json");
    fs::write(&empty, "[]").expect("empty messages");
    let unsupported = channel.join("2026-10-07.json");
    fs::write(&unsupported, "{\"future_schema\":[]}").expect("unknown schema");
    let malformed = channel.join("2026-10-06.json");
    fs::write(&malformed, "[broken").expect("malformed JSON");
    let unrelated = base.join("unrelated/2026-10-09.json");
    fs::create_dir(unrelated.parent().unwrap()).expect("unrelated");
    fs::write(&unrelated, "[{\"type\":\"message\",\"ts\":\"0.000000\"}]").expect("unrelated JSON");
    let mut config = RunConfig::default_for(base.join("cases"));
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config
        .imports
        .extend([path.clone(), empty, unsupported, malformed, unrelated]);
    let root = collect::run(&config, &|_| {}).expect("case");
    let events: Vec<Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .expect("events")
        .lines()
        .map(|line| serde_json::from_str(line).expect("event"))
        .collect();
    assert_eq!(events.len(), 7);
    assert_eq!(events[0]["timestamp"], "2026-10-09T12:30:00.000005Z");
    assert_eq!(events[1]["kind"], "chat-file-reference");
    assert!(events[1]["detail"].as_str().unwrap().contains("\"size\":0"));
    assert!(
        events[2]["detail"]
            .as_str()
            .unwrap()
            .contains("\"is_external\":true")
    );
    assert_eq!(events[3]["timestamp"], "1970-01-01T00:00:00Z");
    assert!(
        events[3]["detail"]
            .as_str()
            .unwrap()
            .contains("message_deleted")
    );
    assert!(events[4]["timestamp"].is_null());
    assert_eq!(events[5]["timestamp"], "2026-10-09T12:30:00.123456789Z");
    assert_eq!(events[6]["kind"], "imported-record");
    assert!(events.iter().all(|event| event["transfer"].is_null()
        && event["user"].is_null()
        && event["destination"].is_null()
        && event["kind"] != "upload"
        && event["kind"] != "download"));
    let normalized = fs::read_to_string(root.join("normalized/events.jsonl")).expect("normalized");
    assert!(!normalized.contains("secret=fixture-only"));
    assert!(!normalized.contains("body stays in raw"));
    assert!(!normalized.contains("old text stays raw"));
    assert_eq!(
        fs::read(root.join("raw/import-000-000000")).expect("raw"),
        bytes
    );
    assert_eq!(fs::read(&path).expect("original"), bytes);
    let coverage = fs::read_to_string(root.join("normalized/coverage.jsonl")).expect("coverage");
    assert!(coverage.contains("#/0/files/2"));
    assert!(coverage.contains("date filename is not substituted"));
    assert!(coverage.contains("unsupported file-reference list"));
    assert!(coverage.contains("unsupported non-message export record"));
    assert!(coverage.contains("#/4/previous"));
    assert!(coverage.contains("nested file references are not decoded"));
    assert!(coverage.contains("unsupported Slack daily export"));
    assert!(coverage.contains("\"state\":\"empty\""));
    assert!(coverage.contains("\"state\":\"failed\""));
    let dashboard = fs::read_to_string(root.join("dashboard/events.js")).expect("dashboard");
    assert!(dashboard.contains("résumé.txt\\u003cscript\\u003e"));
    assert!(dashboard.contains("Source IDs are not verified identities"));
    fs::remove_dir_all(base).expect("owned fixture cleanup");
}
