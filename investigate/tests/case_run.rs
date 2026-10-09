use opsforge_investigate::{collect, config::RunConfig};
use std::fs;

#[test]
fn imported_log_reaches_offline_report_with_escaped_text() {
    let sample = std::env::var_os("OPSFORGE_SAMPLE_OUTPUT");
    let base = sample
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("opsforge-case-run-{}", std::process::id()))
        });
    fs::create_dir_all(&base).expect("base");
    let imported = base.join("proxy.log");
    fs::write(
        &imported,
        "POST https://example.test/upload <script>alert(1)</script>\n",
    )
    .expect("fixture");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(imported);
    let root = collect::run(&config, &|_| {}).expect("case run");
    let events = fs::read_to_string(root.join("normalized/events.jsonl")).expect("events");
    let page = fs::read_to_string(root.join("dashboard/network.html")).expect("dashboard");
    let data = fs::read_to_string(root.join("dashboard/events.js")).expect("event data");
    assert!(events.contains("network-lead"));
    assert!(data.contains("\\u003cscript\\u003e"));
    assert!(!data.contains("<script>"));
    assert!(page.contains("script-src 'self'"));
    assert!(root.join("raw/import-000-000000").exists());
    assert!(root.join("findings.json").exists());
    assert!(root.join("completion.json").exists());
    let completion: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("completion.json")).expect("status"))
            .expect("valid status");
    assert_eq!(completion["status"], "finished_review_coverage");
    assert!(completion["finished_at"].is_string());
    assert!(
        fs::read_to_string(root.join("checksums.sha256"))
            .expect("checksums")
            .contains("raw/import-000-000000")
    );
    if sample.is_none() {
        fs::remove_dir_all(base).expect("remove fixture");
    }
}
