use opsforge_investigate::{collect, config::RunConfig, transfers::Parser};
use serde_json::Value;
use std::fs;

#[test]
fn squid_default_format_rejects_ambiguous_or_custom_rows() {
    let line =
        "0.001 0 2001:db8::1 TCP_TUNNEL/200 0 CONNECT example.test:443 - HIER_DIRECT/2001:db8::2 -";
    let mut parser = Parser::default();
    let row = parser.parse(line, "proxy", "raw/log").unwrap();
    assert_eq!(row.timestamp.as_deref(), Some("1970-01-01T00:00:00.001Z"));
    assert!(row.transfer.is_none() && row.user.is_none() && row.destination.is_none());
    assert!(row.detail.contains("\"reply_traffic_bytes\":0"));
    for invalid in [
        line.replace("0.001", "0.1"),
        line.replace("0.001", "9999999999999999999.000"),
        line.replace("TCP_TUNNEL/200", "other/200"),
        line.replace("TCP_TUNNEL/200", "TCP_TUNNEL/999"),
        line.replace("TCP_TUNNEL/200", "TCP_TUNNEL/bad"),
        line.replace("2001:db8::1", "not-ip"),
        line.replace("CONNECT", "lowercase"),
        line.replace(" 0 CONNECT", " bad CONNECT"),
        line.replace("HIER_DIRECT/", "custom/"),
        format!("{line} appended headers"),
    ] {
        assert!(
            parser.parse(&invalid, "proxy", "raw/log").is_none(),
            "{invalid}"
        );
    }
}

#[test]
fn squid_outcomes_keep_reply_counter_basis_and_raw_lines() {
    let base = std::env::temp_dir().join(format!("opsforge-squid-case-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let path = base.join("access.log");
    let content = "1791549000.123 1 127.0.0.1 TCP_MISS/200 330 GET http://example.test/report.txt - HIER_DIRECT/192.0.2.1 text/plain\n1791549001.000 0 127.0.0.1 TCP_MEM_HIT/200 339 GET http://example.test/report.txt - HIER_NONE/- text/plain\n1791549002.000 1 127.0.0.1 TCP_MISS/200 264 POST http://example.test/upload source-label HIER_DIRECT/192.0.2.1 text/plain\n1791549003.000 0 127.0.0.1 TCP_DENIED/403 3440 GET http://example.test/denied - HIER_NONE/- text/html\n1791549004.000 5 127.0.0.1 TCP_TUNNEL/200 2162 CONNECT example.test:443 - HIER_DIRECT/192.0.2.1 -\n1791549005.000 0 127.0.0.1 TCP_MISS/404 314 GET http://example.test/missing - HIER_DIRECT/192.0.2.1 text/plain\n";
    fs::write(&path, content).unwrap();
    let mut config = RunConfig::default_for(base.join("cases"));
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(path.clone());
    let root = collect::run(&config, &|_| {}).unwrap();
    let rows: Vec<Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 6);
    assert_eq!(rows[0]["timestamp"], "2026-10-09T12:30:00.123Z");
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row["kind"], "proxy-request");
        assert_eq!(row["evidence_line"], i + 1);
        assert!(row["transfer"].is_null() && row["user"].is_null() && row["destination"].is_null());
        assert_eq!(row["level"], "recorded");
        assert!(
            row["detail"]
                .as_str()
                .unwrap()
                .contains("not request/upload bytes")
        );
    }
    assert!(
        rows[2]["detail"]
            .as_str()
            .unwrap()
            .contains("\"reply_traffic_bytes\":264")
    );
    assert!(rows[2]["detail"].as_str().unwrap().contains("source-label"));
    assert!(
        rows[4]["detail"]
            .as_str()
            .unwrap()
            .contains("do not reveal its encrypted HTTP methods")
    );
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).unwrap(),
        content
    );
    assert_eq!(fs::read_to_string(path).unwrap(), content);
    assert!(
        fs::read_to_string(root.join("dashboard/app.js"))
            .unwrap()
            .contains("proxy-request")
    );
    fs::remove_dir_all(base).unwrap();
}
