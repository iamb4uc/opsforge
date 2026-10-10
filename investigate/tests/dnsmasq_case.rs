use opsforge_investigate::{collect, config::RunConfig, transfers::dnsmasq_event};
use serde_json::Value;
use std::fs;

#[test]
fn dnsmasq_logger_and_time_boundaries() {
    let bare = "123 2001:db8::1/12345 query[AAAA] example.test from 2001:db8::1";
    let event = dnsmasq_event(bare, Some("dnsmasq"), "journal", "raw/journal.jsonl").unwrap();
    assert!(event.timestamp.is_none());
    assert!(event.user.is_none());
    assert!(event.transfer.is_none());
    assert!(event.detail.contains("2001:db8::1/12345"));
    assert!(dnsmasq_event(bare, Some("other"), "journal", "raw/log").is_none());
    assert!(
        dnsmasq_event(
            "dnsmasq[1]: query[A] example.test from 127.0.0.1",
            Some("other"),
            "journal",
            "raw/log"
        )
        .is_none()
    );
    for line in [
        "dnsmasq[bad]: query[A] example.test from 127.0.0.1",
        "other[1]: query[A] example.test from 127.0.0.1",
        "dnsmasq[1]: 1 unknown/10 query[A] example.test from 127.0.0.1",
        "dnsmasq[1]: 1 127.0.0.1/99999 reply example.test is NXDOMAIN",
        "dnsmasq[1]: query[] example.test from 127.0.0.1",
        "dnsmasq[1]: query[A] example.test from bad-ip",
        "dnsmasq[1]: reply example.test is",
        "dnsmasq[1]: started, version 2.91",
    ] {
        assert!(
            dnsmasq_event(line, None, "log", "raw/log").is_none(),
            "{line}"
        );
    }
    let event = dnsmasq_event(
        "2026-10-10T12:30:00+05:30 dnsmasq[1]: reply example.test is NXDOMAIN",
        None,
        "log",
        "raw/log",
    )
    .unwrap();
    assert_eq!(event.timestamp.as_deref(), Some("2026-10-10T07:00:00Z"));
    let unassociated = dnsmasq_event(
        "dnsmasq[1]: reply example.test is text with spaces",
        None,
        "log",
        "raw/log",
    )
    .unwrap();
    assert!(unassociated.detail.contains("\"requester\":null"));
    assert!(unassociated.detail.contains("text with spaces"));
}

#[test]
fn retained_dns_records_keep_raw_provenance_without_transfers() {
    let base = std::env::temp_dir().join(format!("opsforge-dnsmasq-case-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let path = base.join("dnsmasq.log");
    let input = "Oct 10 12:30:00 dnsmasq[1]: query[A] example.test from 127.0.0.1\nOct 10 12:30:00 dnsmasq[1]: 1 127.0.0.1/12345 forwarded example.test to 127.0.0.1#15353\nOct 10 12:30:00 dnsmasq[1]: 1 127.0.0.1/12345 reply example.test is 192.0.2.4\nOct 10 12:30:01 dnsmasq[1]: cached example.test is 192.0.2.4\nOct 10 12:30:02 dnsmasq[1]: reply missing.test is NXDOMAIN\nOct 10 12:30:03 dnsmasq[1]: reply error is REFUSED\n";
    fs::write(&path, input).unwrap();
    let mut config = RunConfig::default_for(base.join("cases"));
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(path.clone());
    let root = collect::run(&config, &|_| {}).unwrap();
    let events: Vec<Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 6);
    for (i, event) in events.iter().enumerate() {
        assert!(event["timestamp"].is_null());
        assert!(event["user"].is_null());
        assert!(event["destination"].is_null());
        assert!(event["transfer"].is_null());
        assert_eq!(event["evidence_line"], i + 1);
        assert_eq!(event["level"], "recorded");
    }
    assert_eq!(events[0]["kind"], "dns-query");
    assert_eq!(events[1]["kind"], "dns-forwarded");
    assert_eq!(events[3]["kind"], "dns-cached");
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).unwrap(),
        input
    );
    assert_eq!(fs::read_to_string(path).unwrap(), input);
    assert!(
        fs::read_to_string(root.join("dashboard/app.js"))
            .unwrap()
            .contains("\"dns-query\"")
    );
    fs::remove_dir_all(base).unwrap();
}
