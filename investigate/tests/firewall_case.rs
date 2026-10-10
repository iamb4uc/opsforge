use opsforge_investigate::{
    collect,
    config::RunConfig,
    transfers::{firewall_event, firewall_journal_event},
};
use serde_json::{Value, json};
use std::fs;

#[test]
fn kernel_packet_fields_keep_layers_and_logger_boundaries() {
    let message = "fixture IN= OUT=fixture0 SRC=192.0.2.1 DST=192.0.2.2 LEN=53 PROTO=UDP SPT=12345 DPT=15555 LEN=33 UID=0";
    let event = firewall_event(message, Some("kernel"), "journal", "raw/log").unwrap();
    let metadata: Value = serde_json::from_str(event.detail.split('\n').next().unwrap()).unwrap();
    assert_eq!(metadata["source_fields"]["LEN"], json!(["53", "33"]));
    assert_eq!(metadata["logged_ip_packet_bytes"], 53);
    assert_eq!(metadata["logged_udp_datagram_bytes"], 33);
    let prefixed = firewall_event(
        &format!("LEN=999 {message}"),
        Some("kernel"),
        "journal",
        "raw/log",
    )
    .unwrap();
    assert!(prefixed.detail.contains("\"logged_ip_packet_bytes\":53"));
    assert!(event.timestamp.is_none() && event.transfer.is_none() && event.user.is_none());
    assert!(firewall_event(message, Some("logger"), "journal", "raw/log").is_none());
    assert!(firewall_event(message, None, "text", "raw/log").is_none());
    let source =
        json!({"_TRANSPORT":"kernel","MESSAGE":message,"__REALTIME_TIMESTAMP":"0","_UID":"0"});
    assert_eq!(
        firewall_journal_event(&source, "journal", "raw/log")
            .unwrap()
            .timestamp
            .as_deref(),
        Some("1970-01-01T00:00:00Z")
    );
    assert!(
        firewall_journal_event(
            &json!({"_COMM":"kernel","MESSAGE":message}),
            "journal",
            "raw/log"
        )
        .is_none()
    );
    assert!(
        firewall_journal_event(
            &json!({"_TRANSPORT":"stdout","MESSAGE":message}),
            "journal",
            "raw/log"
        )
        .is_none()
    );
    for invalid in [
        message.replace("192.0.2.1", "not-ip"),
        message.replace("LEN=53", "LEN=bad"),
        format!("{message} SRC=192.0.2.3"),
        format!("{message} LEN=999"),
        message.replace("PROTO=UDP", "PROTO=TCP"),
    ] {
        assert!(
            firewall_event(&invalid, Some("kernel"), "journal", "raw/log").is_none(),
            "{invalid}"
        );
    }
    let icmp = firewall_event("kernel: IN=fixture0 OUT= SRC=2001:db8::1 DST=2001:db8::2 LEN=84 ID=1 PROTO=ICMPv6 ID=2 TYPE=128 CODE=0", None, "text", "raw/log").unwrap();
    let metadata: Value = serde_json::from_str(icmp.detail.split('\n').next().unwrap()).unwrap();
    assert_eq!(metadata["source_fields"]["ID"], json!(["1", "2"]));
    assert!(metadata["logged_udp_datagram_bytes"].is_null());
}

#[test]
fn retained_kernel_journal_and_plaintext_keep_source_lines() {
    let base = std::env::temp_dir().join(format!("opsforge-firewall-case-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let message =
        "[UFW BLOCK] IN=fixture0 OUT= SRC=192.0.2.1 DST=192.0.2.2 LEN=84 PROTO=ICMP TYPE=8 CODE=0";
    let fixtures = [
        format!(
            "Oct 10 12:30:00 fixture kernel: {message}\n2026-10-10T12:30:00+05:30 fixture kernel: {message}\n"
        ),
        format!(
            "{}\n{}\n",
            json!({"_TRANSPORT":"kernel","MESSAGE":message,"__REALTIME_TIMESTAMP":"1791549000000005"}),
            json!({"_TRANSPORT":"kernel","MESSAGE":message,"__REALTIME_TIMESTAMP":"bad"})
        ),
    ];
    let mut config = RunConfig::default_for(base.join("cases"));
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    for (i, content) in fixtures.iter().enumerate() {
        let path = base.join(format!("packet-{i}.log"));
        fs::write(&path, content).unwrap();
        config.imports.push(path);
    }
    let root = collect::run(&config, &|_| {}).unwrap();
    let rows: Vec<Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 4);
    assert!(rows[0]["timestamp"].is_null());
    assert_eq!(rows[1]["timestamp"], "2026-10-10T07:00:00Z");
    assert_eq!(rows[2]["timestamp"], "2026-10-09T12:30:00.000005Z");
    assert!(rows[3]["timestamp"].is_null());
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row["kind"], "firewall-packet");
        assert_eq!(row["evidence_line"], i % 2 + 1);
        assert!(row["transfer"].is_null() && row["user"].is_null() && row["destination"].is_null());
        assert!(
            row["detail"]
                .as_str()
                .unwrap()
                .contains("custom prefix is not a verified verdict")
        );
    }
    for (i, content) in fixtures.iter().enumerate() {
        assert_eq!(
            fs::read_to_string(root.join(format!("raw/import-{i:03}-000000"))).unwrap(),
            *content
        );
        assert_eq!(fs::read_to_string(&config.imports[i]).unwrap(), *content);
    }
    assert!(
        fs::read_to_string(root.join("dashboard/app.js"))
            .unwrap()
            .contains("firewall-packet")
    );
    fs::remove_dir_all(base).unwrap();
}
