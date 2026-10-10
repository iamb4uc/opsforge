use opsforge_investigate::{collect, config::RunConfig};
use serde_json::Value;
use std::fs;

#[test]
fn openvpn_snapshots_keep_perspective_time_and_partial_rows() {
    let base = std::env::temp_dir().join(format!("opsforge-openvpn-case-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let header = "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since";
    let fixtures = [
        format!(
            "OpenVPN CLIENT LIST\nUpdated,2026-10-10 12:30:00\nTIME,foreign format,0\n{header}\nfixture,192.0.2.1:1194,0,999,2026-10-10 12:00:00\nROUTING TABLE\nEND\n"
        ),
        format!(
            "TITLE,OpenVPN fixture\nTIME,ambiguous local time,0\nHEADER,CLIENT_LIST,{header},Connected Since (time_t),Future Field\nCLIENT_LIST,fixture,192.0.2.1:1194,18446744073709551615,123,unknown,0,retained\nEND\n"
        ),
        format!(
            "TITLE\tOpenVPN fixture\nTIME\tunknown\t1791549000\nHEADER\tCLIENT_LIST\t{}\nCLIENT_LIST\tfixture\t[2001:db8::1]:1194\tbad\t18446744073709551616\tunknown\n",
            header.replace(',', "\t")
        ),
        format!(
            "TITLE,OpenVPN fixture\nTIME,unknown,bad\nHEADER,CLIENT_LIST,{header}\nCLIENT_LIST,too,few\nEND\n"
        ),
        format!("TITLE,OpenVPN fixture\nTIME,unknown,0\nHEADER,CLIENT_LIST,{header}\nEND\n"),
        "TITLE,unrelated text\nCLIENT_LIST,not openvpn\n".into(),
        "TITLE,OpenVPN fixture\nHEADER,CLIENT_LIST,Common Name,Common Name\nCLIENT_LIST,a,b\nEND\n"
            .into(),
    ];
    let mut config = RunConfig::default_for(base.join("cases"));
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    for (i, fixture) in fixtures.iter().enumerate() {
        let path = base.join(format!("status-{i}.log"));
        fs::write(&path, fixture).unwrap();
        config.imports.push(path);
    }
    let root = collect::run(&config, &|_| {}).unwrap();
    let events: Vec<Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let vpn: Vec<_> = events
        .iter()
        .filter(|row| row["kind"] == "vpn-session-snapshot")
        .collect();
    assert_eq!(vpn.len(), 3);
    assert!(vpn[0]["timestamp"].is_null());
    assert_eq!(vpn[1]["timestamp"], "1970-01-01T00:00:00Z");
    assert_eq!(vpn[2]["timestamp"], "2026-10-09T12:30:00Z");
    assert_eq!(vpn[0]["evidence_line"], 5);
    assert!(
        vpn[0]["detail"]
            .as_str()
            .unwrap()
            .contains("\"received_link_bytes\":0")
    );
    assert!(
        vpn[1]["detail"]
            .as_str()
            .unwrap()
            .contains("18446744073709551615")
    );
    assert!(vpn[1]["detail"].as_str().unwrap().contains("Future Field"));
    assert!(
        vpn[2]["detail"]
            .as_str()
            .unwrap()
            .contains("\"received_link_bytes\":null")
    );
    assert!(
        vpn[2]["detail"]
            .as_str()
            .unwrap()
            .contains("\"sent_link_bytes\":null")
    );
    assert!(vpn.iter().all(|row| row["transfer"].is_null()
        && row["user"].is_null()
        && row["destination"].is_null()
        && row["level"] == "recorded"));
    let coverage = fs::read_to_string(root.join("normalized/coverage.jsonl")).unwrap();
    for detail in [
        "invalid OpenVPN cumulative",
        "END marker missing",
        "invalid OpenVPN status UNIX",
        "field count mismatch",
        "unique columns missing",
        "\"state\":\"empty\"",
    ] {
        assert!(coverage.contains(detail), "{detail}");
    }
    for (i, fixture) in fixtures.iter().enumerate() {
        assert_eq!(
            fs::read_to_string(root.join(format!("raw/import-{i:03}-000000"))).unwrap(),
            *fixture
        );
        assert_eq!(fs::read_to_string(&config.imports[i]).unwrap(), *fixture);
    }
    assert!(
        fs::read_to_string(root.join("dashboard/app.js"))
            .unwrap()
            .contains("vpn-session-snapshot")
    );
    fs::remove_dir_all(base).unwrap();
}
