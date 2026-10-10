use opsforge_investigate::{collect, config::RunConfig};
use serde_json::Value;
use std::fs;

#[test]
fn docker_envelopes_keep_raw_bodies_and_runtime_provenance() {
    let base = std::env::temp_dir().join(format!("opsforge-docker-case-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let id = "a".repeat(64);
    let fixtures = [
        (
            format!("{id}-json.log"),
            "{\"log\":\"uploaded private-fixture.txt\\n\",\"stream\":\"stdout\",\"time\":\"2026-10-10T12:00:00.123456789+02:00\",\"attrs\":{\"fixture\":\"not-normalized\"}}\n{\"log\":\"downloaded fixture\\n\",\"stream\":\"stderr\",\"time\":\"bad\"}\n{\"log\":\"bad stream\",\"stream\":\"other\",\"time\":\"2026-10-10T00:00:00Z\"}\n{\"log\":123,\"stream\":\"stdout\",\"time\":\"2026-10-10T00:00:00Z\"}\ntruncated\n",
        ),
        (
            format!("docker-log-{id}.txt"),
            "2026-10-10T00:00:00.000000001Z fixture upload\nnot a runtime line\n",
        ),
        (
            format!("docker-log-{id}.stderr.txt"),
            "2026-10-10T00:00:01Z fixture diagnostic\nError response from daemon: fixture\n",
        ),
        (format!("{}-json.log", "b".repeat(64)), ""),
        (
            "offline.jsonl".into(),
            "{\"log\":\"unclaimed body\",\"stream\":\"stdout\",\"time\":\"1970-01-01T00:00:00Z\"}\n",
        ),
        ("unrelated.jsonl".into(), "{\"log\":\"ordinary text\"}\n"),
    ];
    let mut config = RunConfig::default_for(base.join("cases"));
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    for (name, content) in &fixtures {
        let path = base.join(name);
        fs::write(&path, content).unwrap();
        config.imports.push(path);
    }
    let root = collect::run(&config, &|_| {}).unwrap();
    let events: Vec<Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let rows: Vec<_> = events
        .iter()
        .filter(|row| row["kind"] == "container-log-reference")
        .collect();
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[0]["timestamp"], "2026-10-10T10:00:00.123456789Z");
    assert!(rows[1]["timestamp"].is_null());
    assert_eq!(rows[2]["timestamp"], "2026-10-10T00:00:00.000000001Z");
    assert_eq!(rows[3]["evidence_line"], 1);
    for row in &rows {
        assert!(row["transfer"].is_null() && row["destination"].is_null() && row["user"].is_null());
        assert_eq!(row["level"], "recorded");
        let detail = row["detail"].as_str().unwrap();
        assert!(!detail.contains("private-fixture.txt") && !detail.contains("not-normalized"));
        assert!(detail.contains("not file/network bytes"));
    }
    let metadata: Value = serde_json::from_str(
        rows[4]["detail"]
            .as_str()
            .unwrap()
            .split('\n')
            .next()
            .unwrap(),
    )
    .unwrap();
    assert!(metadata["container_source_label"].is_null());
    assert_eq!(metadata["log_text_utf8_bytes"], 14);
    assert_eq!(
        events
            .iter()
            .filter(|row| row["transfer"].is_object())
            .count(),
        0
    );
    let coverage = fs::read_to_string(root.join("normalized/coverage.jsonl")).unwrap();
    for detail in [
        "invalid Docker runtime time",
        "unknown Docker JSON stream",
        "unsupported Docker JSON envelope",
        "invalid Docker JSON envelope",
        "Docker CLI diagnostic",
        "\"state\":\"empty\"",
    ] {
        assert!(coverage.contains(detail), "{detail}");
    }
    for (index, (name, content)) in fixtures.iter().enumerate() {
        assert_eq!(
            fs::read_to_string(root.join(format!("raw/import-{index:03}-000000"))).unwrap(),
            *content
        );
        assert_eq!(fs::read_to_string(base.join(name)).unwrap(), *content);
    }
    assert!(
        fs::read_to_string(root.join("dashboard/app.js"))
            .unwrap()
            .contains("container-log-reference")
    );
    fs::remove_dir_all(base).unwrap();
}
