use opsforge_investigate::{collect, config::RunConfig};
use std::{fs, process::Command};

#[test]
fn compressed_logs_keep_original_and_decoded_line_references_and_report_bad_crc() {
    let base = std::env::temp_dir().join(format!("opsforge-gzip-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let text = base.join("access.log");
    let line = "127.0.0.1 - - [09/Oct/2026:10:00:00 +0000] \"PUT /fixture HTTP/1.1\" 201 0\n";
    fs::write(&text, line.repeat(1301)).expect("text");
    let gzip = Command::new("gzip")
        .args(["-c", "--"])
        .arg(&text)
        .output()
        .expect("gzip fixture dependency");
    assert!(gzip.status.success());
    let good = base.join("good.log.gz");
    let bad = base.join("bad.log.gz");
    fs::write(&good, &gzip.stdout).expect("compressed");
    let mut corrupt = gzip.stdout.clone();
    let crc = corrupt.len() - 8;
    corrupt[crc] ^= 1;
    fs::write(&bad, &corrupt).expect("bad crc");
    fs::write(&text, "").expect("empty text");
    let empty_gzip = Command::new("gzip")
        .args(["-c", "--"])
        .arg(&text)
        .output()
        .expect("empty gzip");
    assert!(empty_gzip.status.success());
    let empty = base.join("empty.log.gz");
    fs::write(&empty, empty_gzip.stdout).expect("empty compressed");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports = vec![good, bad, empty];
    let root = collect::run(&config, &|_| {}).expect("case survives bad stream");
    assert_eq!(
        fs::read(root.join("raw/import-000-000000")).expect("original"),
        gzip.stdout
    );
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000.decoded")).expect("decoded"),
        line.repeat(1301)
    );
    let rows: Vec<serde_json::Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .expect("events")
        .lines()
        .map(|line| serde_json::from_str(line).expect("event"))
        .collect();
    assert_eq!(rows.len(), 1301);
    assert_eq!(rows[0]["transfer"]["direction"], "upload");
    assert_eq!(rows[0]["evidence"], "raw/import-000-000000.decoded");
    assert_eq!(rows[0]["evidence_line"], 1);
    assert_eq!(rows[1300]["evidence_line"], 1301);
    assert!(
        fs::read_to_string(root.join("manifest.jsonl"))
            .expect("manifest")
            .contains("derived gzip -cd output")
    );
    let coverage: Vec<serde_json::Value> =
        fs::read_to_string(root.join("normalized/coverage.jsonl"))
            .expect("coverage")
            .lines()
            .map(|line| serde_json::from_str(line).expect("row"))
            .collect();
    assert!(coverage.iter().any(|row| {
        row["source"]
            .as_str()
            .is_some_and(|source| source.ends_with("bad.log.gz"))
            && row["state"] == "failed"
    }));
    assert!(coverage.iter().any(|row| {
        row["source"]
            .as_str()
            .is_some_and(|source| source.ends_with("empty.log.gz"))
            && row["state"] == "empty"
    }));
    assert!(
        fs::read_to_string(root.join("raw/import-001-000000.gzip.stderr"))
            .expect("stderr")
            .contains("crc error")
    );
    assert!(root.join("completion.json").exists());
    fs::remove_dir_all(base).expect("cleanup");
}
