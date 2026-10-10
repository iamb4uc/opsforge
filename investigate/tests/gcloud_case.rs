use opsforge_investigate::{collect, config::RunConfig};
use std::fs;

#[test]
fn cloud_manifests_preserve_per_file_results_and_partial_csv_errors() {
    let base = std::env::temp_dir().join(format!("opsforge-gcloud-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let manifest = base.join("manifest.csv");
    let header =
        "Source,Destination,Start,End,Md5,Source Size,Bytes Transferred,Result,Description\r\n";
    let rows = concat!(
        "\"file:///local/name, with \"\"quotes\"\"\nsecond.txt\",gs://bucket/object,2026-10-10T05:35:56Z,2026-10-10T05:35:57Z,,39,39,OK,\r\n",
        "file:///local/denied.txt,gs://bucket/denied,2026-10-10T05:35:56Z,2026-10-10T05:35:57Z,,39,0,error,Permission denied\r\n",
        "gs://bucket/skipped,file:///local/skipped,2026-10-10T05:35:56Z,2026-10-10T05:35:57Z,,39,0,skip,No clobber\r\n",
        "gs://bucket/object,gs://other/copy,2026-10-10T05:35:56Z,2026-10-10T05:35:57Z,,39,0,OK,\r\n",
        "file:///local/a,file:///local/b,,,,39,0,OK,\r\n",
        "file:///local/unknown,gs://bucket/unknown,,,,39,0,unknown,\r\n"
    );
    fs::write(&manifest, format!("{header}{rows}")).expect("manifest");
    let partial = base.join("truncated.csv");
    fs::write(&partial, format!("{header}\"unfinished\n")).expect("truncated");
    let empty = base.join("empty.csv");
    fs::write(&empty, header).expect("empty");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.extend([manifest, partial, empty]);
    let root = collect::run(&config, &|_| {}).expect("case");
    let events: Vec<serde_json::Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .expect("events")
        .lines()
        .map(|line| serde_json::from_str(line).expect("event"))
        .collect();
    assert_eq!(events.len(), 6);
    assert_eq!(
        events[0]["transfer"]["file"],
        "file:///local/name, with \"quotes\"\nsecond.txt"
    );
    assert_eq!(events[0]["transfer"]["status"], "completed");
    assert_eq!(events[0]["transfer"]["bytes"], 39);
    assert_eq!(events[1]["transfer"]["status"], "failed");
    assert!(events[1]["transfer"]["bytes"].is_null());
    assert_eq!(events[1]["evidence_line"], 4);
    assert_eq!(events[2]["transfer"]["status"], "skipped");
    assert!(events[2]["transfer"]["bytes"].is_null());
    assert!(events[3..].iter().all(|event| event["transfer"].is_null()));
    assert!(
        events
            .iter()
            .all(|event| event["user"].is_null() && event["transfer"]["peer"].is_null())
    );
    let coverage = fs::read_to_string(root.join("normalized/coverage.jsonl")).expect("coverage");
    assert!(coverage.contains("unterminated transfer manifest record"));
    assert!(coverage.contains("\"state\":\"failed\"") && coverage.contains("\"state\":\"empty\""));
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).expect("raw"),
        format!("{header}{rows}")
    );
    assert!(
        fs::read_to_string(root.join("dashboard/events.js"))
            .expect("dashboard")
            .contains("manifest sentinel")
    );
    fs::remove_dir_all(base).expect("fixture cleanup");
}
