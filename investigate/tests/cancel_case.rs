use opsforge_investigate::{collect, config::RunConfig};
use std::{cell::RefCell, fs, path::PathBuf, process::Command};

#[test]
fn term_signal_keeps_saved_records_and_finalizes_a_cancelled_case() {
    collect::install_signal_handlers().expect("signal handlers");
    let base = std::env::temp_dir().join(format!("opsforge-cancel-case-{}", std::process::id()));
    let imports = base.join("imports");
    fs::create_dir_all(&imports).expect("fixture directory");
    for index in 0..101 {
        fs::write(
            imports.join(format!("{index}.log")),
            "POST https://example.test/upload\n",
        )
        .expect("fixture log");
    }
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(imports);
    let root = RefCell::new(None::<PathBuf>);
    let error = collect::run(&config, &|message| {
        if let Some(path) = message.strip_prefix("Case created: ") {
            *root.borrow_mut() = Some(PathBuf::from(path));
        }
        if message == "import-000: 100 files saved" {
            fs::write(
                root.borrow()
                    .as_ref()
                    .expect("case path")
                    .join("raw/orphan.log"),
                b"partial bytes",
            )
            .expect("unmanifested partial file");
            assert!(
                Command::new("kill")
                    .args(["-TERM", &std::process::id().to_string()])
                    .status()
                    .expect("signal own test process")
                    .success()
            );
        }
    })
    .expect_err("cancelled collection");
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .expect("io interruption")
            .kind(),
        std::io::ErrorKind::Interrupted
    );
    let root = root.into_inner().expect("case path");
    let completion: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("completion.json")).expect("completion"))
            .expect("status");
    assert_eq!(completion["status"], "cancelled");
    assert!(
        completion["error"]
            .as_str()
            .expect("cancel reason")
            .contains("SIGTERM")
    );
    assert_eq!(
        fs::read_to_string(root.join("normalized/events.jsonl"))
            .expect("saved events")
            .lines()
            .count(),
        100
    );
    assert!(
        fs::read_to_string(root.join("normalized/coverage.jsonl"))
            .expect("coverage")
            .contains("cancelled")
    );
    assert!(
        fs::read_to_string(root.join("dashboard/events.js"))
            .expect("partial report")
            .contains("example.test/upload")
    );
    assert!(root.join("checksums.sha256").exists());
    let manifest = fs::read_to_string(root.join("manifest.jsonl")).expect("manifest");
    let partial: serde_json::Value = manifest
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("manifest row"))
        .find(|row| row["path"] == "raw/orphan.log")
        .expect("partial raw record");
    assert!(
        partial["source"]
            .as_str()
            .expect("source gap")
            .contains("source mapping unavailable")
    );
    assert_eq!(partial["bytes"], 13);
    assert_eq!(partial["sha256"].as_str().expect("hash").len(), 64);
    fs::remove_dir_all(base).expect("remove owned fixture");
}
