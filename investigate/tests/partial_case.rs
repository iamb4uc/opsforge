use opsforge_investigate::{collect, config::RunConfig};
use std::{cell::RefCell, fs, io::Write, path::PathBuf};

#[test]
fn failed_report_preserves_initial_dashboard_and_raw_evidence() {
    let sample = std::env::var_os("OPSFORGE_PARTIAL_OUTPUT");
    let base = sample.as_ref().map(PathBuf::from).unwrap_or_else(|| {
        std::env::temp_dir().join(format!("opsforge-partial-case-{}", std::process::id()))
    });
    fs::create_dir_all(&base).expect("fixture directory");
    let imported = base.join("proxy.log");
    fs::write(&imported, "POST https://example.test/upload\n").expect("fixture");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(imported);
    let root = RefCell::new(None::<PathBuf>);
    let error = collect::run(&config, &|message| {
        if let Some(path) = message.strip_prefix("Case created: ") {
            *root.borrow_mut() = Some(PathBuf::from(path));
        }
        if message == "Building offline dashboard" {
            let root = root.borrow();
            let path = root.as_ref().expect("case path");
            fs::OpenOptions::new()
                .append(true)
                .open(path.join("normalized/events.jsonl"))
                .expect("events")
                .write_all(b"{truncated\n")
                .expect("damaged final row");
        }
    })
    .expect_err("damaged events reject final report");
    let root = root.into_inner().expect("case created");
    assert!(format!("{error:#}").contains(&root.display().to_string()));
    let completion: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("completion.json")).expect("status"))
            .expect("valid status");
    assert_eq!(completion["status"], "failed");
    assert!(completion["error"].as_str().is_some());
    let script = fs::read_to_string(root.join("dashboard/events.js")).expect("initial events");
    assert_eq!(script, "window.caseEvents = [\n\n];\n");
    assert!(root.join("dashboard/index.html").exists());
    assert!(
        fs::read_to_string(root.join("dashboard/completion.js"))
            .expect("status script")
            .contains("failed")
    );
    assert_eq!(
        fs::read_to_string(root.join("raw/import-000-000000")).expect("retained raw"),
        "POST https://example.test/upload\n"
    );
    assert!(root.join("checksums.sha256").exists());
    if sample.is_none() {
        fs::remove_dir_all(base).expect("remove owned fixture");
    }
}
