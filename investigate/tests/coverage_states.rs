use opsforge_investigate::{
    case::{Coverage, CoverageState},
    collect,
    config::RunConfig,
};
use std::fs;

#[test]
fn missing_import_is_unavailable_in_json_and_offline_dashboard() {
    let base = std::env::temp_dir().join(format!("opsforge-unavailable-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let mut config = RunConfig::default_for(base.clone());
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.push(base.join("absent.log"));
    let root = collect::run(&config, &|_| {}).expect("case");
    let coverage = fs::read_to_string(root.join("normalized/coverage.jsonl")).expect("coverage");
    let rows: Vec<Coverage> = coverage
        .lines()
        .map(|line| serde_json::from_str(line).expect("row"))
        .collect();
    assert!(
        rows.iter()
            .any(|row| matches!(row.state, CoverageState::Unavailable)
                && row.source.ends_with("absent.log"))
    );
    let data = fs::read_to_string(root.join("dashboard/case.js")).expect("dashboard");
    assert!(data.contains("unavailable"));
    for status in [
        "denied",
        "cancelled",
        "failed",
        "unsupported",
        "collected",
        "empty",
        "skipped",
    ] {
        let row: Coverage = serde_json::from_str(&format!(
            r#"{{"source":"fixture","state":"{status}","detail":"fixture"}}"#
        ))
        .expect("status");
        assert!(
            serde_json::to_string(&row)
                .expect("serialize")
                .contains(status)
        );
    }
    fs::remove_dir_all(base).expect("fixture cleanup");
}
