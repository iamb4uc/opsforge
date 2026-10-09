use crate::{
    browser,
    case::{Case, Coverage, CoverageState, Event, EvidenceLevel},
    collect,
};
use anyhow::Result;
use std::{collections::BTreeSet, path::Path};
use walkdir::WalkDir;

const LOCATIONS: &[(&str, &str)] = &[
    ("rclone", ".cache/rclone"),
    ("rclone", ".local/state/rclone"),
    ("rclone", ".local/share/rclone"),
    ("rclone", ".config/rclone/logs"),
    ("rclone", "rclone.log"),
    ("rclone", ".cache/rclone.log"),
    ("rsync", ".local/state/rsync"),
    ("rsync", "rsync.log"),
    ("OpenSSH", ".ssh/logs"),
    ("FileZilla", ".config/filezilla/logs"),
    ("FileZilla", "filezilla.log"),
    ("AWS CLI", ".aws/cli/history"),
    ("Azure CLI", ".azure/commands"),
    ("gcloud", ".config/gcloud/logs"),
    ("Nextcloud", ".local/share/Nextcloud"),
    ("Nextcloud", ".config/Nextcloud/logs"),
    ("Syncthing", ".local/state/syncthing"),
    ("Syncthing", ".config/syncthing"),
    ("Thunderbird", ".thunderbird"),
    ("Evolution", ".local/share/evolution/logs"),
    ("Slack", ".config/Slack/logs"),
    ("Discord", ".config/discord/logs"),
    ("Element", ".config/Element/logs"),
    ("Signal", ".config/Signal/logs"),
    ("curl", "curl.log"),
    ("wget", "wget-log"),
];

pub(crate) fn collect(case: &mut Case, progress: &impl Fn(&str)) -> Result<()> {
    let mut attempted = 0;
    let mut parsed = 0;
    let mut failed = 0;
    for (user, home) in browser::user_homes()? {
        let (attempts, files, errors) = collect_home(case, &user, &home, attempted, progress)?;
        attempted += attempts;
        parsed += files;
        failed += errors;
    }
    case.coverage(&Coverage {
        source: "application-transfer-logs".into(),
        state: if failed > 0 { CoverageState::Failed } else if parsed == 0 { CoverageState::Empty } else { CoverageState::Collected },
        detail: format!("{attempted} files attempted; {parsed} files parsed; {failed} errors; discovery is limited to listed locations, depth 8, and recognized log names; use imports for custom paths; absent logs do not prove absent activity"),
    })?;
    Ok(())
}

fn collect_home(
    case: &mut Case,
    user: &str,
    home: &Path,
    offset: usize,
    progress: &impl Fn(&str),
) -> Result<(usize, usize, usize)> {
    let mut seen = BTreeSet::new();
    let mut attempted = 0;
    let mut parsed_files = 0;
    let mut errors = 0;
    for (application, relative) in LOCATIONS {
        let location = home.join(relative);
        let source = format!("{application}:{user}:{}", location.display());
        match std::fs::symlink_metadata(&location) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                case.coverage(&Coverage { source, state: CoverageState::Unsupported, detail: "discovery root is a symbolic link; select its trusted target explicitly as an import".into() })?;
                continue;
            }
            Ok(_) => {}
            Err(error) => {
                let missing = error.kind() == std::io::ErrorKind::NotFound;
                if !missing {
                    errors += 1;
                }
                case.coverage(&Coverage { source, state: if missing { CoverageState::Empty } else { CoverageState::Failed }, detail: format!("discovery location unavailable: {error}; absent logs do not prove absent activity") })?;
                continue;
            }
        }
        let mut count = 0;
        let mut failed = 0;
        for entry in WalkDir::new(&location).follow_links(false).max_depth(8) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    failed += 1;
                    case.coverage(&Coverage {
                        source: source.clone(),
                        state: CoverageState::Failed,
                        detail: error.to_string(),
                    })?;
                    continue;
                }
            };
            let path = entry.path();
            if !entry.file_type().is_file() || !is_log(path) || !seen.insert(path.to_owned()) {
                continue;
            }
            let name = format!("application-{:06}", offset + attempted);
            attempted += 1;
            progress(&format!(
                "Application log: {application} / {user} / {}",
                path.display()
            ));
            let parsed = if *application == "AWS CLI"
                && path.file_name().is_some_and(|name| name == "history.db")
            {
                aws_history(case, path, &name, user)
            } else {
                case.copy_evidence(path, &name).and_then(|raw| {
                    collect::normalize_text_log(
                        case,
                        &raw,
                        &name,
                        "application-log",
                        path,
                        Some((application, user)),
                    )
                })
            };
            match parsed {
                Ok(lines) => {
                    count += 1;
                    case.coverage(&Coverage { source: path.display().to_string(), state: if lines == 0 { CoverageState::Empty } else { CoverageState::Collected }, detail: format!("{lines} records; application/user derived from discovery location; unrecognized text remains leads") })?;
                }
                Err(error) => {
                    failed += 1;
                    case.coverage(&Coverage {
                        source: path.display().to_string(),
                        state: CoverageState::Failed,
                        detail: format!(
                            "copy or parser failed; inspect any retained raw file: {error}"
                        ),
                    })?;
                }
            }
        }
        case.coverage(&Coverage { source, state: if failed > 0 { CoverageState::Failed } else if count == 0 { CoverageState::Empty } else { CoverageState::Collected }, detail: format!("{count} files parsed; {failed} failed; log-name discovery only; credentials/configuration and message stores are not parsed") })?;
        parsed_files += count;
        errors += failed;
    }
    Ok((attempted, parsed_files, errors))
}

fn is_log(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name == "history.db"
                || name == "wget-log"
                || name.ends_with(".log")
                || name.ends_with(".jsonl")
                || name.contains(".log.")
        })
}

fn aws_history(case: &mut Case, path: &Path, name: &str, user: &str) -> Result<u64> {
    let db = browser::snapshot(case, path, name)?;
    let mut statement = db.prepare(
        "SELECT id,request_id,source,event_type,timestamp,payload FROM records ORDER BY timestamp",
    )?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    let mut failed = 0;
    while let Some(row) = rows.next()? {
        let parsed = (|| -> rusqlite::Result<_> {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
            ))
        })();
        let (command, request, source, kind, time, payload) = match parsed {
            Ok(record) => record,
            Err(error) => {
                failed += 1;
                case.coverage(&Coverage {
                    source: path.display().to_string(),
                    state: CoverageState::Failed,
                    detail: format!("invalid AWS history row: {error}"),
                })?;
                continue;
            }
        };
        case.event(&Event {
            timestamp: jiff::Timestamp::from_millisecond(time).ok().map(|time| time.to_string()),
            source: "aws-cli-history".into(), kind: "application-history".into(),
            application: Some("AWS CLI".into()), user: Some(user.into()), destination: None,
            detail: format!("command_id={command}; request_id={request:?}; source={source}; event_type={kind}; payload={payload}"),
            evidence: format!("raw/{name}"), level: EvidenceLevel::Recorded,
            transfer: None, evidence_line: None,
        })?;
        count += 1;
    }
    if failed > 0 {
        anyhow::bail!("{failed} invalid AWS history rows; {count} valid rows retained");
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn application_logs_preserve_identity_raw_files_and_unknown_outcomes() {
        let base =
            std::env::temp_dir().join(format!("opsforge-applications-{}", std::process::id()));
        let home = base.join("home");
        let logs = home.join(".azure/commands");
        fs::create_dir_all(&logs).expect("logs");
        fs::write(logs.join("command.log"), "upload requested\n").expect("log");
        fs::write(logs.join("credentials.json"), "private config fixture").expect("config");
        let aws = home.join(".aws/cli/history");
        fs::create_dir_all(&aws).expect("history directory");
        let db = rusqlite::Connection::open(aws.join("history.db")).expect("database");
        db.execute_batch("CREATE TABLE records(id TEXT,request_id TEXT,source TEXT,event_type TEXT,timestamp INTEGER,payload TEXT);
            INSERT INTO records VALUES('cmd','req','CLI','API_CALL',1000,'{\"operation\":\"PutObject\"}');").expect("schema");
        drop(db);
        let mut case = Case::new(&base.join("cases")).expect("case");
        assert_eq!(
            collect_home(&mut case, "operator", &home, 0, &|_| {}).expect("collect"),
            (2, 2, 0)
        );
        let events: Vec<serde_json::Value> =
            fs::read_to_string(case.root.join("normalized/events.jsonl"))
                .expect("events")
                .lines()
                .map(|line| serde_json::from_str(line).expect("event"))
                .collect();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event["user"] == "operator" && event.get("transfer").is_none())
        );
        assert!(
            events
                .iter()
                .any(|event| event["application"] == "Azure CLI" && event["level"] == "lead")
        );
        assert!(events.iter().any(|event| event["application"] == "AWS CLI"
            && event["timestamp"] == "1970-01-01T00:00:01Z"));
        let manifest = fs::read_to_string(case.root.join("manifest.jsonl")).expect("manifest");
        assert!(manifest.contains("history.db"));
        assert!(!manifest.contains("credentials.json"));
        db_fixture_invalid(&aws.join("history.db"));
        let second =
            collect_home(&mut case, "operator", &home, 2, &|_| {}).expect("partial collection");
        assert_eq!(second, (2, 1, 1));
        assert!(
            fs::read_to_string(case.root.join("normalized/coverage.jsonl"))
                .expect("coverage")
                .contains("invalid AWS history rows")
        );
        fs::create_dir_all(home.join(".local/state")).expect("state directory");
        std::os::unix::fs::symlink(&logs, home.join(".local/state/rsync"))
            .expect("symlink fixture");
        collect_home(&mut case, "operator", &home, 4, &|_| {}).expect("symlink collection");
        assert!(
            fs::read_to_string(case.root.join("normalized/coverage.jsonl"))
                .expect("coverage")
                .contains("discovery root is a symbolic link")
        );
        crate::report::generate(&case.root).expect("report");
        assert!(
            fs::read_to_string(case.root.join("dashboard/events.js"))
                .expect("dashboard")
                .contains("Azure CLI")
        );
        fs::remove_dir_all(base).expect("fixture cleanup");
    }

    fn db_fixture_invalid(path: &Path) {
        let db = rusqlite::Connection::open(path).expect("database");
        db.execute_batch("INSERT INTO records VALUES(NULL,NULL,'CLI','API_CALL',2000,'{}');")
            .expect("malformed row");
    }
}
