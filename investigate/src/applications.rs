use crate::{
    browser,
    case::{Case, Coverage, CoverageState, Event, EvidenceLevel, Transfer},
    collect,
};
use anyhow::Result;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};
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

pub(crate) fn inventory(case: &mut Case, source: &str) -> Result<()> {
    let evidence = format!("raw/{source}.txt");
    let path = case.root.join(&evidence);
    let input = match File::open(path) {
        Ok(input) => input,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let timestamp = jiff::Timestamp::now().to_string();
    for (index, line) in BufReader::new(input).lines().enumerate() {
        let line = line?;
        if let Some(event) = inventory_event(
            source,
            &line,
            &timestamp,
            &evidence,
            u64::try_from(index)? + 1,
        ) {
            case.event(&event)?;
        }
    }
    Ok(())
}

fn inventory_event(
    source: &str,
    line: &str,
    timestamp: &str,
    evidence: &str,
    number: u64,
) -> Option<Event> {
    let application = match source {
        "packages-xbps" => line.split_whitespace().nth(1)?,
        "packages-pacman" | "apps-snap" => line.split_whitespace().next()?,
        _ => line.split('\t').next()?.trim(),
    };
    if application.is_empty() || (source == "apps-snap" && application == "Name") {
        return None;
    }
    Some(Event {
        timestamp: Some(timestamp.into()),
        source: source.into(),
        kind: "application-inventory".into(),
        application: Some(application.into()),
        user: None,
        destination: None,
        detail: format!(
            "Current package-manager record; collection time, not install time. Version, architecture, package state and other retained fields: {line}. Installation does not prove execution or network traffic; XBPS labels retain the full package-version identifier."
        ),
        evidence: evidence.into(),
        level: EvidenceLevel::Observed,
        transfer: None,
        evidence_line: Some(number),
    })
}

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
                case.coverage(&Coverage { source, state: CoverageState::from_io(&error), detail: format!("discovery location unavailable: {error}; absent logs do not prove absent activity") })?;
                continue;
            }
        }
        let mut count = 0;
        let mut failed = 0;
        for entry in WalkDir::new(&location).follow_links(false).max_depth(8) {
            crate::runtime::check_cancelled()?;
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    failed += 1;
                    case.coverage(&Coverage {
                        source: source.clone(),
                        state: error
                            .io_error()
                            .map_or(CoverageState::Failed, CoverageState::from_io),
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
                        state: CoverageState::from_error(&error),
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
    db.execute_batch(
        "CREATE INDEX IF NOT EXISTS opsforge_history_lookup ON records(id,request_id,timestamp)",
    )?;
    let mut statement = db.prepare(
        "SELECT id,request_id,source,event_type,timestamp,payload FROM records ORDER BY timestamp",
    )?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    let mut failed = 0;
    while let Some(row) = rows.next()? {
        crate::runtime::check_cancelled()?;
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
        let transfer = if kind == "HTTP_RESPONSE" {
            request
                .as_deref()
                .map(|request| aws_transfer(&db, &command, request, time, &payload))
                .transpose()?
                .flatten()
        } else {
            None
        };
        case.event(&Event {
            timestamp: jiff::Timestamp::from_millisecond(time).ok().map(|time| time.to_string()),
            source: "aws-cli-history".into(), kind: transfer.as_ref().map_or_else(|| "application-history".into(), |transfer| format!("{}-request", transfer.direction)),
            application: Some("AWS CLI".into()), user: Some(format!("{user} (current account for discovery home)")), destination: transfer.as_ref().and_then(|transfer| transfer.target.clone()),
            detail: format!("command_id={command}; request_id={request:?}; source={source}; event_type={kind}; payload={payload}"),
            evidence: format!("raw/{name}"), level: EvidenceLevel::Recorded,
            transfer, evidence_line: None,
        })?;
        count += 1;
    }
    if failed > 0 {
        anyhow::bail!("{failed} invalid AWS history rows; {count} valid rows retained");
    }
    Ok(count)
}

fn aws_transfer(
    db: &rusqlite::Connection,
    command: &str,
    request: &str,
    time: i64,
    response: &str,
) -> Result<Option<Transfer>> {
    let mut statement = db.prepare("SELECT event_type,payload FROM records WHERE id=?1 AND request_id=?2 AND timestamp<=?3 AND event_type IN ('API_CALL','HTTP_REQUEST') ORDER BY timestamp")?;
    let mut rows = statement.query(rusqlite::params![command, request, time])?;
    let mut calls = 0;
    let mut operation = None;
    let mut targets = BTreeSet::new();
    while let Some(row) = rows.next()? {
        crate::runtime::check_cancelled()?;
        let kind: String = row.get(0)?;
        let payload: String = row.get(1)?;
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&payload) else {
            return Ok(None);
        };
        if kind == "API_CALL" {
            calls += 1;
            if value["service"] == "s3" {
                operation = value["operation"].as_str().map(str::to_owned);
            }
        } else if let (Some(url), Some(method)) = (value["url"].as_str(), value["method"].as_str())
        {
            targets.insert((url.to_owned(), method.to_owned()));
        }
    }
    if calls != 1 {
        return Ok(None);
    }
    let direction = match operation.as_deref() {
        Some("PutObject" | "UploadPart" | "CompleteMultipartUpload") => "upload",
        Some("GetObject") => "download",
        _ => return Ok(None),
    };
    let Ok(response) = serde_json::from_str::<serde_json::Value>(response) else {
        return Ok(None);
    };
    if response["context"]["operation_name"]
        .as_str()
        .is_some_and(|name| Some(name) != operation.as_deref())
    {
        return Ok(None);
    }
    let status = match response["status_code"].as_u64() {
        Some(200..=299) => "accepted",
        Some(400..=599) => "failed",
        _ => "unknown",
    };
    let (target, method) = if targets.len() == 1 {
        let (target, method) = targets.into_iter().next().expect("one target");
        let expected = match operation.as_deref() {
            Some("GetObject") => "GET",
            Some("CompleteMultipartUpload") => "POST",
            _ => "PUT",
        };
        if method != expected {
            return Ok(None);
        }
        (Some(target), Some(method))
    } else {
        (None, None)
    };
    Ok(Some(Transfer {
        direction: direction.into(), status: status.into(), protocol: "S3 API".into(),
        perspective: "client".into(), file: None, target, peer: None, bytes: None,
        bytes_basis: "API/HTTP outcome only; request/response headers do not prove file bytes or full download completion".into(),
        method: operation.map(|operation| format!("{operation} / {}", method.as_deref().unwrap_or("HTTP method unknown"))),
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn package_inventory_keeps_manager_identity_without_claiming_network_activity() {
        for (source, line, name) in [
            ("packages-dpkg", "curl\t8.0\tamd64\tii ", "curl"),
            ("packages-rpm", "curl\t8.0-1\tx86_64", "curl"),
            ("packages-xbps", "ii curl-8.0_1 HTTP client", "curl-8.0_1"),
            ("packages-pacman", "curl 8.0-1", "curl"),
            (
                "apps-flatpak",
                "org.example.App\t1\tstable\tflathub",
                "org.example.App",
            ),
            (
                "apps-snap",
                "chromium 100 1 latest/stable canonical -",
                "chromium",
            ),
        ] {
            let event =
                super::inventory_event(source, line, "2026-10-09T00:00:00Z", "raw/packages.txt", 2)
                    .expect("record");
            assert_eq!(event.application.as_deref(), Some(name));
            assert_eq!(event.evidence_line, Some(2));
            assert!(event.transfer.is_none());
            assert!(event.detail.contains(line));
            assert!(event.detail.contains("not install time"));
        }
        assert!(super::inventory_event("apps-snap", "Name Version Rev", "", "", 1).is_none());
        assert!(super::inventory_event("packages-dpkg", "", "", "", 1).is_none());
    }
    use super::*;
    use std::fs;

    #[test]
    fn aws_http_outcomes_require_matching_api_context_and_keep_actual_endpoint() {
        let db = rusqlite::Connection::open_in_memory().expect("database");
        db.execute_batch("CREATE TABLE records(id TEXT,request_id TEXT,source TEXT,event_type TEXT,timestamp INTEGER,payload TEXT);
            INSERT INTO records VALUES('cmd','req','BOTOCORE','API_CALL',1000,'{\"service\":\"s3\",\"operation\":\"PutObject\"}'),
                ('cmd','req','BOTOCORE','HTTP_REQUEST',1001,'{\"url\":\"http://127.0.0.1/uploads/file\",\"method\":\"PUT\"}');").expect("schema");
        let response = r#"{"status_code":201,"headers":{"Content-Length":"0"}}"#;
        let transfer = aws_transfer(&db, "cmd", "req", 1002, response)
            .expect("parse")
            .expect("transfer");
        assert_eq!(transfer.direction, "upload");
        assert_eq!(transfer.status, "accepted");
        assert_eq!(
            transfer.target.as_deref(),
            Some("http://127.0.0.1/uploads/file")
        );
        assert!(transfer.file.is_none() && transfer.bytes.is_none());
        assert_eq!(
            aws_transfer(&db, "cmd", "req", 1002, r#"{"status_code":403}"#)
                .expect("failed response")
                .expect("transfer")
                .status,
            "failed"
        );
        assert!(
            aws_transfer(
                &db,
                "cmd",
                "req",
                1002,
                r#"{"status_code":200,"context":{"operation_name":"GetObject"}}"#
            )
            .expect("mismatched operation")
            .is_none()
        );
        assert!(
            aws_transfer(&db, "cmd", "missing", 1002, response)
                .expect("missing context")
                .is_none()
        );
        assert!(
            aws_transfer(&db, "cmd", "req", 999, response)
                .expect("future context")
                .is_none()
        );
        db.execute_batch("INSERT INTO records VALUES('cmd','req','BOTOCORE','API_CALL',1002,'{\"service\":\"s3\",\"operation\":\"GetObject\"}');").expect("ambiguous context");
        assert!(
            aws_transfer(&db, "cmd", "req", 1003, response)
                .expect("ambiguous")
                .is_none()
        );
    }

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
        assert!(events.iter().all(|event| event["user"]
            == "operator (current account for discovery home)"
            && event.get("transfer").is_none()));
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
