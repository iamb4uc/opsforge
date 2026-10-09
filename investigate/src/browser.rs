use crate::case::{Case, Coverage, CoverageState, Event, EvidenceLevel};
use anyhow::{Context, Result, bail};
use rusqlite::Connection;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use walkdir::WalkDir;

pub fn collect(case: &mut Case, progress: &impl Fn(&str)) -> Result<()> {
    let mut found = 0_u64;
    let mut failed = 0_u64;
    for (user, home) in user_homes()? {
        if !home.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&home).follow_links(false).max_depth(8) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    failed = failed.saturating_add(1);
                    case.coverage(&Coverage {
                        source: home.display().to_string(),
                        state: error
                            .io_error()
                            .map_or(CoverageState::Failed, CoverageState::from_io),
                        detail: error.to_string(),
                    })?;
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let filename = entry.file_name().to_string_lossy();
            let firefox = filename == "places.sqlite";
            if !firefox && filename != "History" {
                continue;
            }
            found = found.saturating_add(1);
            progress(&format!("Browser profile: {}", entry.path().display()));
            let raw = format!("browser-{found:05}.sqlite");
            let result = snapshot(case, entry.path(), &raw)
                .and_then(|db| parse_history(case, &db, &user, &raw, firefox));
            match result {
                Ok(count) => case.coverage(&Coverage {
                    source: entry.path().display().to_string(),
                    state: if count == 0 {
                        CoverageState::Empty
                    } else {
                        CoverageState::Collected
                    },
                    detail: format!("{count} history and download records"),
                })?,
                Err(error) => {
                    failed = failed.saturating_add(1);
                    case.coverage(&Coverage {
                        source: entry.path().display().to_string(),
                        state: CoverageState::from_error(&error),
                        detail: format!("snapshot or parser failed: {error}"),
                    })?;
                }
            }
        }
    }
    case.coverage(&Coverage {
        source: "browser-profiles".into(),
        state: if failed > 0 {
            CoverageState::Failed
        } else if found == 0 {
            CoverageState::Empty
        } else {
            CoverageState::Collected
        },
        detail: format!("{found} profiles found; {failed} failed"),
    })?;
    Ok(())
}

pub(crate) fn user_homes() -> Result<Vec<(String, PathBuf)>> {
    let passwd = fs::read_to_string("/etc/passwd")?;
    let mut homes = Vec::new();
    for line in passwd.lines() {
        let parts: Vec<_> = line.split(':').collect();
        if let (Some(user), Some(home)) = (parts.first(), parts.get(5)) {
            let home = PathBuf::from(home);
            if home != Path::new("/")
                && home.is_dir()
                && !homes.iter().any(|(_, known)| known == &home)
            {
                homes.push(((*user).to_owned(), home));
            }
        }
    }
    Ok(homes)
}

pub(crate) fn snapshot(case: &mut Case, source: &Path, name: &str) -> Result<Connection> {
    let working = case.root.join("normalized").join(name);
    let raw = case.copy_evidence(source, name)?;
    fs::copy(raw, &working)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut source_sidecar = source.as_os_str().to_os_string();
        source_sidecar.push(suffix);
        let source_sidecar = PathBuf::from(source_sidecar);
        match fs::metadata(&source_sidecar) {
            Ok(_) => {
                let sidecar_name = format!("{name}{suffix}");
                let raw = case.copy_evidence(&source_sidecar, &sidecar_name)?;
                // SQLite rebuilds shared memory for the isolated working copy.
                if suffix != "-shm" {
                    fs::copy(raw, working.with_file_name(sidecar_name))?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("checking browser journal files"),
        }
    }
    case.coverage(&Coverage {
        source: format!("{}:acquisition", source.display()),
        state: CoverageState::Collected,
        detail: "database and available WAL, shared-memory, and rollback journal files preserved; parsing uses an isolated copy; live file copies are not an atomic snapshot".into(),
    })?;
    let db = Connection::open(working)?;
    db.busy_timeout(Duration::from_millis(250))?;
    let check: String = db.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if check != "ok" {
        bail!("browser working copy failed SQLite quick_check: {check}");
    }
    Ok(db)
}

fn parse_history(
    case: &mut Case,
    db: &Connection,
    user: &str,
    raw: &str,
    firefox: bool,
) -> Result<u64> {
    let query = if firefox {
        "SELECT v.visit_date, p.url, COALESCE(p.title, '') FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date"
    } else {
        "SELECT v.visit_time, u.url, COALESCE(u.title, '') FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time"
    };
    let mut statement = db.prepare(query)?;
    let mut rows = statement.query([])?;
    let mut count = 0_u64;
    while let Some(row) = rows.next()? {
        let time: i64 = row.get(0)?;
        let url: String = row.get(1)?;
        let title: String = row.get(2)?;
        let microseconds = if firefox {
            Some(time)
        } else {
            time.checked_sub(11_644_473_600_000_000)
        };
        let timestamp = microseconds
            .and_then(|value| jiff::Timestamp::from_microsecond(value).ok())
            .map(|value| value.to_string());
        case.event(&Event {
            timestamp,
            source: "browser-history".into(),
            kind: "browser-visit".into(),
            application: Some(
                if firefox {
                    "Firefox"
                } else {
                    "Chromium-family"
                }
                .into(),
            ),
            user: Some(user.into()),
            destination: Some(url),
            detail: title,
            evidence: format!("raw/{raw}"),
            level: EvidenceLevel::Lead,
            transfer: None,
            evidence_line: None,
        })?;
        count = count.saturating_add(1);
    }
    if firefox {
        count = count.saturating_add(firefox_downloads(case, db, user, raw)?);
    } else {
        let rich = "SELECT d.start_time, COALESCE(d.target_path, d.current_path, ''), d.received_bytes, d.total_bytes, COALESCE((SELECT url FROM downloads_url_chains WHERE id=d.id ORDER BY chain_index LIMIT 1), '') FROM downloads d ORDER BY d.start_time";
        let basic = "SELECT start_time, COALESCE(target_path, current_path, ''), received_bytes, total_bytes, '' FROM downloads ORDER BY start_time";
        let (mut downloads, source_urls) = match db.prepare(rich) {
            Ok(statement) => (statement, true),
            Err(_) => match db.prepare(basic) {
                Ok(statement) => (statement, false),
                Err(error) => {
                    case.coverage(&Coverage {
                        source: format!("raw/{raw}:downloads"),
                        state: CoverageState::Unsupported,
                        detail: format!("download schema not decoded: {error}"),
                    })?;
                    return Ok(count);
                }
            },
        };
        if !source_urls {
            case.coverage(&Coverage {
                source: format!("raw/{raw}:download-urls"),
                state: CoverageState::Unsupported,
                detail: "source URL table unavailable in this profile".into(),
            })?;
        }
        let mut rows = downloads.query([])?;
        let mut download_count = 0_u64;
        while let Some(row) = rows.next()? {
            let time: i64 = row.get(0)?;
            let path: String = row.get(1)?;
            let received: i64 = row.get(2)?;
            let total: i64 = row.get(3)?;
            let url: String = row.get(4)?;
            let timestamp = time
                .checked_sub(11_644_473_600_000_000)
                .and_then(|value| jiff::Timestamp::from_microsecond(value).ok())
                .map(|value| value.to_string());
            case.event(&Event {
                timestamp,
                source: "browser-downloads".into(),
                kind: "download".into(),
                application: Some("Chromium-family".into()),
                user: Some(user.into()),
                destination: Some(path.clone()),
                detail: format!("source {url}; received {received} of {total} bytes"),
                evidence: format!("raw/{raw}"),
                level: EvidenceLevel::Recorded,
                transfer: Some(crate::case::Transfer {
                    direction: "download".into(),
                    status: "recorded".into(),
                    protocol: "browser".into(),
                    perspective: "client".into(),
                    file: Some(path),
                    target: (!url.is_empty()).then_some(url),
                    peer: None,
                    bytes: u64::try_from(received).ok(),
                    bytes_basis: "received bytes; completion state not decoded".into(),
                    method: None,
                }),
                evidence_line: None,
            })?;
            download_count = download_count.saturating_add(1);
            count = count.saturating_add(1);
        }
        case.coverage(&Coverage {
            source: format!("raw/{raw}:downloads"),
            state: if download_count == 0 {
                CoverageState::Empty
            } else {
                CoverageState::Collected
            },
            detail: format!("{download_count} records"),
        })?;
    }
    Ok(count)
}

fn firefox_downloads(case: &mut Case, db: &Connection, user: &str, raw: &str) -> Result<u64> {
    let query = "SELECT p.id, p.url, MAX(v.visit_date),
        (SELECT a.content FROM moz_annos a JOIN moz_anno_attributes n ON n.id=a.anno_attribute_id
            WHERE a.place_id=p.id AND n.name='downloads/destinationFileURI' LIMIT 1),
        (SELECT a.content FROM moz_annos a JOIN moz_anno_attributes n ON n.id=a.anno_attribute_id
            WHERE a.place_id=p.id AND n.name='downloads/metaData' LIMIT 1)
        FROM moz_places p JOIN moz_historyvisits v ON v.place_id=p.id
        WHERE v.visit_type=7 GROUP BY p.id,p.url ORDER BY MAX(v.visit_date)";
    let mut statement = match db.prepare(query) {
        Ok(statement) => statement,
        Err(error) => {
            case.coverage(&Coverage {
                source: format!("raw/{raw}:downloads"),
                state: CoverageState::Unsupported,
                detail: format!("Firefox download annotation schema unavailable: {error}"),
            })?;
            return Ok(0);
        }
    };
    let mut rows = statement.query([])?;
    let mut count = 0_u64;
    let mut failed = 0_u64;
    while let Some(row) = rows.next()? {
        let parsed = (|| -> rusqlite::Result<_> {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })();
        let (place, url, visit, file, metadata) = match parsed {
            Ok(record) => record,
            Err(error) => {
                failed = failed.saturating_add(1);
                case.coverage(&Coverage {
                    source: format!("raw/{raw}:downloads"),
                    state: CoverageState::Failed,
                    detail: format!("invalid download row: {error}"),
                })?;
                continue;
            }
        };
        let metadata = metadata
            .as_deref()
            .map(serde_json::from_str::<serde_json::Value>)
            .transpose();
        let metadata = match metadata {
            Ok(value) => value.unwrap_or(serde_json::Value::Null),
            Err(error) => {
                failed = failed.saturating_add(1);
                case.coverage(&Coverage {
                    source: format!("raw/{raw}:download-place-{place}"),
                    state: CoverageState::Failed,
                    detail: format!("invalid download metadata: {error}"),
                })?;
                serde_json::Value::Null
            }
        };
        let status = match metadata.get("state").and_then(serde_json::Value::as_u64) {
            Some(1) => "completed",
            Some(2) => "failed",
            Some(3) => "cancelled",
            _ => "unknown",
        };
        let timestamp = metadata
            .get("endTime")
            .and_then(serde_json::Value::as_i64)
            .and_then(|time| jiff::Timestamp::from_millisecond(time).ok())
            .or_else(|| jiff::Timestamp::from_microsecond(visit).ok())
            .map(|time| time.to_string());
        case.event(&Event {
            timestamp,
            source: "browser-downloads".into(),
            kind: "download".into(),
            application: Some("Firefox".into()),
            user: Some(user.into()),
            destination: file.clone(),
            detail: format!("moz_places.id={place}; latest download annotation for URL; latest visit_us={visit}; metadata={metadata}"),
            evidence: format!("raw/{raw}"),
            level: EvidenceLevel::Recorded,
            transfer: Some(crate::case::Transfer {
                direction: "download".into(),
                status: status.into(),
                protocol: "browser".into(),
                perspective: "client".into(),
                file,
                target: Some(url),
                peer: None,
                bytes: metadata.get("fileSize").and_then(serde_json::Value::as_u64),
                bytes_basis: "Firefox download annotation fileSize; latest annotation, not every visit".into(),
                method: None,
            }),
            evidence_line: None,
        })?;
        count = count.saturating_add(1);
    }
    case.coverage(&Coverage {
        source: format!("raw/{raw}:downloads"),
        state: if failed > 0 { CoverageState::Failed }
            else if count == 0 { CoverageState::Empty } else { CoverageState::Collected },
        detail: format!("{count} latest URL annotation records; {failed} malformed rows/annotations; annotations cannot reconstruct repeated downloads to older destinations"),
    })?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::{parse_history, snapshot};
    use crate::case::Case;
    use rusqlite::Connection;
    use std::fs;

    #[test]
    fn firefox_download_annotations_keep_latest_record_and_unknown_metadata() {
        let base = std::env::temp_dir().join(format!("opsforge-firefox-{}", std::process::id()));
        fs::create_dir_all(&base).expect("base");
        let mut case = Case::new(&base).expect("case");
        let source = base.join("places.sqlite");
        let db = Connection::open(&source).expect("database");
        db.execute_batch("CREATE TABLE moz_places(id INTEGER,url TEXT,title TEXT);
            CREATE TABLE moz_historyvisits(place_id INTEGER,visit_date INTEGER,visit_type INTEGER);
            CREATE TABLE moz_anno_attributes(id INTEGER,name TEXT);
            CREATE TABLE moz_annos(place_id INTEGER,anno_attribute_id INTEGER,content TEXT);
            INSERT INTO moz_anno_attributes VALUES(1,'downloads/destinationFileURI'),(2,'downloads/metaData');
            INSERT INTO moz_places VALUES(1,'https://example.test/file.zip','file.zip'),
                (2,'https://example.test/failed.zip','failed.zip'),(3,'https://example.test/bad.zip','bad.zip');
            INSERT INTO moz_historyvisits VALUES(1,1000000,7),(1,2000000,7),(2,3000000,7),(3,4000000,7);
            INSERT INTO moz_annos VALUES(1,1,'file:///tmp/latest%20file.zip'),
                (1,2,'{\"state\":1,\"endTime\":2000,\"fileSize\":123}'),
                (2,2,'{\"state\":2}'),(3,2,'invalid-json');").expect("schema");
        let copy = snapshot(&mut case, &source, "firefox.sqlite").expect("snapshot");
        parse_history(&mut case, &copy, "operator", "firefox.sqlite", true).expect("parse");
        let rows: Vec<serde_json::Value> =
            fs::read_to_string(case.root.join("normalized/events.jsonl"))
                .expect("events")
                .lines()
                .map(|line| serde_json::from_str(line).expect("event"))
                .collect();
        let downloads: Vec<_> = rows
            .iter()
            .filter(|row| row["source"] == "browser-downloads")
            .collect();
        assert_eq!(downloads.len(), 3);
        assert_eq!(downloads[0]["transfer"]["status"], "completed");
        assert_eq!(
            downloads[0]["transfer"]["file"],
            "file:///tmp/latest%20file.zip"
        );
        assert_eq!(downloads[0]["transfer"]["bytes"], 123);
        assert_eq!(downloads[0]["timestamp"], "1970-01-01T00:00:02Z");
        assert_eq!(downloads[1]["transfer"]["status"], "failed");
        assert_eq!(downloads[2]["transfer"]["status"], "unknown");
        assert!(
            fs::read_to_string(case.root.join("normalized/coverage.jsonl"))
                .expect("coverage")
                .contains("invalid download metadata")
        );
        crate::report::generate(&case.root).expect("dashboard");
        crate::report::write_checksums(&case.root).expect("checksums");
        assert!(
            fs::read_to_string(case.root.join("dashboard/events.js"))
                .expect("dashboard data")
                .contains("latest%20file.zip")
        );
        assert_eq!(
            fs::read(&source).expect("source"),
            fs::read(case.root.join("raw/firefox.sqlite")).expect("raw")
        );
        drop(copy);
        drop(db);
        fs::remove_dir_all(base).expect("fixture cleanup");
    }

    #[test]
    fn acquires_an_exclusively_locked_browser_and_preserves_wal() {
        let base =
            std::env::temp_dir().join(format!("opsforge-live-browser-{}", std::process::id()));
        fs::create_dir_all(&base).expect("base");
        let source = base.join("History");
        let browser = Connection::open(&source).expect("browser database");
        browser.execute_batch("PRAGMA journal_mode=WAL; PRAGMA locking_mode=EXCLUSIVE; PRAGMA wal_autocheckpoint=0; CREATE TABLE visits(visit_time INTEGER,url INTEGER); CREATE TABLE urls(id INTEGER,url TEXT,title TEXT); INSERT INTO urls VALUES(1,'http://lab.test/','lab'); INSERT INTO visits VALUES(11644473600000000,1);").expect("live browser records");
        let original = fs::read(&source).expect("source bytes");
        let wal = fs::read(base.join("History-wal")).expect("WAL bytes");
        let mut case = Case::new(&base).expect("case");
        let copy =
            snapshot(&mut case, &source, "browser-00001.sqlite").expect("locked acquisition");
        assert_eq!(
            copy.query_row("SELECT url FROM urls", [], |row| row.get::<_, String>(0))
                .expect("WAL record"),
            "http://lab.test/"
        );
        parse_history(&mut case, &copy, "operator", "browser-00001.sqlite", false).expect("parse");
        assert_eq!(
            fs::read(case.root.join("raw/browser-00001.sqlite")).expect("raw"),
            original
        );
        assert_eq!(
            fs::read(case.root.join("raw/browser-00001.sqlite-wal")).expect("raw WAL"),
            wal
        );
        assert_eq!(fs::read(&source).expect("source unchanged"), original);
        assert!(
            fs::read_to_string(case.root.join("manifest.jsonl"))
                .expect("manifest")
                .contains("browser-00001.sqlite-wal")
        );
        drop(copy);
        drop(browser);
        fs::remove_dir_all(base).expect("remove fixture");
    }

    #[test]
    fn chromium_download_keeps_origin_and_local_path() {
        let base = std::env::temp_dir().join(format!("opsforge-browser-{}", std::process::id()));
        fs::create_dir_all(&base).expect("base");
        let mut case = Case::new(&base).expect("case");
        let db = Connection::open_in_memory().expect("database");
        db.execute_batch("CREATE TABLE visits(visit_time INTEGER,url INTEGER); CREATE TABLE urls(id INTEGER,url TEXT,title TEXT); CREATE TABLE downloads(id INTEGER,start_time INTEGER,target_path TEXT,current_path TEXT,received_bytes INTEGER,total_bytes INTEGER); CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT); INSERT INTO downloads VALUES(1,11644473600000000,'/tmp/file.bin','/tmp/file.part',123,123); INSERT INTO downloads_url_chains VALUES(1,0,'https://example.test/file.bin');").expect("schema");
        parse_history(&mut case, &db, "operator", "browser-00001.sqlite", false).expect("parse");
        let events = fs::read_to_string(case.root.join("normalized/events.jsonl")).expect("events");
        assert!(events.contains("https://example.test/file.bin"));
        assert!(events.contains("/tmp/file.bin"));
        fs::remove_dir_all(base).expect("remove fixture");
    }
}
