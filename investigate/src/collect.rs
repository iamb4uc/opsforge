use crate::{
    case::{Case, Coverage, CoverageState, Event, EvidenceLevel},
    config::RunConfig,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use walkdir::WalkDir;

pub fn run(config: &RunConfig, progress: &impl Fn(&str)) -> Result<PathBuf> {
    config.validate().map_err(anyhow::Error::msg)?;
    let mut case = Case::new(&config.output_base)?;
    let root = case.root.clone();
    fs::write(root.join("config.json"), serde_json::to_vec_pretty(config)?)?;
    fs::write(
        root.join("case-info.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "tool": "opsforge-investigate",
            "case_id": root.file_name().unwrap_or_default().to_string_lossy(),
            "version": env!("CARGO_PKG_VERSION"),
            "started_at": jiff::Timestamp::now().to_string(),
            "operator": std::env::var("SUDO_USER").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "unknown".into()),
        }))?,
    )?;
    progress(&format!("Case created: {}", root.display()));
    let mut live = if config.live_capture {
        progress(&format!(
            "Starting live traffic capture for {}",
            config.capture_duration
        ));
        match start_capture(&mut case, config.capture_duration.seconds()) {
            Ok(capture) => capture,
            Err(error) => {
                case.coverage(&Coverage {
                    source: "live-traffic".into(),
                    state: CoverageState::from_error(&error),
                    detail: error.to_string(),
                })?;
                None
            }
        }
    } else {
        case.coverage(&Coverage {
            source: "live-traffic".into(),
            state: CoverageState::Skipped,
            detail: "operator deselected live capture".into(),
        })?;
        None
    };

    for (enabled, source) in [
        (config.exfil, "exfiltration"),
        (config.timeline, "device-timeline"),
        (config.downloads, "downloads"),
    ] {
        if !enabled {
            case.coverage(&Coverage {
                source: source.into(),
                state: CoverageState::Skipped,
                detail: "operator deselected category".into(),
            })?;
        }
    }
    if config.imports.is_empty() {
        case.coverage(&Coverage {
            source: "imported-logs".into(),
            state: CoverageState::Skipped,
            detail: "no paths supplied".into(),
        })?;
    }

    if config.exfil || config.timeline {
        progress("Collecting active sockets and installed applications");
        source(&mut case, "active-sockets", |case| {
            run_command(case, "active-sockets", "ss", &["-tunap"])
        })?;
        source(&mut case, "active-socket-normalization", normalize_sockets)?;
        for (name, program, args) in [
            (
                "packages-dpkg",
                "dpkg-query",
                vec![
                    "-W",
                    "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n",
                ],
            ),
            (
                "packages-rpm",
                "rpm",
                vec!["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
            ),
            ("packages-xbps", "xbps-query", vec!["-l"]),
            ("packages-pacman", "pacman", vec!["-Q"]),
            (
                "apps-flatpak",
                "flatpak",
                vec![
                    "list",
                    "--app",
                    "--columns=application,version,branch,origin",
                ],
            ),
            ("apps-snap", "snap", vec!["list"]),
        ] {
            source(&mut case, name, |case| {
                run_command(case, name, program, &args)?;
                crate::applications::inventory(case, name)
            })?;
        }
        progress("Collecting retained system journal");
        source(&mut case, "journal", |case| collect_journal(case, progress))?;
        progress("Preserving retained system logs");
        source(&mut case, "system-logs", |case| {
            collect_logs(case, progress)
        })?;
    }
    if config.exfil || config.downloads {
        progress("Collecting retained application transfer logs");
        source(&mut case, "application-transfer-logs", |case| {
            crate::applications::collect(case, progress)
        })?;
        progress("Collecting browser activity and downloads");
        source(&mut case, "browser-profiles", |case| {
            crate::browser::collect(case, progress)
        })?;
        case.coverage(&Coverage { source: "browser-upload-transactions".into(), state: CoverageState::Unsupported, detail: "browser history does not retain upload payloads or prove that a visit uploaded data".into() })?;
    }
    for (index, path) in config.imports.iter().enumerate() {
        progress(&format!("Importing {}", path.display()));
        source(&mut case, &path.display().to_string(), |case| {
            import_path(case, path, &format!("import-{index:03}"), progress)
        })?;
    }
    if config.deep_inventory {
        progress("Inventorying local files");
        source(&mut case, "file-inventory", |case| {
            inventory(case, Path::new("/"), progress)
        })?;
    } else {
        case.coverage(&Coverage {
            source: "file-inventory".into(),
            state: CoverageState::Skipped,
            detail: "operator deselected deep inventory".into(),
        })?;
    }
    if let Some(capture) = &mut live {
        source(&mut case, "live-traffic", |case| {
            finish_capture(case, capture, progress)
        })?;
    }
    progress("Building offline dashboard");
    crate::report::generate(&root)?;
    fs::write(
        root.join("completion.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"finished_at": jiff::Timestamp::now().to_string(), "status": "finished_review_coverage"}),
        )?,
    )?;
    crate::report::write_checksums(&root)?;
    progress(&format!(
        "Case saved; review source coverage: {}",
        root.display()
    ));
    Ok(root)
}

fn source(
    case: &mut Case,
    name: &str,
    collect: impl FnOnce(&mut Case) -> Result<()>,
) -> Result<()> {
    if let Err(error) = collect(case) {
        case.coverage(&Coverage {
            source: name.into(),
            state: CoverageState::from_error(&error),
            detail: error.to_string(),
        })?;
    }
    Ok(())
}

fn run_command(case: &mut Case, name: &str, program: &str, args: &[&str]) -> Result<()> {
    if !command_exists(program) {
        case.coverage(&Coverage {
            source: name.into(),
            state: CoverageState::Unavailable,
            detail: format!("{program} is not installed"),
        })?;
        return Ok(());
    }
    let raw = format!("{name}.txt");
    let file = File::create(case.root.join("raw").join(&raw))?;
    let error_file = File::create(case.root.join("raw").join(format!("{name}.stderr.txt")))?;
    let status = Command::new(program)
        .args(args)
        .stdout(file)
        .stderr(error_file)
        .status()?;
    case.record_existing(&format!("{program} {}", args.join(" ")), &raw)?;
    case.record_existing(&format!("{program} stderr"), &format!("{name}.stderr.txt"))?;
    let bytes = fs::metadata(case.root.join("raw").join(raw))?.len();
    let state = if !status.success() {
        CoverageState::Failed
    } else if bytes == 0 {
        CoverageState::Empty
    } else {
        CoverageState::Collected
    };
    case.coverage(&Coverage {
        source: name.into(),
        state,
        detail: format!("exit status: {status}"),
    })?;
    Ok(())
}

fn command_exists(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

fn normalize_sockets(case: &mut Case) -> Result<()> {
    let path = case.root.join("raw/active-sockets.txt");
    if !path.exists() {
        return Ok(());
    }
    let timestamp = jiff::Timestamp::now().to_string();
    for line in BufReader::new(File::open(path)?).lines().skip(1) {
        let line = line?;
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let application = line
            .split("users:((\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .map(str::to_owned);
        case.event(&Event {
            timestamp: Some(timestamp.clone()),
            source: "active-sockets".into(),
            kind: if fields[1] == "LISTEN" {
                "inbound-listener"
            } else {
                "active-connection"
            }
            .into(),
            application,
            user: None,
            destination: Some(fields[5].into()),
            detail: line,
            evidence: "raw/active-sockets.txt".into(),
            level: EvidenceLevel::Observed,
            transfer: None,
            evidence_line: None,
        })?;
    }
    Ok(())
}

fn collect_journal(case: &mut Case, progress: &impl Fn(&str)) -> Result<()> {
    let users: std::collections::HashMap<String, String> = fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.len() >= 3).then(|| (fields[2].to_owned(), fields[0].to_owned()))
        })
        .collect();
    if !command_exists("journalctl") {
        case.coverage(&Coverage {
            source: "journal".into(),
            state: CoverageState::Unavailable,
            detail: "journalctl is not installed".into(),
        })?;
        return Ok(());
    }
    let mut child = Command::new("journalctl")
        .args(["--no-pager", "-o", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().context("journal stdout")?;
    let mut raw = BufWriter::new(File::create(case.root.join("raw/journal.jsonl"))?);
    let mut count = 0_u64;
    for line in BufReader::new(stdout).lines() {
        let line = line?;
        writeln!(raw, "{line}")?;
        raw.flush()?;
        let Ok(record) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let message = record.get("MESSAGE").and_then(Value::as_str).unwrap_or("");
        let app = record
            .get("_COMM")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let timestamp = record
            .get("__REALTIME_TIMESTAMP")
            .and_then(Value::as_str)
            .and_then(|micros| micros.parse::<i64>().ok())
            .and_then(|micros| jiff::Timestamp::from_microsecond(micros).ok())
            .map(|stamp| stamp.to_string());
        let network = [
            "connect", "upload", "download", "network", "firewall", "vpn", "dns", "ssh", "http",
            "sync",
        ]
        .iter()
        .any(|needle| message.to_ascii_lowercase().contains(needle));
        case.event(&Event {
            timestamp,
            source: "journal".into(),
            kind: if network { "network-lead" } else { "journal" }.into(),
            application: app,
            user: record.get("_UID").and_then(Value::as_str).map(|uid| {
                users.get(uid).map_or_else(
                    || format!("UID {uid}"),
                    |name| format!("{name} (current passwd name for UID {uid})"),
                )
            }),
            destination: None,
            detail: message.to_owned(),
            evidence: "raw/journal.jsonl".into(),
            level: EvidenceLevel::Lead,
            transfer: None,
            evidence_line: Some(count + 1),
        })?;
        count = count.saturating_add(1);
        if count.is_multiple_of(10_000) {
            progress(&format!("Journal: {count} entries saved"));
        }
    }
    raw.flush()?;
    let status = child.wait()?;
    case.record_existing("journalctl --no-pager -o json", "journal.jsonl")?;
    case.coverage(&Coverage {
        source: "journal".into(),
        state: if !status.success() {
            CoverageState::Failed
        } else if count == 0 {
            CoverageState::Empty
        } else {
            CoverageState::Collected
        },
        detail: format!("{count} entries; {status}"),
    })?;
    Ok(())
}

fn collect_logs(case: &mut Case, progress: &impl Fn(&str)) -> Result<()> {
    let mut count = 0_u64;
    let mut attempted = 0_u64;
    let mut failed = 0_u64;
    for entry in WalkDir::new("/var/log").follow_links(false).max_depth(4) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                failed = failed.saturating_add(1);
                case.coverage(&Coverage {
                    source: "system-logs".into(),
                    state: CoverageState::Failed,
                    detail: error.to_string(),
                })?;
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let name = format!("system-log-{attempted:05}");
        attempted = attempted.saturating_add(1);
        match case.copy_evidence(entry.path(), &name) {
            Ok(_) => {
                count = count.saturating_add(1);
                let raw = case.root.join("raw").join(&name);
                let parsed =
                    normalize_text_log(case, &raw, &name, "system-log", entry.path(), None);
                case.coverage(&Coverage {
                    source: entry.path().display().to_string(),
                    state: if parsed.is_ok() {
                        CoverageState::Collected
                    } else {
                        CoverageState::Unsupported
                    },
                    detail: match parsed {
                        Ok(lines) => format!("{lines} text records normalized"),
                        Err(error) => format!("raw preserved; text parser unavailable: {error}"),
                    },
                })?;
            }
            Err(error) => {
                failed = failed.saturating_add(1);
                case.coverage(&Coverage {
                    source: entry.path().display().to_string(),
                    state: CoverageState::Failed,
                    detail: error.to_string(),
                })?;
            }
        }
        if count > 0 && count.is_multiple_of(100) {
            progress(&format!("System logs: {count} files saved"));
        }
    }
    case.coverage(&Coverage {
        source: "system-logs".into(),
        state: if failed > 0 {
            CoverageState::Failed
        } else if count == 0 {
            CoverageState::Empty
        } else {
            CoverageState::Collected
        },
        detail: format!("{count} files saved; {failed} failed; scan depth 4"),
    })?;
    Ok(())
}

fn import_path(case: &mut Case, path: &Path, prefix: &str, progress: &impl Fn(&str)) -> Result<()> {
    if let Err(error) = fs::metadata(path) {
        case.coverage(&Coverage {
            source: path.display().to_string(),
            state: CoverageState::from_io(&error),
            detail: format!("import path unavailable: {error}"),
        })?;
        return Ok(());
    }
    let mut count = 0_u64;
    let mut failed = 0_u64;
    let mut attempted = 0_u64;
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                failed = failed.saturating_add(1);
                case.coverage(&Coverage {
                    source: path.display().to_string(),
                    state: CoverageState::Failed,
                    detail: error.to_string(),
                })?;
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let name = format!("{prefix}-{attempted:06}");
        attempted = attempted.saturating_add(1);
        if let Err(error) = case.copy_evidence(entry.path(), &name) {
            failed = failed.saturating_add(1);
            case.coverage(&Coverage {
                source: entry.path().display().to_string(),
                state: CoverageState::from_error(&error),
                detail: error.to_string(),
            })?;
            continue;
        }
        let raw = case.root.join("raw").join(&name);
        let parsed = normalize_text_log(case, &raw, &name, "imported-log", entry.path(), None);
        case.coverage(&Coverage {
            source: entry.path().display().to_string(),
            state: if parsed.is_ok() {
                CoverageState::Collected
            } else {
                CoverageState::Unsupported
            },
            detail: match parsed {
                Ok(lines) => format!("{lines} text records normalized"),
                Err(error) => format!("raw preserved; text parser unavailable: {error}"),
            },
        })?;
        count = count.saturating_add(1);
        if count.is_multiple_of(100) {
            progress(&format!("{prefix}: {count} files saved"));
        }
    }
    case.coverage(&Coverage {
        source: path.display().to_string(),
        state: if failed > 0 {
            CoverageState::Failed
        } else if count == 0 {
            CoverageState::Empty
        } else {
            CoverageState::Collected
        },
        detail: format!(
            "{count} raw files saved; {failed} failed; unrecognized formats remain leads"
        ),
    })?;
    Ok(())
}

pub(crate) fn normalize_text_log(
    case: &mut Case,
    raw: &Path,
    name: &str,
    source: &str,
    original: &Path,
    context: Option<(&str, &str)>,
) -> Result<u64> {
    if original
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("har"))
    {
        let document: Value = serde_json::from_reader(BufReader::new(File::open(raw)?))?;
        let events = crate::transfers::har_events(&document, &format!("raw/{name}"))
            .context("HAR log.entries schema not recognized")?;
        let count = u64::try_from(events.len())?;
        for event in events {
            case.event(&event)?;
        }
        return Ok(count);
    }
    let mut count = 0_u64;
    let mut parser = crate::transfers::Parser::default();
    for line in BufReader::new(File::open(raw)?).lines() {
        let line = line?;
        count = count.saturating_add(1);
        if let Some(mut event) = parser.parse(&line, source, &format!("raw/{name}")) {
            if let Some((application, user)) = context {
                if event.application.is_none() {
                    event.application = Some(application.into());
                }
                if event.user.is_none() {
                    event.user = Some(format!("{user} (current account for discovery home)"));
                }
            }
            event.evidence_line = Some(count);
            case.event(&event)?;
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let network = [
            "upload", "download", "post ", "put ", "connect", "dns", "vpn", "src=", "dst=",
            "outbound", "egress",
        ]
        .iter()
        .any(|word| lower.contains(word));
        case.event(&Event {
            timestamp: None,
            source: source.into(),
            kind: if network {
                "network-lead"
            } else {
                "imported-record"
            }
            .into(),
            application: context.map(|(application, _)| application.into()),
            user: context.map(|(_, user)| format!("{user} (current account for discovery home)")),
            destination: None,
            detail: line,
            evidence: format!("raw/{name}"),
            level: EvidenceLevel::Lead,
            transfer: None,
            evidence_line: Some(count),
        })?;
    }
    Ok(count)
}

fn inventory(case: &mut Case, root: &Path, progress: &impl Fn(&str)) -> Result<()> {
    let case_root = case.root.clone();
    let mut output = BufWriter::new(File::create(
        case.root.join("normalized/file-inventory.jsonl"),
    )?);
    let mut count = 0_u64;
    let mut failed = 0_u64;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            let path = entry.path();
            !["/proc", "/sys", "/dev", "/run"]
                .iter()
                .any(|prefix| path == Path::new(prefix))
                && !path.starts_with(&case_root)
        })
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                failed = failed.saturating_add(1);
                case.coverage(&Coverage {
                    source: "file-inventory".into(),
                    state: CoverageState::Failed,
                    detail: error.to_string(),
                })?;
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                failed = failed.saturating_add(1);
                case.coverage(&Coverage {
                    source: entry.path().display().to_string(),
                    state: CoverageState::Failed,
                    detail: error.to_string(),
                })?;
                continue;
            }
        };
        serde_json::to_writer(
            &mut output,
            &serde_json::json!({
                "path": entry.path().display().to_string(), "bytes": metadata.len(),
                "modified": metadata.modified().ok().and_then(|stamp| jiff::Timestamp::try_from(stamp).map(|value| value.to_string()).ok()),
            }),
        )?;
        output.write_all(b"\n")?;
        count = count.saturating_add(1);
        if count.is_multiple_of(1_000) {
            output.flush()?;
        }
        if count.is_multiple_of(10_000) {
            progress(&format!("File inventory: {count} files saved"));
        }
    }
    output.flush()?;
    case.coverage(&Coverage {
        source: "file-inventory".into(),
        state: if failed > 0 { CoverageState::Failed } else if count == 0 { CoverageState::Empty } else { CoverageState::Collected },
        detail: format!("{count} files; {failed} unreadable entries; excludes proc, sys, dev, run, and case directory"),
    })?;
    Ok(())
}

struct LiveCapture {
    child: Child,
    started: Instant,
    started_at: String,
    seconds: u64,
}

impl Drop for LiveCapture {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status();
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }
}

fn start_capture(case: &mut Case, seconds: u64) -> Result<Option<LiveCapture>> {
    if !command_exists("tcpdump") || !command_exists("timeout") {
        case.coverage(&Coverage {
            source: "live-traffic".into(),
            state: CoverageState::Unavailable,
            detail: "tcpdump or timeout is not installed".into(),
        })?;
        return Ok(None);
    }
    let pcap = case.root.join("raw/live-traffic.pcap");
    let log = File::create(case.root.join("raw/live-traffic.log"))?;
    let child = Command::new("timeout")
        .args([
            "-s",
            "INT",
            &format!("{seconds}s"),
            "tcpdump",
            "-i",
            "any",
            "-nn",
            "-s",
            "0",
            "-U",
            "-w",
        ])
        .arg(&pcap)
        .stderr(log)
        .stdout(Stdio::null())
        .spawn()?;
    Ok(Some(LiveCapture {
        child,
        started: Instant::now(),
        started_at: jiff::Timestamp::now().to_string(),
        seconds,
    }))
}

fn finish_capture(
    case: &mut Case,
    capture: &mut LiveCapture,
    progress: &impl Fn(&str),
) -> Result<()> {
    let status = loop {
        if let Some(status) = capture.child.try_wait()? {
            break status;
        }
        progress(&format!(
            "Live traffic: {}/{}s",
            capture.started.elapsed().as_secs(),
            capture.seconds
        ));
        thread::sleep(Duration::from_secs(1));
    };
    case.record_existing("tcpdump -i any", "live-traffic.log")?;
    let pcap = case.root.join("raw/live-traffic.pcap");
    let bytes = if pcap.exists() {
        case.record_existing("tcpdump -i any", "live-traffic.pcap")?;
        fs::metadata(&pcap)?.len()
    } else {
        0
    };
    let code = status.code();
    case.coverage(&Coverage {
        source: "live-traffic".into(),
        state: if code != Some(124) && !status.success() {
            CoverageState::Failed
        } else if bytes <= 24 {
            CoverageState::Empty
        } else {
            CoverageState::Collected
        },
        detail: format!(
            "started {}; ended {}; elapsed {}s; {status}",
            capture.started_at,
            jiff::Timestamp::now(),
            capture.started.elapsed().as_secs()
        ),
    })?;
    if bytes > 24 {
        normalize_pcap(case, &pcap)?;
    }
    Ok(())
}

fn normalize_pcap(case: &mut Case, pcap: &Path) -> Result<()> {
    let mut child = Command::new("tcpdump")
        .args(["-nn", "-tttt", "-r"])
        .arg(pcap)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().context("tcpdump decode stdout")?;
    let mut raw = File::create(case.root.join("raw/live-traffic-summary.txt"))?;
    let mut count = 0_u64;
    for line in BufReader::new(stdout).lines() {
        let line = line?;
        writeln!(raw, "{line}")?;
        case.event(&Event {
            timestamp: {
                let mut fields = line.split_whitespace();
                fields
                    .next()
                    .zip(fields.next())
                    .map(|(date, time)| format!("{date}T{time}"))
            },
            source: "live-traffic".into(),
            kind: "packet".into(),
            application: None,
            user: None,
            destination: line
                .split_once(" > ")
                .and_then(|(_, tail)| tail.split_whitespace().next())
                .map(|endpoint| endpoint.trim_end_matches(':').to_owned()),
            detail: line,
            evidence: "raw/live-traffic-summary.txt".into(),
            level: EvidenceLevel::Observed,
            transfer: None,
            evidence_line: Some(count + 1),
        })?;
        count = count.saturating_add(1);
    }
    let status = child.wait()?;
    case.record_existing("tcpdump -nn -tttt -r", "live-traffic-summary.txt")?;
    case.coverage(&Coverage {
        source: "live-traffic-decode".into(),
        state: if !status.success() {
            CoverageState::Failed
        } else if count == 0 {
            CoverageState::Empty
        } else {
            CoverageState::Collected
        },
        detail: format!("{count} packet summaries; {status}"),
    })?;
    Ok(())
}
