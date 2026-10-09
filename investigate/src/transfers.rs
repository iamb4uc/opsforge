use crate::case::{Event, EvidenceLevel, Transfer};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn leading_timestamp(line: &str) -> Option<String> {
    let stamp = line.split_whitespace().next()?.trim_matches(['[', ']']);
    stamp
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|time| time.to_string())
}

pub(crate) fn rsync_event(
    line: &str,
    logger: Option<&str>,
    source: &str,
    raw: &str,
) -> Option<Event> {
    let (timestamp, message) = if matches!(logger, Some("rsync" | "rsyncd")) {
        (None, line)
    } else {
        let date = line.get(..10)?;
        let time = line.get(11..19)?;
        if line.get(10..11)? != " "
            || line.get(19..20)? != " "
            || date.as_bytes().get(4) != Some(&b'/')
            || date.as_bytes().get(7) != Some(&b'/')
        {
            return None;
        }
        let timestamp = format!("{}T{time}", date.replace('/', "-"));
        timestamp.parse::<jiff::civil::DateTime>().ok()?;
        let rest = line.get(20..)?.strip_prefix('[')?;
        let (pid, message) = rest.split_once("] ")?;
        if pid.parse::<u32>().ok()? == 0 {
            return None;
        }
        (Some(timestamp), message)
    };
    let (operation, rest) = message.split_once(' ')?;
    if operation.len() == 11
        && operation
            .bytes()
            .next()
            .is_some_and(|code| b"<>ch.".contains(&code))
        && operation
            .as_bytes()
            .get(1)
            .is_some_and(|kind| b"fdLDS".contains(kind))
        && operation
            .bytes()
            .skip(2)
            .all(|code| b".+?cstTpogunbax".contains(&code))
        && !rest.is_empty()
    {
        return Some(Event {
            timestamp,
            source: source.into(),
            kind: "rsync-itemized-update".into(),
            application: Some("rsync".into()),
            user: None,
            destination: Some(rest.into()),
            detail: format!(
                "{line}\nItemized update, not proof of a network transfer or completed payload. Local copies use this format too. Peer, actual transferred bytes and outcome are not retained; names are kept as logged and plain log time has no timezone."
            ),
            evidence: raw.into(),
            level: EvidenceLevel::Lead,
            transfer: None,
            evidence_line: None,
        });
    }
    if !matches!(operation, "send" | "recv" | "del.") {
        return None;
    }
    let (host, rest) = rest.split_once(" [")?;
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    let (peer, rest) = rest.split_once("] ")?;
    peer.parse::<std::net::IpAddr>().ok()?;
    let (module, rest) = rest.split_once(" (")?;
    if module.is_empty() {
        return None;
    }
    let (user, rest) = rest.split_once(") ")?;
    let (file, length) = rest.rsplit_once(' ')?;
    if file.is_empty() {
        return None;
    }
    let length: u64 = length.parse().ok()?;
    let direction = if operation == "recv" {
        "upload"
    } else {
        "download"
    };
    Some(Event {
        timestamp, source: source.into(), kind: if operation == "del." { "rsync-delete".into() } else { format!("{direction}-transfer") },
        application: Some("rsync daemon".into()), user: (!user.is_empty()).then(||user.to_owned()), destination: Some(file.into()),
        detail: format!("{line}\nDaemon operation record. It may describe content or metadata updates; actual payload bytes are unknown. File/module names are retained as logged, including escaping. Plain log time has no retained timezone."),
        evidence: raw.into(), level: EvidenceLevel::Recorded,
        transfer: (operation != "del.").then(||Transfer {
            direction: direction.into(), status: "observed".into(), protocol: "rsync".into(), perspective: "server".into(),
            file: Some(file.into()), target: Some(format!("module {module}")), peer: Some(peer.into()), bytes: Some(length),
            bytes_basis: "daemon %l: logged object length; not actual payload or wire bytes; object type is not retained".into(), method: Some(operation.into()),
        }), evidence_line: None,
    })
}

pub(crate) fn sftp_events(
    line: &str,
    logger: Option<&str>,
    source: &str,
    raw: &str,
) -> Option<Vec<Event>> {
    let message = if matches!(logger, Some("sftp-server" | "internal-sftp")) {
        line
    } else {
        let mut message = None;
        for program in ["sftp-server[", "internal-sftp["] {
            let (prefix, rest) = match line.split_once(program) {
                Some(parts) => parts,
                None => continue,
            };
            if !prefix.is_empty() && !prefix.ends_with(char::is_whitespace) {
                continue;
            }
            let (pid, payload) = rest.split_once("]: ")?;
            if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            message = Some(payload);
            break;
        }
        message?
    };
    let forced = message.starts_with("forced close ");
    let record = message
        .strip_prefix("forced close \"")
        .or_else(|| message.strip_prefix("close \""))?;
    let (file, counters) = record.rsplit_once("\" bytes read ")?;
    let (read, written) = counters.split_once(" written ")?;
    let read: u64 = read.parse().ok()?;
    let written: u64 = written.trim_end().parse().ok()?;
    let mut events = Vec::new();
    for (direction, bytes, operation) in
        [("download", read, "read"), ("upload", written, "written")]
    {
        if bytes == 0 {
            continue;
        }
        events.push(Event {
            timestamp: leading_timestamp(line), source: source.into(), kind: format!("{direction}-transfer"),
            application: Some("OpenSSH SFTP server".into()), user: None, destination: Some(file.into()),
            detail: line.into(), evidence: raw.into(), level: EvidenceLevel::Recorded,
            transfer: Some(Transfer {
                direction: direction.into(), status: if forced { "interrupted" } else { "observed" }.into(),
                protocol: "SFTP".into(), perspective: "server".into(), file: Some(file.into()), target: None, peer: None,
                bytes: Some(bytes), bytes_basis: format!("server handle bytes {operation}; repeated ranges count again; wire overhead, close success and whole-file completion are unknown"), method: Some(format!("handle bytes {operation}")),
            }), evidence_line: None,
        });
    }
    if events.is_empty() {
        events.push(Event {
            timestamp: leading_timestamp(line),
            source: source.into(),
            kind: "file-close".into(),
            application: Some("OpenSSH SFTP server".into()),
            user: None,
            destination: Some(file.into()),
            detail: line.into(),
            evidence: raw.into(),
            level: EvidenceLevel::Recorded,
            transfer: None,
            evidence_line: None,
        });
    }
    Some(events)
}

#[derive(Default)]
struct FileZillaSession {
    peer: Option<String>,
    pending: Option<(String, String, String)>,
}

#[derive(Default)]
pub struct Parser {
    filezilla: BTreeMap<(u32, u32), FileZillaSession>,
    rclone_paths: Option<(String, String, bool)>,
    network_backend: Option<String>,
    active_runs: u32,
    ambiguous_runs: bool,
}

impl Parser {
    fn filezilla_event(&mut self, line: &str, source: &str, raw: &str) -> Option<Event> {
        let date = line.get(..10)?;
        let time = line.get(11..19)?;
        if line.get(10..11)? != " " || line.get(19..20)? != " " {
            return None;
        }
        let timestamp = format!("{date}T{time}");
        timestamp.parse::<jiff::civil::DateTime>().ok()?;
        let (pid, rest) = line.get(20..)?.split_once(' ')?;
        let (engine, rest) = rest.split_once(' ')?;
        let key = (pid.parse::<u32>().ok()?, engine.parse::<u32>().ok()?);
        if key.0 == 0 || key.1 == 0 {
            return None;
        }
        let (kind, message) = rest.split_once(": ")?;
        if !matches!(kind, "Status" | "Error") {
            return None;
        }
        if let Some(endpoint) = message
            .strip_prefix("Connecting to ")
            .and_then(|value| value.strip_suffix("..."))
        {
            if self.filezilla.len() >= 4096 {
                self.filezilla.clear();
            }
            self.filezilla.insert(
                key,
                FileZillaSession {
                    peer: Some(endpoint.into()),
                    pending: None,
                },
            );
            return None;
        }
        if message == "Disconnected from server"
            || message.starts_with("Could not connect to server")
        {
            self.filezilla.remove(&key);
            return None;
        }
        let start = message
            .strip_prefix("Starting upload of ")
            .map(|file| ("upload", file))
            .or_else(|| {
                message
                    .strip_prefix("Starting download of ")
                    .map(|file| ("download", file))
            });
        if let Some((direction, file)) = start.filter(|(_, file)| !file.is_empty()) {
            if self.filezilla.len() >= 4096 && !self.filezilla.contains_key(&key) {
                self.filezilla.clear();
            }
            self.filezilla.entry(key).or_default().pending =
                Some((direction.into(), file.into(), line.into()));
            return Some(Event {
                timestamp: Some(timestamp),
                source: source.into(),
                kind: "filezilla-transfer-start".into(),
                application: Some("FileZilla".into()),
                user: None,
                destination: Some(file.into()),
                detail: format!(
                    "{line}\nTransfer start is intent; outcome and transferred bytes are not yet recorded. Source-local time has no retained timezone."
                ),
                evidence: raw.into(),
                level: EvidenceLevel::Lead,
                transfer: None,
                evidence_line: None,
            });
        }
        let (status, counter) = if message == "File transfer successful" {
            ("completed", None)
        } else if let Some(counter) = message.strip_prefix("File transfer successful, transferred ")
        {
            ("completed", Some(counter))
        } else if message == "File transfer skipped" {
            ("skipped", None)
        } else if message == "File transfer aborted by user" {
            ("interrupted", None)
        } else if let Some(counter) =
            message.strip_prefix("File transfer aborted by user after transferring ")
        {
            ("interrupted", Some(counter))
        } else if message == "File transfer failed" || message == "Critical file transfer error" {
            ("failed", None)
        } else if let Some(counter) = message
            .strip_prefix("File transfer failed after transferring ")
            .or_else(|| message.strip_prefix("Critical file transfer error after transferring "))
        {
            ("failed", Some(counter))
        } else {
            return None;
        };
        let mut unknown = FileZillaSession::default();
        let session = self.filezilla.get_mut(&key).unwrap_or(&mut unknown);
        let pending = session.pending.take();
        let (direction, file, start) = pending.map_or(
            ("unknown".into(), None, "Matching start not retained".into()),
            |(direction, file, start)| (direction, Some(file), start),
        );
        let bytes = counter
            .and_then(|counter| counter.split_once(" B in "))
            .and_then(|(bytes, _)| {
                (!bytes.is_empty() && bytes.bytes().all(|byte| byte.is_ascii_digit()))
                    .then_some(bytes)
            })
            .and_then(|bytes| bytes.parse::<u64>().ok());
        Some(Event {
            timestamp: Some(timestamp), source: source.into(), kind: if direction == "unknown" { "transfer".into() } else { format!("{direction}-transfer") },
            application: Some("FileZilla".into()), user: None, destination: session.peer.clone(),
            detail: format!("{line}\nMatched by logged process/engine {}/{}: {start}. Outcome is the client-reported operation result. Peer is the recorded connection endpoint; protocol, authentication identity and the opposite-side file path are not inferred. Source-local time has no retained timezone; rounded/localized byte counters remain unknown.", key.0,key.1),
            evidence: raw.into(), level: EvidenceLevel::Recorded,
            transfer: Some(Transfer {
                direction, status: status.into(), protocol: "unknown".into(), perspective: "client".into(), file,
                target: session.peer.clone(), peer: session.peer.clone(), bytes,
                bytes_basis: "client transfer progress (current offset minus starting offset); not full object size or wire bytes; resumed/skipped bytes excluded".into(), method: None,
            }), evidence_line: None,
        })
    }

    pub fn parse(&mut self, line: &str, source: &str, raw: &str) -> Option<Event> {
        if let Some(event) = self.filezilla_event(line, source, raw) {
            return Some(event);
        }
        if let Some(event) = rsync_event(line, None, source, raw) {
            return Some(event);
        }
        let mut event = Event {
            timestamp: leading_timestamp(line),
            source: source.into(),
            kind: "transfer".into(),
            application: None,
            user: None,
            destination: None,
            detail: line.into(),
            evidence: raw.into(),
            level: EvidenceLevel::Recorded,
            transfer: None,
            evidence_line: None,
        };
        if let Ok(record) = serde_json::from_str::<Value>(line) {
            if syncthing_record(&record, &mut event).is_some() {
                return Some(event);
            }
            if record.get("msg").is_some()
                && (record.get("objectType").is_some()
                    || record
                        .get("source")
                        .and_then(Value::as_str)
                        .is_some_and(|source| source.starts_with("cmd/")))
                && ["request_method", "method", "request"]
                    .iter()
                    .all(|field| record.get(field).is_none())
            {
                return self.rclone(&record, event);
            }
            let method = text(&record, "request_method").or_else(|| text(&record, "method"));
            let request = text(&record, "request");
            let method = method.or_else(|| {
                request
                    .as_deref()?
                    .split_whitespace()
                    .next()
                    .map(str::to_owned)
            })?;
            let target = text(&record, "request_uri")
                .or_else(|| text(&record, "uri"))
                .or_else(|| {
                    request
                        .as_deref()?
                        .split_whitespace()
                        .nth(1)
                        .map(str::to_owned)
                })?;
            let status = number(&record, "status")?;
            event.timestamp = text(&record, "time_iso8601").or_else(|| text(&record, "timestamp"));
            event.user = text(&record, "remote_user").filter(|value| value != "-");
            event.application = Some("HTTP server".into());
            let upload = matches!(method.as_str(), "PUT" | "POST" | "PATCH");
            event.transfer = http_transfer(
                &method,
                target,
                status,
                text(&record, "remote_addr"),
                number(
                    &record,
                    if upload {
                        "request_length"
                    } else {
                        "body_bytes_sent"
                    },
                ),
            );
        } else if let Some(transfer) = xferlog(line, &mut event) {
            event.transfer = Some(transfer);
        } else {
            let (prefix, rest) = line.split_once('"')?;
            let (request, suffix) = rest.split_once('"')?;
            let mut request = request.split_whitespace();
            let method = request.next()?;
            let target = request.next()?;
            if !request.next()?.starts_with("HTTP/") {
                return None;
            }
            let mut response = suffix.split_whitespace();
            let status = response.next()?.parse::<u64>().ok()?;
            let response_bytes = response.next()?.parse::<u64>().ok();
            let stamp = prefix.split_once('[')?.1.strip_suffix("] ")?.trim();
            event.timestamp = jiff::Timestamp::strptime("%d/%b/%Y:%H:%M:%S %z", stamp)
                .ok()
                .map(|time| time.to_string());
            let mut fields = prefix.split_whitespace();
            let peer = fields.next().map(str::to_owned);
            event.user = fields
                .nth(1)
                .filter(|value| *value != "-")
                .map(str::to_owned);
            event.application = Some("HTTP server".into());
            event.transfer = http_transfer(
                method,
                target.into(),
                status,
                peer,
                if matches!(method, "PUT" | "POST" | "PATCH") {
                    None
                } else {
                    response_bytes
                },
            );
        }
        let transfer = event.transfer.as_ref()?;
        event.destination = transfer.target.clone();
        event.kind = format!(
            "{}-{}",
            transfer.direction,
            if transfer.protocol == "HTTP" {
                "request"
            } else {
                "transfer"
            }
        );
        Some(event)
    }

    fn rclone(&mut self, record: &Value, mut event: Event) -> Option<Event> {
        let message = text(record, "msg")?;
        let object_type = text(record, "objectType").unwrap_or_default();
        if message.trim_end().ends_with("go routines active")
            && text(record, "source").is_some_and(|source| source.starts_with("cmd/"))
        {
            self.active_runs = self.active_runs.saturating_sub(1);
            self.rclone_paths = None;
            self.network_backend = None;
            self.ambiguous_runs = self.active_runs > 0;
        }
        if message.contains("starting with parameters [") {
            self.ambiguous_runs = self.active_runs > 0;
            self.active_runs = self.active_runs.saturating_add(1);
            self.rclone_paths = None;
            self.network_backend = None;
            let parameters = message
                .split_once("starting with parameters [")?
                .1
                .strip_suffix(']')?;
            let args = serde_json::Deserializer::from_str(parameters)
                .into_iter::<String>()
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            if !self.ambiguous_runs {
                self.rclone_paths = rclone_arguments(&args);
            }
        }
        if object_type.ends_with(".Fs")
            && [
                "*ftp.",
                "*sftp.",
                "*s3.",
                "*drive.",
                "*dropbox.",
                "*onedrive.",
                "*webdav.",
                "*azureblob.",
                "*b2.",
            ]
            .iter()
            .any(|prefix| object_type.starts_with(prefix))
        {
            self.network_backend = text(record, "object");
        }
        let object = text(record, "object")?;
        if !object_type.ends_with(".Object")
            || !(message.starts_with("Copied (") || message.starts_with("Failed to copy:"))
        {
            return None;
        }
        let mut direction = "unknown";
        let mut file = Some(object.clone());
        let mut target = None;
        if let Some((from, to, single_file)) = &self.rclone_paths {
            if !from.contains(':')
                && to.contains(':')
                && self.network_backend.is_some()
                && object_type == "*local.Object"
            {
                direction = "upload";
                target = Some(if *single_file {
                    file = Some(from.clone());
                    to.clone()
                } else {
                    format!(
                        "{}/{object}",
                        self.network_backend.as_deref()?.trim_end_matches('/')
                    )
                });
            } else if from.contains(':')
                && !to.contains(':')
                && object_type != "*local.Object"
                && self.network_backend.is_some()
            {
                direction = "download";
                target = Some(if *single_file {
                    file = Some(to.clone());
                    from.clone()
                } else {
                    format!(
                        "{}/{object}",
                        self.network_backend.as_deref()?.trim_end_matches('/')
                    )
                });
            }
        }
        event.timestamp = text(record, "time");
        event.application = Some("rclone".into());
        event.source = "rclone-json".into();
        event.kind = format!("{direction}-transfer");
        event.destination = target.clone();
        event.transfer = Some(Transfer {
            direction: direction.into(),
            status: if message.starts_with("Copied (") {
                "completed"
            } else {
                "failed"
            }
            .into(),
            protocol: "rclone".into(),
            perspective: "client".into(),
            file,
            target,
            peer: None,
            bytes: number(record, "size"),
            bytes_basis: "object size when logged; not aggregate stats".into(),
            method: None,
        });
        Some(event)
    }
}

fn syncthing_record(record: &Value, event: &mut Event) -> Option<()> {
    if ["request_method", "method", "request"]
        .iter()
        .any(|field| record.get(field).is_some())
    {
        return None;
    }
    record.get("id")?.as_u64()?;
    if let Some(global_id) = record.get("globalID") {
        global_id.as_u64()?;
    }
    let kind = record.get("type")?.as_str()?;
    let timestamp = record.get("time")?.as_str()?;
    let data = record.get("data")?.as_object()?;
    let (activity, destination, limits) = match kind {
        "ItemStarted" | "ItemFinished" => {
            let folder = data.get("folder")?.as_str()?;
            let item = data.get("item")?.as_str()?;
            let item_type = data.get("type")?.as_str()?;
            let action = data.get("action")?.as_str()?;
            if !matches!(action, "update" | "metadata" | "delete")
                || !matches!(item_type, "file" | "dir" | "symlink")
            {
                return None;
            }
            let outcome = if kind == "ItemStarted" {
                "started"
            } else {
                match data.get("error") {
                    Some(Value::Null) => "completed",
                    Some(Value::String(error)) if !error.is_empty() => "failed",
                    _ => "unknown",
                }
            };
            (
                format!("sync-{item_type}-{action}-{outcome}"),
                Some(format!("folder {folder}: {item}")),
                "Local synchronization operation; this can reuse local blocks. Network direction, transferred bytes, originating peer and outbound upload completion are not established.",
            )
        }
        "StateChanged" => {
            let folder = data.get("folder")?.as_str()?;
            let state = data.get("to")?.as_str()?;
            (
                format!("sync-state-{state}"),
                Some(format!("folder {folder}")),
                "Retained local folder state; state duration is not a transfer duration, and idle does not prove an upload completed. Any error remains tied to this event time.",
            )
        }
        "FolderErrors" => {
            let folder = data.get("folder")?.as_str()?;
            data.get("errors")?.as_array()?;
            (
                "sync-folder-errors".into(),
                Some(format!("folder {folder}")),
                "Retained local file/directory error list; a later syncing state makes this list obsolete. This does not establish a failed outbound transfer.",
            )
        }
        "DeviceConnected" | "DeviceDisconnected" => {
            let device = data.get("id")?.as_str()?;
            let destination = data.get("addr").and_then(Value::as_str).unwrap_or(device);
            (
                (if kind == "DeviceConnected" {
                    "active-connection"
                } else {
                    "connection-closed"
                })
                .into(),
                Some(destination.into()),
                "Retained device connection event; a connection or disconnection does not establish file transfer or bytes. A disconnection reason is not automatically a failed transfer.",
            )
        }
        _ => return None,
    };
    event.timestamp = Some(timestamp.into());
    event.application = Some("Syncthing".into());
    event.kind = activity;
    event.destination = destination;
    event.detail = format!("{limits}\n{}", event.detail);
    Some(())
}

fn rclone_arguments(args: &[String]) -> Option<(String, String, bool)> {
    let mut positionals = Vec::new();
    let mut args = args.iter().skip(1);
    let mut flags = true;
    while let Some(argument) = args.next() {
        if flags && argument == "--" {
            flags = false;
        } else if flags && argument.starts_with('-') {
            if argument.starts_with("--") && argument.contains('=') {
                continue;
            }
            match argument.as_str() {
                "-v"
                | "-vv"
                | "-q"
                | "-P"
                | "--verbose"
                | "--quiet"
                | "--progress"
                | "--use-json-log"
                | "--checksum"
                | "--size-only"
                | "--ignore-existing"
                | "--ignore-times"
                | "--dry-run"
                | "--fast-list"
                | "--no-traverse"
                | "--stats-one-line"
                | "--stats-one-line-date" => {}
                "--config"
                | "--log-file"
                | "--log-level"
                | "--log-format"
                | "--stats"
                | "--stats-log-level"
                | "--transfers"
                | "--checkers"
                | "--bwlimit"
                | "--include"
                | "--exclude"
                | "--filter"
                | "--files-from"
                | "--files-from-raw"
                | "--min-age"
                | "--max-age"
                | "--min-size"
                | "--max-size"
                | "--retries"
                | "--low-level-retries" => {
                    args.next()?;
                }
                // Unknown flag arity must not shift paths into an invented direction.
                _ => return None,
            }
        } else {
            positionals.push(argument);
        }
    }
    let [command, from, to] = positionals.as_slice() else {
        return None;
    };
    if !matches!(
        command.as_str(),
        "copy" | "sync" | "move" | "copyto" | "moveto"
    ) {
        return None;
    }
    Some((
        (*from).clone(),
        (*to).clone(),
        matches!(command.as_str(), "copyto" | "moveto"),
    ))
}

fn text(record: &Value, key: &str) -> Option<String> {
    record
        .get(key)?
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn number(record: &Value, key: &str) -> Option<u64> {
    let value = record.get(key)?;
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

fn http_transfer(
    method: &str,
    target: String,
    status: u64,
    peer: Option<String>,
    bytes: Option<u64>,
) -> Option<Transfer> {
    let direction = match method {
        "PUT" | "POST" | "PATCH" => "upload",
        "GET" => "download",
        _ => return None,
    };
    if !(100..600).contains(&status) {
        return None;
    }
    Some(Transfer {
        direction: direction.into(),
        status: if (200..300).contains(&status) {
            "accepted"
        } else if status >= 400 {
            "failed"
        } else {
            "other-response"
        }
        .into(),
        protocol: "HTTP".into(),
        perspective: "server".into(),
        file: None,
        target: Some(target),
        peer,
        bytes,
        bytes_basis: if direction == "upload" {
            "request including headers; not file size"
        } else {
            "response body; not necessarily a file"
        }
        .into(),
        method: Some(method.into()),
    })
}

fn xferlog(line: &str, event: &mut Event) -> Option<Transfer> {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 18
        || fields[14] != "ftp"
        || !matches!(fields[11], "i" | "o")
        || !matches!(fields[17], "c" | "i")
    {
        return None;
    }
    let bytes = fields[7].parse::<u64>().ok()?;
    event.timestamp =
        jiff::civil::DateTime::strptime("%a %b %e %H:%M:%S %Y", fields[..5].join(" "))
            .ok()
            .map(|time| time.to_string());
    event.source = "ftp-xferlog".into();
    event.application = Some("FTP server".into());
    event.user = Some(fields[13].into());
    Some(Transfer {
        direction: if fields[11] == "i" {
            "upload"
        } else {
            "download"
        }
        .into(),
        status: if fields[17] == "c" {
            "completed"
        } else {
            "incomplete"
        }
        .into(),
        protocol: "FTP".into(),
        perspective: "server".into(),
        file: Some(fields[8].into()),
        target: Some(fields[8].into()),
        peer: Some(fields[6].into()),
        bytes: Some(bytes),
        bytes_basis: "transferred bytes; xferlog replaces spaces with underscores".into(),
        method: None,
    })
}

pub fn har_events(record: &Value, raw: &str) -> Option<Vec<Event>> {
    let entries = record.get("log")?.get("entries")?.as_array()?;
    let mut events = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let request = entry.get("request")?;
        let method = text(request, "method")?;
        let target = text(request, "url")?;
        if !matches!(method.as_str(), "PUT" | "POST" | "PATCH" | "GET") {
            continue;
        }
        let status = entry
            .get("response")
            .and_then(|response| number(response, "status"));
        let files: Vec<_> = request
            .get("postData")
            .and_then(|data| data.get("params"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|param| text(param, "fileName"))
            .collect();
        let files = if files.is_empty() {
            vec![None]
        } else {
            files.into_iter().map(Some).collect()
        };
        for file in files {
            let upload = method != "GET";
            let bytes = if upload {
                number(request, "bodySize")
            } else {
                entry
                    .get("response")
                    .and_then(|response| number(response, "bodySize"))
            };
            events.push(Event {
                timestamp: text(entry, "startedDateTime"),
                source: "http-har".into(),
                kind: if upload {
                    "upload-request"
                } else {
                    "download-request"
                }
                .into(),
                application: Some("HTTP client (HAR)".into()),
                user: None,
                destination: Some(target.clone()),
                detail: format!(
                    "HAR log.entries[{index}]; {method} {target}; response {}",
                    status.map_or_else(|| "unknown".into(), |value| value.to_string())
                ),
                evidence: raw.into(),
                level: EvidenceLevel::Recorded,
                evidence_line: None,
                transfer: Some(Transfer {
                    direction: if upload { "upload" } else { "download" }.into(),
                    status: match status {
                        Some(200..=299) => "accepted",
                        Some(400..=599) => "failed",
                        _ => "unknown",
                    }
                    .into(),
                    protocol: "HTTP".into(),
                    perspective: "client".into(),
                    file,
                    target: Some(target.clone()),
                    peer: None,
                    bytes,
                    bytes_basis: "HAR body size; not per-file bytes; -1 means unavailable".into(),
                    method: Some(method.clone()),
                }),
            });
        }
    }
    Some(events)
}

#[cfg(test)]
mod tests {
    #[test]
    fn filezilla_engine_ids_isolate_interleaved_results_and_rounded_bytes() {
        let mut parser = super::Parser::default();
        for (engine, direction, file) in [
            (2, "upload", "/local/file with spaces.txt"),
            (3, "download", "/remote/file.txt"),
        ] {
            parser.parse(
                &format!(
                    "2026-10-09 18:04:30 42 {engine} Status: Connecting to 127.0.0.1:35589..."
                ),
                "import",
                "raw/log",
            );
            let start = parser
                .parse(
                    &format!(
                        "2026-10-09 18:04:30 42 {engine} Status: Starting {direction} of {file}"
                    ),
                    "import",
                    "raw/log",
                )
                .expect("start");
            assert!(start.transfer.is_none());
        }
        let result = parser.parse("2026-10-09 18:04:31 42 3 Status: File transfer successful, transferred 1.2 KiB in 1 second", "import", "raw/log").expect("download");
        let download = result.transfer.expect("transfer");
        assert_eq!(download.direction, "download");
        assert_eq!(download.file.as_deref(), Some("/remote/file.txt"));
        assert!(download.bytes.is_none());
        let result = parser.parse("2026-10-09 18:04:31 42 2 Status: File transfer successful, transferred 26 B in 1 second", "import", "raw/log").expect("upload");
        let upload = result.transfer.expect("transfer");
        assert_eq!(upload.direction, "upload");
        assert_eq!(upload.status, "completed");
        assert_eq!(upload.bytes, Some(26));
        assert_eq!(upload.peer.as_deref(), Some("127.0.0.1:35589"));
        assert_eq!(upload.file.as_deref(), Some("/local/file with spaces.txt"));
        let orphan = parser
            .parse(
                "2026-10-09 18:04:32 43 2 Status: File transfer successful",
                "import",
                "raw/log",
            )
            .expect("orphan")
            .transfer
            .expect("transfer");
        assert_eq!(orphan.direction, "unknown");
        assert!(orphan.file.is_none() && orphan.peer.is_none());
        parser.parse(
            "2026-10-09 18:04:32 42 2 Status: Starting upload of /stale",
            "import",
            "raw/log",
        );
        parser.parse(
            "2026-10-09 18:04:32 42 2 Status: Connecting to other.example:21...",
            "import",
            "raw/log",
        );
        let retry = parser
            .parse(
                "2026-10-09 18:04:33 42 2 Error: File transfer failed",
                "import",
                "raw/log",
            )
            .expect("retry")
            .transfer
            .expect("transfer");
        assert_eq!(retry.direction, "unknown");
        assert!(retry.file.is_none());
        for line in [
            "2026-02-30 18:04:30 42 2 Status: File transfer successful",
            "2026-10-09 18:04:30 0 2 Status: File transfer successful",
            "2026-10-09 18:04:30 42 2 Response: 226 Transfer complete.",
        ] {
            assert!(parser.filezilla_event(line, "import", "raw/log").is_none());
        }
    }

    #[test]
    fn rsync_records_keep_object_length_and_local_updates_distinct() {
        let mut parser = super::Parser::default();
        for (operation, direction) in [("recv", "upload"), ("send", "download")] {
            let line = format!(
                "2026/10/09 17:38:45 [42] {operation} UNDETERMINED [::1] evidence () report with spaces.txt 35"
            );
            let event = parser.parse(&line, "import", "raw/rsync").expect("daemon");
            assert_eq!(event.timestamp.as_deref(), Some("2026-10-09T17:38:45"));
            assert!(event.user.is_none());
            let transfer = event.transfer.expect("operation");
            assert_eq!(transfer.direction, direction);
            assert_eq!(transfer.status, "observed");
            assert_eq!(transfer.file.as_deref(), Some("report with spaces.txt"));
            assert_eq!(transfer.bytes, Some(35));
            assert!(transfer.bytes_basis.contains("not actual payload"));
        }
        for code in [">f+++++++++", "<f..t......"] {
            let line = format!("2026/10/09 17:38:45 [42] {code} report with spaces.txt");
            let event = parser
                .parse(&line, "import", "raw/rsync")
                .expect("itemized");
            assert!(event.transfer.is_none());
            assert_eq!(event.kind, "rsync-itemized-update");
        }
        let message = "recv host [127.0.0.1] evidence (operator) file 35";
        let journal =
            super::rsync_event(message, Some("rsync"), "journal", "raw/journal").expect("journal");
        assert!(journal.timestamp.is_none());
        assert_eq!(journal.user.as_deref(), Some("operator"));
        assert!(super::rsync_event(message, Some("logger"), "journal", "raw/journal").is_none());
        for line in [
            "2026/02/30 17:38:45 [42] recv host [127.0.0.1] evidence () file 35",
            "2026/10/09 17:38:45 [0] recv host [127.0.0.1] evidence () file 35",
            "2026/10/09 17:38:45 [42] recv host [invalid] evidence () file 35",
            "2026/10/09 17:38:45 [42] recv host [127.0.0.1] evidence () file 35K",
            "2026/10/09 17:38:45 [42] sent 35 bytes received 70 bytes",
        ] {
            assert!(
                super::rsync_event(line, None, "import", "raw/rsync").is_none(),
                "{line}"
            );
        }
    }

    #[test]
    fn leading_times_require_a_full_date_and_explicit_offset() {
        for line in [
            "2026-10-09T12:00:00+05:30 host app[1]: upload",
            "[2026-10-09T06:30:00Z] upload",
        ] {
            assert_eq!(
                super::leading_timestamp(line).as_deref(),
                Some("2026-10-09T06:30:00Z")
            );
        }
        for line in [
            "Oct 9 12:00:00 host upload",
            "2026-10-09T12:00:00 host upload",
            "upload completed at 2026-10-09T06:30:00Z",
            "2026-02-30T06:30:00Z upload",
        ] {
            assert!(super::leading_timestamp(line).is_none(), "{line}");
        }
    }

    use super::{Parser, har_events};
    use serde_json::json;

    #[test]
    fn syncthing_audit_keeps_local_operations_separate_from_network_transfers() {
        let mut parser = Parser::default();
        for (kind, action, error, expected) in [
            (
                "ItemStarted",
                "update",
                json!(null),
                "sync-file-update-started",
            ),
            (
                "ItemFinished",
                "update",
                json!(null),
                "sync-file-update-completed",
            ),
            (
                "ItemFinished",
                "metadata",
                json!(null),
                "sync-file-metadata-completed",
            ),
            (
                "ItemFinished",
                "delete",
                json!("permission denied"),
                "sync-file-delete-failed",
            ),
            (
                "ItemFinished",
                "update",
                json!(""),
                "sync-file-update-unknown",
            ),
        ] {
            let record = json!({"id":1,"globalID":2,"type":kind,"time":"2026-10-09T00:00:00Z","data":{"folder":"lab","item":"file with spaces.txt","type":"file","action":action,"error":error}});
            let event = parser
                .parse(&record.to_string(), "audit", "raw/audit")
                .expect("event");
            assert_eq!(event.kind, expected);
            assert_eq!(event.application.as_deref(), Some("Syncthing"));
            assert_eq!(
                event.destination.as_deref(),
                Some("folder lab: file with spaces.txt")
            );
            assert!(event.transfer.is_none());
            assert!(event.detail.contains("reuse local blocks"));
        }
        for (kind, expected) in [
            ("DeviceConnected", "active-connection"),
            ("DeviceDisconnected", "connection-closed"),
        ] {
            let record = json!({"id":1,"globalID":2,"type":kind,"time":"2026-10-09T00:00:00Z","data":{"id":"device-id","addr":"127.0.0.1:22000","error":"unexpected EOF"}});
            let event = parser
                .parse(&record.to_string(), "audit", "raw/audit")
                .expect("connection");
            assert_eq!(event.kind, expected);
            assert_eq!(event.destination.as_deref(), Some("127.0.0.1:22000"));
            assert!(event.transfer.is_none());
        }
        assert!(
            parser
                .parse(
                    r#"{"type":"ItemFinished","data":{"item":"file"}}"#,
                    "audit",
                    "raw/audit"
                )
                .is_none()
        );
        let http = json!({"id":1,"globalID":1,"type":"ItemFinished","time":"2026-10-09T00:00:00Z","data":{"folder":"lab","item":"file","type":"file","action":"update","error":null},"method":"POST","uri":"/upload","status":201});
        assert_eq!(
            parser
                .parse(&http.to_string(), "log", "raw/log")
                .expect("HTTP record")
                .application
                .as_deref(),
            Some("HTTP server")
        );
        for (record, expected) in [
            (
                json!({"id":1,"type":"FolderErrors","time":"2026-10-09T00:00:00Z","data":{"folder":"lab","errors":[{"path":"file.txt","error":"permission denied"}]}}),
                "sync-folder-errors",
            ),
            (
                json!({"id":1,"globalID":1,"type":"StateChanged","time":"2026-10-09T00:00:00Z","data":{"folder":"lab","from":"idle","to":"error","error":"permission denied","duration":1}}),
                "sync-state-error",
            ),
        ] {
            let event = parser
                .parse(&record.to_string(), "audit", "raw/audit")
                .expect("folder event");
            assert_eq!(event.kind, expected);
            assert!(event.detail.contains("permission denied"));
            assert!(event.transfer.is_none());
        }
    }

    #[test]
    fn sftp_counts_keep_server_perspective_and_unknown_completion() {
        let line = "Oct 9 10:00:00 host internal-sftp[42]: close \"/uploads/file with spaces.txt\" bytes read 12 written 34";
        let events = super::sftp_events(line, None, "log", "raw/log").expect("close record");
        assert_eq!(events.len(), 2);
        for (event, direction, bytes) in [(&events[0], "download", 12), (&events[1], "upload", 34)]
        {
            let transfer = event.transfer.as_ref().expect("counter");
            assert_eq!(transfer.direction, direction);
            assert_eq!(transfer.bytes, Some(bytes));
            assert_eq!(transfer.status, "observed");
            assert_eq!(transfer.perspective, "server");
            assert_eq!(
                transfer.file.as_deref(),
                Some("/uploads/file with spaces.txt")
            );
            assert!(event.timestamp.is_none() && event.user.is_none() && transfer.peer.is_none());
        }
        let forced = super::sftp_events(
            "forced close \"file\" bytes read 0 written 1",
            Some("internal-sftp"),
            "journal",
            "raw/journal",
        )
        .expect("forced");
        assert_eq!(
            forced[0].transfer.as_ref().expect("counter").status,
            "interrupted"
        );
        assert!(
            super::sftp_events(
                "close \"file\" bytes read 1 written 0",
                None,
                "log",
                "raw/log"
            )
            .is_none()
        );
        assert!(
            super::sftp_events(
                "http://host/internal-sftp[42]: close \"file\" bytes read 1 written 0",
                None,
                "log",
                "raw/log"
            )
            .is_none()
        );
        assert!(
            super::sftp_events(
                "close \"file\" bytes read -1 written 0",
                Some("sftp-server"),
                "log",
                "raw/log"
            )
            .is_none()
        );
        let empty = super::sftp_events(
            "close \"file\" bytes read 0 written 0",
            Some("sftp-server"),
            "log",
            "raw/log",
        )
        .expect("zero counters");
        assert_eq!(empty.len(), 1);
        assert!(empty[0].transfer.is_none());
    }

    fn rclone_line(message: &str, object: &str, object_type: &str) -> String {
        json!({"msg": message, "object": object, "objectType": object_type,
            "source": "cmd/cmd.go:1", "time": "2026-10-09T00:00:00Z"})
        .to_string()
    }

    #[test]
    fn json_log_fields_do_not_confuse_http_and_rclone() {
        let mut parser = Parser::default();
        let http = json!({"msg": "request complete", "source": "proxy",
            "request_method": "POST", "request_uri": "/upload", "status": 201,
            "request_length": 200})
        .to_string();
        let event = parser.parse(&http, "log", "raw/log").expect("HTTP record");
        assert_eq!(event.application.as_deref(), Some("HTTP server"));
        assert_eq!(event.transfer.expect("transfer").direction, "upload");
        let copied = json!({"msg": "Copied (new)", "object": "file.txt",
            "objectType": "*local.Object"})
        .to_string();
        let event = parser
            .parse(&copied, "log", "raw/log")
            .expect("rclone record without source field");
        assert_eq!(event.application.as_deref(), Some("rclone"));
        assert_eq!(event.transfer.expect("transfer").direction, "unknown");
    }

    fn start_rclone(parser: &mut Parser, args: &[&str]) {
        let parameters = args
            .iter()
            .map(|arg| serde_json::to_string(arg).expect("arg"))
            .collect::<Vec<_>>()
            .join(" ");
        parser.parse(
            &rclone_line(
                &format!("Version starting with parameters [{parameters}]"),
                "rclone",
                "string",
            ),
            "log",
            "raw/log",
        );
        parser.parse(
            &rclone_line("dial", "ftp://example.test/folder", "*ftp.Fs"),
            "log",
            "raw/log",
        );
    }

    #[test]
    fn rclone_flags_and_single_file_commands_keep_actual_target() {
        for command in ["copyto", "moveto"] {
            let mut parser = Parser::default();
            start_rclone(
                &mut parser,
                &[
                    "rclone",
                    "--config",
                    "/safe/config",
                    command,
                    "--use-json-log",
                    "/local/original.txt",
                    "remote:renamed.txt",
                    "--log-level=DEBUG",
                ],
            );
            let event = parser
                .parse(
                    &rclone_line("Copied (new)", "original.txt", "*local.Object"),
                    "log",
                    "raw/log",
                )
                .expect("record");
            let transfer = event.transfer.expect("transfer");
            assert_eq!(transfer.direction, "upload", "{command}");
            assert_eq!(transfer.target.as_deref(), Some("remote:renamed.txt"));
        }
        let mut parser = Parser::default();
        start_rclone(
            &mut parser,
            &[
                "rclone",
                "copy",
                "--log-level",
                "DEBUG",
                "--progress",
                "/local/folder",
                "remote:folder",
            ],
        );
        let transfer = parser
            .parse(
                &rclone_line("Copied (new)", "document.txt", "*local.Object"),
                "log",
                "raw/log",
            )
            .expect("record")
            .transfer
            .expect("transfer");
        assert_eq!(transfer.direction, "upload");
        assert_eq!(
            transfer.target.as_deref(),
            Some("ftp://example.test/folder/document.txt")
        );
    }

    #[test]
    fn rclone_unknown_flags_and_interleaved_runs_do_not_invent_direction() {
        let copied = rclone_line("Copied (new)", "document.txt", "*local.Object");
        let args = ["rclone", "copy", "/local/folder", "remote:folder"];
        let mut parser = Parser::default();
        start_rclone(
            &mut parser,
            &[
                "rclone",
                "--unknown-option",
                "copy",
                "/local/folder",
                "remote:folder",
            ],
        );
        assert_eq!(
            parser
                .parse(&copied, "log", "raw/log")
                .expect("record")
                .transfer
                .expect("transfer")
                .direction,
            "unknown"
        );
        parser.parse(
            &rclone_line("4 go routines active", "rclone", "string"),
            "log",
            "raw/log",
        );
        start_rclone(&mut parser, &args);
        assert_eq!(
            parser
                .parse(&copied, "log", "raw/log")
                .expect("record")
                .transfer
                .expect("transfer")
                .direction,
            "upload"
        );
        start_rclone(&mut parser, &args);
        assert_eq!(
            parser
                .parse(&copied, "log", "raw/log")
                .expect("record")
                .transfer
                .expect("transfer")
                .direction,
            "unknown"
        );
        parser.parse(
            &rclone_line("4 go routines active", "rclone", "string"),
            "log",
            "raw/log",
        );
        assert_eq!(
            parser
                .parse(&copied, "log", "raw/log")
                .expect("record")
                .transfer
                .expect("transfer")
                .direction,
            "unknown"
        );
        parser.parse(
            &rclone_line("4 go routines active", "rclone", "string"),
            "log",
            "raw/log",
        );
        start_rclone(&mut parser, &args);
        assert_eq!(
            parser
                .parse(&copied, "log", "raw/log")
                .expect("record")
                .transfer
                .expect("transfer")
                .direction,
            "upload"
        );
    }

    #[test]
    fn rclone_requires_command_and_network_backend_before_assigning_upload_direction() {
        let mut parser = Parser::default();
        let copied = json!({"msg":"Copied (new)","object":"report.txt","objectType":"*local.Object","source":"operations/copy.go:123","time":"2026-10-06T00:00:00Z"}).to_string();
        assert_eq!(
            parser
                .parse(&copied, "imported-log", "raw/log")
                .expect("record")
                .transfer
                .expect("transfer")
                .direction,
            "unknown"
        );
        let command = json!({"msg":"Version starting with parameters [\"rclone\" \"copy\" \"/home/operator/files\" \"remote:folder\"]","object":"rclone","objectType":"string","source":"cmd/cmd.go:414"}).to_string();
        parser.parse(&command, "imported-log", "raw/log");
        assert_eq!(
            parser
                .parse(&copied, "imported-log", "raw/log")
                .expect("record")
                .transfer
                .expect("transfer")
                .direction,
            "unknown"
        );
        parser.parse(&json!({"msg":"dial","object":"ftp://example.test/folder","objectType":"*ftp.Fs","source":"ftp/ftp.go:341"}).to_string(),"imported-log","raw/log");
        let transfer = parser
            .parse(&copied, "imported-log", "raw/log")
            .expect("record")
            .transfer
            .expect("transfer");
        assert_eq!(transfer.direction, "upload");
        assert_eq!(transfer.file.as_deref(), Some("report.txt"));
        assert_eq!(
            transfer.target.as_deref(),
            Some("ftp://example.test/folder/report.txt")
        );
        assert!(transfer.bytes.is_none());
        parser.parse(&command, "imported-log", "raw/log");
        assert_eq!(
            parser
                .parse(&copied, "imported-log", "raw/log")
                .expect("record")
                .transfer
                .expect("transfer")
                .direction,
            "unknown"
        );
        assert!(
            parser
                .parse("POST /upload upload complete", "imported-log", "raw/log")
                .is_none()
        );
    }

    #[test]
    fn har_keeps_each_uploaded_filename_without_dividing_request_bytes() {
        let har = json!({"log":{"entries":[{"startedDateTime":"2026-10-06T00:00:00Z","request":{"method":"POST","url":"https://example.test/upload","bodySize":500,"postData":{"params":[{"fileName":"first.txt"},{"fileName":"second.txt"}]}},"response":{"status":201}}]}});
        let events = har_events(&har, "raw/browser.har").expect("har");
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[1]
                .transfer
                .as_ref()
                .expect("transfer")
                .file
                .as_deref(),
            Some("second.txt")
        );
        assert_eq!(
            events[0].transfer.as_ref().expect("transfer").bytes,
            Some(500)
        );
        assert_eq!(
            events[0].transfer.as_ref().expect("transfer").status,
            "accepted"
        );
        assert!(events[0].detail.contains("log.entries[0]"));
    }
}
