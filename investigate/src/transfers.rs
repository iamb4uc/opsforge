use crate::case::{Event, EvidenceLevel, Transfer};
use serde_json::Value;

#[derive(Default)]
pub struct Parser {
    rclone_paths: Option<(String, String)>,
    network_backend: Option<String>,
    run_active: bool,
    ambiguous_runs: bool,
}

impl Parser {
    pub fn parse(&mut self, line: &str, source: &str, raw: &str) -> Option<Event> {
        if line.contains(" Failed to create file system for ") {
            self.run_active = false;
            self.rclone_paths = None;
            self.network_backend = None;
        }
        let mut event = Event {
            timestamp: None,
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
            if record.get("msg").is_some() && record.get("source").is_some() {
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
        if message.trim_end().ends_with("go routines active") {
            self.run_active = false;
            self.rclone_paths = None;
            self.network_backend = None;
        }
        if message.contains("starting with parameters [") {
            self.ambiguous_runs |= self.run_active;
            self.run_active = true;
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
            if args.len() >= 4
                && !self.ambiguous_runs
                && matches!(args[1].as_str(), "copy" | "sync" | "move")
                && !args[2].starts_with('-')
                && !args[3].starts_with('-')
            {
                self.rclone_paths = Some((args[2].clone(), args[3].clone()));
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
        let file = Some(object.clone());
        let mut target = self.network_backend.clone();
        if let Some((from, to)) = &self.rclone_paths {
            if !from.contains(':')
                && to.contains(':')
                && self.network_backend.is_some()
                && object_type == "*local.Object"
            {
                direction = "upload";
                target = Some(format!(
                    "{}/{object}",
                    self.network_backend.as_deref()?.trim_end_matches('/')
                ));
            } else if from.contains(':')
                && !to.contains(':')
                && object_type != "*local.Object"
                && self.network_backend.is_some()
            {
                direction = "download";
                target = Some(format!(
                    "{}/{object}",
                    self.network_backend.as_deref()?.trim_end_matches('/')
                ));
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
    use super::{Parser, har_events};
    use serde_json::json;

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
