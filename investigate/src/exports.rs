use crate::case::{Case, Coverage, CoverageState, Event, EvidenceLevel};
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

pub(crate) fn docker_logs(
    case: &mut Case,
    raw: &Path,
    name: &str,
    original: &Path,
) -> Result<Option<u64>> {
    let filename = original
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let cli = filename.strip_prefix("docker-log-").and_then(|value| {
        let (id, stream) = if let Some(id) = value.strip_suffix(".stderr.txt") {
            (id, "CLI stderr capture")
        } else {
            (value.strip_suffix(".txt")?, "CLI stdout capture")
        };
        crate::collect::container_id(id).then_some((id, stream))
    });
    let exported_id = filename
        .strip_suffix("-json.log")
        .filter(|id| crate::collect::container_id(id));
    let mut lines = BufReader::new(File::open(raw)?).lines().peekable();
    let envelope = if cli.is_none() && exported_id.is_none() {
        match lines.peek() {
            Some(Ok(line)) => serde_json::from_str::<Value>(line).ok().is_some_and(|row| {
                row.get("log").is_some() && row.get("stream").is_some() && row.get("time").is_some()
            }),
            Some(Err(_)) => return Err(lines.next().unwrap().unwrap_err().into()),
            None => false,
        }
    } else {
        true
    };
    if cli.is_none() && !envelope {
        return Ok(None);
    }
    let evidence = format!("raw/{name}");
    let mut count = 0;
    for (index, line) in lines.enumerate() {
        crate::runtime::check_cancelled()?;
        let line = line?;
        let line_number = index as u64 + 1;
        let (time, stream, body_length, id) = if let Some((id, stream)) = cli {
            let Some((time, body)) = line.split_once(' ') else {
                gap(
                    case,
                    &evidence,
                    &format!("line-{line_number}"),
                    "Docker CLI diagnostic or unsupported line; retained raw, not a container event",
                )?;
                continue;
            };
            if time.parse::<jiff::Timestamp>().is_err() {
                gap(
                    case,
                    &evidence,
                    &format!("line-{line_number}"),
                    "Docker CLI diagnostic or invalid timestamp; retained raw, not a container event",
                )?;
                continue;
            }
            (time.to_owned(), stream.to_owned(), body.len(), Some(id))
        } else {
            let row: Value = match serde_json::from_str(&line) {
                Ok(row) => row,
                Err(_) => {
                    gap(
                        case,
                        &evidence,
                        &format!("line-{line_number}"),
                        "invalid Docker JSON envelope; line retained raw",
                    )?;
                    continue;
                }
            };
            let (Some(time), Some(stream), Some(body)) = (
                row["time"].as_str(),
                row["stream"].as_str(),
                row["log"].as_str(),
            ) else {
                gap(
                    case,
                    &evidence,
                    &format!("line-{line_number}"),
                    "unsupported Docker JSON envelope fields; line retained raw",
                )?;
                continue;
            };
            if !matches!(stream, "stdout" | "stderr") {
                gap(
                    case,
                    &evidence,
                    &format!("line-{line_number}"),
                    "unknown Docker JSON stream; line retained raw",
                )?;
                continue;
            }
            (time.to_owned(), stream.to_owned(), body.len(), exported_id)
        };
        let timestamp = time
            .parse::<jiff::Timestamp>()
            .ok()
            .map(|value| value.to_string());
        if timestamp.is_none() {
            gap(
                case,
                &evidence,
                &format!("line-{line_number}"),
                "invalid Docker runtime time; event time stays unknown",
            )?;
        }
        case.event(&Event {
            timestamp, source: "docker-log".into(), kind: "container-log-reference".into(),
            application: Some("Docker (runtime log; application unknown)".into()),
            user: None, destination: None,
            detail: format!("{}\nRuntime log reference only. Body stays in raw evidence; its UTF-8 byte length is log text, not file/network bytes. Runtime time does not establish when an application action occurred. Container ID from filename is an unverified source label, not workload/process/user ownership. CLI stdout/stderr may include diagnostics or merged TTY streams; envelope stream is a runtime-reported label. No inbound/outbound activity, transfer, destination or application identity is inferred. Retention/rotation may omit history; embedded bodies are not recursively decoded.", json!({"container_source_label":id,"runtime_time":time,"stream_label":stream,"log_text_utf8_bytes":body_length})),
            evidence: evidence.clone(), level: EvidenceLevel::Recorded, transfer: None,
            evidence_line: Some(line_number),
        })?;
        count += 1;
    }
    Ok(Some(count))
}

pub(crate) fn openvpn_status(case: &mut Case, raw: &Path, name: &str) -> Result<Option<u64>> {
    let mut lines = BufReader::new(File::open(raw)?).lines();
    let Some(first) = lines.next().transpose()? else {
        return Ok(None);
    };
    let version_one = first == "OpenVPN CLIENT LIST";
    let separator = if first.starts_with("TITLE\tOpenVPN ") {
        '\t'
    } else {
        ','
    };
    if !version_one && !first.starts_with("TITLE,OpenVPN ") && !first.starts_with("TITLE\tOpenVPN ")
    {
        return Ok(None);
    }
    let evidence = format!("raw/{name}");
    let mut timestamp = None;
    let mut headers: Vec<String> = Vec::new();
    let mut active = false;
    let mut ended = false;
    let mut count = 0;
    for (index, line) in lines.enumerate() {
        crate::runtime::check_cancelled()?;
        let line = line?;
        let line_number = index as u64 + 2;
        if line == "END" {
            ended = true;
            active = false;
            continue;
        }
        if line == "ROUTING TABLE" {
            active = false;
            continue;
        }
        let fields: Vec<_> = line.split(separator).collect();
        if !version_one && fields.first() == Some(&"TIME") {
            timestamp = fields
                .get(2)
                .filter(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|value| value.parse::<i64>().ok())
                .and_then(|value| jiff::Timestamp::from_second(value).ok())
                .map(|value| value.to_string());
            if timestamp.is_none() {
                gap(
                    case,
                    &evidence,
                    &format!("line-{line_number}"),
                    "invalid OpenVPN status UNIX snapshot time; local text time is not substituted",
                )?;
            }
            continue;
        }
        let header = if fields.first() == Some(&"HEADER") && fields.get(1) == Some(&"CLIENT_LIST") {
            Some(&fields[2..])
        } else if version_one && fields.first() == Some(&"Common Name") {
            Some(fields.as_slice())
        } else {
            None
        };
        if let Some(header) = header {
            headers = header.iter().map(|value| (*value).to_owned()).collect();
            let unique: std::collections::BTreeSet<_> = headers.iter().collect();
            active = [
                "Common Name",
                "Real Address",
                "Bytes Received",
                "Bytes Sent",
                "Connected Since",
            ]
            .iter()
            .all(|required| headers.iter().any(|header| header == required))
                && unique.len() == headers.len();
            if !active {
                gap(
                    case,
                    &evidence,
                    &format!("line-{line_number}"),
                    "unsupported OpenVPN client status header; required or unique columns missing",
                )?;
            }
            continue;
        }
        let row = if !version_one && fields.first() == Some(&"CLIENT_LIST") {
            Some(&fields[1..])
        } else if version_one && active {
            Some(fields.as_slice())
        } else {
            None
        };
        let Some(row) = row else { continue };
        if !active || row.len() != headers.len() {
            gap(
                case,
                &evidence,
                &format!("line-{line_number}"),
                "unsupported OpenVPN client row; missing header or field count mismatch, ambiguous delimiters remain raw",
            )?;
            continue;
        }
        let metadata: BTreeMap<_, _> = headers
            .iter()
            .map(String::as_str)
            .zip(row.iter().copied())
            .collect();
        let counter = |field| {
            metadata
                .get(field)
                .filter(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|value| value.parse::<u64>().ok())
        };
        let received = counter("Bytes Received");
        let sent = counter("Bytes Sent");
        if received.is_none() || sent.is_none() {
            gap(
                case,
                &evidence,
                &format!("line-{line_number}"),
                "invalid OpenVPN cumulative counters; values remain raw metadata, not zero or estimated bytes",
            )?;
        }
        case.event(&Event {
            timestamp: timestamp.clone(), source: "openvpn-status".into(), kind: "vpn-session-snapshot".into(),
            application: Some("OpenVPN (server status)".into()), user: None, destination: None,
            detail: format!("{}\nServer-reported session snapshot. Receive/send counters are cumulative OpenVPN link counters from the server perspective, not file sizes, file payload, complete wire-frame bytes or exfiltration totals. Do not sum repeated snapshots or infer transfers, client processes or verified identities from common-name/username labels. Snapshot time comes only from retained UNIX TIME; offsetless Updated/Connected Since text remains source-local metadata. Status files may be overwritten and do not reconstruct missing history.", serde_json::json!({"source_fields":metadata,"received_link_bytes":received,"sent_link_bytes":sent})),
            evidence: evidence.clone(), level: EvidenceLevel::Recorded, transfer: None, evidence_line: Some(line_number),
        })?;
        count += 1;
    }
    if !ended {
        gap(
            case,
            &evidence,
            "end",
            "OpenVPN status END marker missing; retained rows are an incomplete snapshot",
        )?;
    }
    if headers.is_empty() {
        gap(
            case,
            &evidence,
            "header",
            "OpenVPN status client header missing; no client rows decoded",
        )?;
    }
    Ok(Some(count))
}

pub(crate) fn slack(
    case: &mut Case,
    raw: &Path,
    name: &str,
    original: &Path,
) -> Result<Option<u64>> {
    let Some(date) = original.file_stem().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    if original.extension().is_none_or(|ext| ext != "json")
        || date.parse::<jiff::civil::Date>().is_err()
        || !original.ancestors().skip(2).take(2).any(|root| {
            regular(&root.join("channels.json"))
                && (regular(&root.join("users.json")) || regular(&root.join("org_users.json")))
        })
    {
        return Ok(None);
    }
    let document: Value = serde_json::from_reader(BufReader::new(File::open(raw)?))?;
    let rows = document.as_array().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported Slack daily export: expected an array",
        )
    })?;
    let evidence = format!("raw/{name}");
    let conversation = original
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str());
    let mut count = 0;
    for (index, row) in rows.iter().enumerate() {
        crate::runtime::check_cancelled()?;
        let pointer = format!("/{index}");
        if row["type"].as_str() != Some("message") {
            gap(
                case,
                &evidence,
                &pointer,
                "unsupported non-message export record",
            )?;
            continue;
        }
        let timestamp = row["ts"].as_str().and_then(slack_time);
        if timestamp.is_none() {
            gap(
                case,
                &evidence,
                &pointer,
                "missing or invalid UNIX message timestamp; date filename is not substituted",
            )?;
        }
        let detail = json!({
            "json_pointer": pointer,
            "source_path": original.display().to_string(),
            "conversation_folder": conversation,
            "channel_id": row.get("channel"),
            "user_id": row.get("user"),
            "bot_id": row.get("bot_id"),
            "subtype": row.get("subtype"),
            "ts": row.get("ts"),
            "original_ts": row.get("original_ts"),
            "thread_ts": row.get("thread_ts"),
            "edited": row.get("edited"),
            "editor_id": row.get("editor_id"),
        });
        let event = Event {
            timestamp,
            source: "slack-export".into(),
            kind: "chat-message-reference".into(),
            application: Some("Slack".into()),
            user: None,
            destination: None,
            detail: format!(
                "Exported message metadata: {detail}. Source IDs are not verified identities; the folder is an export label, not a network destination. Edited/deleted records retain their own event time; original text and prior versions remain raw. Export authenticity, receipt and device activity are not established."
            ),
            evidence: evidence.clone(),
            level: EvidenceLevel::Recorded,
            transfer: None,
            evidence_line: None,
        };
        case.event(&event)?;
        count += 1;
        for field in ["message", "previous", "attachments"] {
            if row.get(field).is_some() {
                gap(
                    case,
                    &evidence,
                    &format!("{pointer}/{field}"),
                    "nested message/prior content or rich attachments remain raw; nested file references are not decoded",
                )?;
            }
        }
        let Some(files) = row.get("files") else {
            continue;
        };
        let Some(files) = files.as_array() else {
            gap(
                case,
                &evidence,
                &format!("{pointer}/files"),
                "unsupported file-reference list",
            )?;
            continue;
        };
        for (file_index, file) in files.iter().enumerate() {
            crate::runtime::check_cancelled()?;
            let file_pointer = format!("{pointer}/files/{file_index}");
            if !file.is_object() || file["id"].as_str().is_none() {
                gap(
                    case,
                    &evidence,
                    &file_pointer,
                    "unsupported file reference without a string ID",
                )?;
                continue;
            }
            let mut reference = event.clone();
            reference.kind = "chat-file-reference".into();
            let metadata = json!({
                "json_pointer": file_pointer,
                "file_id": file.get("id"),
                "name": file.get("name"),
                "title": file.get("title"),
                "mimetype": file.get("mimetype"),
                "size": file.get("size"),
                "mode": file.get("mode"),
                "is_external": file.get("is_external"),
                "external_type": file.get("external_type"),
                "file_access": file.get("file_access"),
                "created": file.get("created"),
                "timestamp": file.get("timestamp"),
            });
            reference.detail = format!(
                "Exported file reference: {metadata}. Message context: {detail}. File size/type/name are source metadata, not observed payload bytes or verified content. File creation time is distinct from the containing message time. A share/reference is not an upload, download or delivery result; external, deleted and inaccessible files may have no local payload. URLs remain in raw evidence and are never fetched. Export authenticity and identities are not verified."
            );
            case.event(&reference)?;
            count += 1;
        }
    }
    Ok(Some(count))
}

fn regular(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

pub(crate) fn element(
    case: &mut Case,
    raw: &Path,
    name: &str,
    original: &Path,
) -> Result<Option<u64>> {
    if original.extension().is_none_or(|ext| ext != "json") {
        return Ok(None);
    }
    let Ok(document) = serde_json::from_reader::<_, Value>(BufReader::new(File::open(raw)?)) else {
        return Ok(None);
    };
    if document.get("room_name").is_none() || document.get("exported_by").is_none() {
        return Ok(None);
    }
    let rows = document["messages"].as_array().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported Element export: messages array missing",
        )
    })?;
    let evidence = format!("raw/{name}");
    let mut count = 0;
    for (index, row) in rows.iter().enumerate() {
        crate::runtime::check_cancelled()?;
        let pointer = format!("/messages/{index}");
        let (Some(kind), Some(_)) = (row["type"].as_str(), row["content"].as_object()) else {
            gap(
                case,
                &evidence,
                &pointer,
                "unsupported Matrix event: type or content missing",
            )?;
            continue;
        };
        let timestamp = row["origin_server_ts"]
            .as_i64()
            .and_then(|time| jiff::Timestamp::from_millisecond(time).ok())
            .map(|time| time.to_string());
        if timestamp.is_none() {
            gap(
                case,
                &evidence,
                &pointer,
                "missing or invalid server UNIX-millisecond timestamp; export date and event age are not substituted",
            )?;
        }
        let content = &row["content"];
        let redaction = row
            .get("redacted_because")
            .filter(|value| value.is_object())
            .or_else(|| {
                row["unsigned"]
                    .get("redacted_because")
                    .filter(|value| value.is_object())
            });
        let context = json!({
            "json_pointer": pointer,
            "source_path": original.display().to_string(),
            "room_name": document.get("room_name"),
            "exported_by": document.get("exported_by"),
            "event_id": row.get("event_id"),
            "room_id": row.get("room_id"),
            "sender_id": row.get("sender"),
            "event_type": kind,
            "origin_server_ts": row.get("origin_server_ts"),
            "redacted": redaction.is_some(),
            "redaction_event_id": redaction.and_then(|value| value.get("event_id")),
            "msgtype": content.get("msgtype"),
            "relation_type": content["m.relates_to"].get("rel_type"),
            "related_event_id": content["m.relates_to"].get("event_id"),
            "reply_event_id": content["m.relates_to"]["m.in_reply_to"].get("event_id"),
        });
        let event = Event {
            timestamp,
            source: "element-export".into(),
            kind: "chat-event-reference".into(),
            application: Some("Element/Matrix".into()),
            user: None,
            destination: None,
            detail: format!(
                "Exported Matrix event metadata: {context}. Time is the recorded homeserver event time, not local receipt or device activity. Source IDs/display labels and export authenticity are not verified. Bodies, prior content and ciphertext remain raw; room names/IDs are not network destinations."
            ),
            evidence: evidence.clone(),
            level: EvidenceLevel::Recorded,
            transfer: None,
            evidence_line: None,
        };
        case.event(&event)?;
        count += 1;
        if kind == "m.room.encrypted" {
            gap(
                case,
                &evidence,
                &format!("{pointer}/content"),
                "encrypted Matrix event content is not decoded; no key acquisition or decryption",
            )?;
            continue;
        }
        if content.get("m.new_content").is_some() {
            gap(
                case,
                &evidence,
                &format!("{pointer}/content/m.new_content"),
                "nested replacement content/file references remain raw and are not decoded",
            )?;
        }
        if kind != "m.room.message"
            || !matches!(
                content["msgtype"].as_str(),
                Some("m.file" | "m.image" | "m.audio" | "m.video")
            )
        {
            continue;
        }
        let descriptor = content.get("file");
        let uri = descriptor
            .and_then(|file| file.get("url"))
            .or_else(|| content.get("url"))
            .and_then(Value::as_str)
            .filter(|uri| {
                uri.strip_prefix("mxc://")
                    .and_then(|value| value.split_once('/'))
                    .is_some_and(|(server, media)| {
                        !server.is_empty() && !media.is_empty() && !uri.contains(['?', '#'])
                    })
            });
        if uri.is_none() {
            gap(
                case,
                &evidence,
                &format!("{pointer}/content"),
                "missing or invalid Matrix media URI; file metadata retained without fetching",
            )?;
        }
        if descriptor.is_some() {
            gap(
                case,
                &evidence,
                &format!("{pointer}/content/file"),
                "encrypted attachment descriptor retained as metadata; keys omitted, ciphertext hash not verified, payload not decrypted",
            )?;
        }
        let metadata = json!({
            "filename": content.get("filename"),
            "body_label": content.get("body"),
            "mxc_uri": uri,
            "size": content["info"].get("size"),
            "mimetype": content["info"].get("mimetype"),
            "width": content["info"].get("w"),
            "height": content["info"].get("h"),
            "duration": content["info"].get("duration"),
            "encrypted_descriptor_present": descriptor.is_some(),
            "descriptor_version": descriptor.and_then(|file| file.get("v")),
            "recorded_ciphertext_sha256": descriptor.and_then(|file| file["hashes"].get("sha256")),
        });
        let mut reference = event;
        reference.kind = "chat-file-reference".into();
        reference.detail = format!(
            "Exported Matrix file reference: {metadata}. Event context: {context}. Size/type/dimensions/duration are source metadata, not observed payload bytes or verified content. Body may be a caption; an absent filename remains unknown. A message/media URI does not establish an upload, download, receipt or local payload. Encrypted descriptors are not decrypted, keys stay raw and recorded hashes are not computed hashes. Media and thumbnail URLs are never fetched."
        );
        case.event(&reference)?;
        count += 1;
    }
    Ok(Some(count))
}

fn gap(case: &mut Case, evidence: &str, pointer: &str, detail: &str) -> Result<()> {
    case.coverage(&Coverage {
        source: format!("{evidence}#{pointer}"),
        state: CoverageState::Unsupported,
        detail: detail.into(),
    })
}

fn slack_time(value: &str) -> Option<String> {
    let (seconds, fraction) = value.split_once('.')?;
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_empty()
        || fraction.len() > 9
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let nanoseconds =
        fraction.parse::<i32>().ok()? * 10_i32.pow(9 - u32::try_from(fraction.len()).ok()?);
    jiff::Timestamp::new(seconds.parse().ok()?, nanoseconds)
        .ok()
        .map(|time| time.to_string())
}
