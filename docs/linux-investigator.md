# Linux investigator

The investigator is a separate Linux x86_64 case runner. The release bootstrap
downloads a prebuilt binary and checksum, verifies the archive, and starts
terminal setup. `--install-deps` installs missing capture tools through the
local package manager.
No Rust toolchain is needed on the investigated host. Release assets are
published from signed tags after the release workflow passes.

```bash
curl -fsSL https://raw.githubusercontent.com/iamb4uc/opsforge/main/investigate/install-and-run.sh -o /tmp/opsforge-investigate-bootstrap && bash /tmp/opsforge-investigate-bootstrap --install-deps --remove-bootstrap
```

The TUI selects exfiltration review, device timeline, downloads, deep file
inventory, and live capture by default. It shows the case output directory,
asks for a location change, accepts extra log paths, and accepts positive
capture durations such as `30s`, `5m`, `1h`, or `1d`. Use `--non-interactive`
with flags for a repeatable run. A root session skips `sudo`; otherwise the
runner validates cached `sudo` access or prompts once before case creation.
It stops if elevation fails.

## Repeatable configuration

Use `--config FILE` to load a JSON configuration. Omitted fields use the normal
defaults; unknown keys are rejected to catch spelling mistakes. Saved case
`config.json` files remain accepted. A capture duration can also be written as
`"5m"`; legacy `{ "seconds": 300, "label": "5m" }` values must agree.

```json
{
  "output_base": "/var/lib/opsforge/cases",
  "capture_duration": "5m",
  "deep_inventory": false,
  "imports": ["/mnt/evidence/proxy.log"]
}
```

```bash
opsforge-investigate --config case-config.json --dry-run
opsforge-investigate --config case-config.json --non-interactive
```

`--dry-run` prints validated settings without starting the TUI, requesting sudo,
or creating a case. `--output` and `--duration` override file settings. Repeated
`--import` paths are appended. The existing `--no-*` flags deselect sources.
Path ownership, source availability and capture tool checks still happen during
the actual run; dry run validates configuration only.

## Case files

Cases are created at `/var/lib/opsforge/cases/HOST-investigate-YYYYMMDD-HHMMSS/`
by default, or under a selected root-owned parent directory. Every ancestor of
the selected location must be root-owned and lack group or world write access;
this prevents an unprivileged process from redirecting root-owned case writes.
The cases contain:

- `raw/`: copied logs, browser databases and available journal files, command output, packet
  capture, and decoded packet text.
- `normalized/events.jsonl`: one event per line, written during collection.
- `normalized/coverage.jsonl`: source status and reason, including failures,
  empty sources, and unsupported formats. Statuses are `collected`, `empty`,
  `unavailable`, `denied`, `unsupported`, `failed`, `skipped` and `cancelled`.
  Missing tools/paths are unavailable; filesystem permission errors are denied.
  Collection interruptions reported by an I/O operation are cancelled; a killed
  process can still leave an incomplete case without a final status record.
- `normalized/file-inventory.jsonl`: path, size, and modification time when
  deep inventory is selected.
- `manifest.jsonl`: source path, copy time, byte count, and SHA-256 for each
  saved raw file.
- `case-info.json`, `completion.json`, and `checksums.sha256`: run identity,
  completion marker, and hashes of the finished case files. An interrupted
  case keeps saved evidence but has no completion marker.
- `findings.json`, `report.md`, `summary.txt`, and `dashboard/` with Overview,
  Uploads, Timeline, Downloads, Network, Applications, Coverage, and Evidence HTML pages.

The dashboard opens locally without a server or external assets. Its local
JavaScript data contains every normalized event; search, application/source/outcome
filters, UTC time ranges and pagination work across the complete case. Report
generation streams events to disk; the browser loads the full event dataset into
memory and renders only one page at a time. Large cases need enough browser memory.
Packet summaries are hidden initially in Timeline and remain available in Network
or with the timeline checkbox. Raw references show the original source path and
line number or HAR entry index. Keep the whole case directory when sharing it. The bootstrap
removes only its temporary files. It does not compress or remove the case.

## Sources and interpretation

The runner inventories active sockets and installed application lists, saves
the retained system journal and `/var/log` files, snapshots Firefox and
Chromium-family history, reads Chromium and Firefox download records, copies supplied
logs, and captures live packets on all interfaces. The live timer starts when
the case starts. Sources are saved and hashed as they are collected.

Applications displays current package-manager records and application-attributed
activity with the existing search, source, outcome and time filters. Package
records retain versions/states and raw line links. Their timestamp is collection
time, not installation time, and they do not establish execution or traffic.
XBPS labels keep the complete package-version identifier. Missing managers are
unavailable sources; an empty activity history does not prove no past traffic.

Generic text logs are normalized line by line. Keyword matches appear as
network leads; their original lines remain in `raw/`. Browser visits are
leads, and a browser visit does not prove upload. Current sockets are observed
at one point in time. Historical application attribution depends on retained
records with application names. Packet summaries do not identify an
application by themselves. Upload payloads and binary or compressed imported-log
formats are not decoded yet; coverage records these
limits. No malware verdict or exfiltration conclusion is generated from weak
signals, so `findings.json` can be empty.

## Upload and download records

The Uploads page separates completed file-transfer records, accepted HTTP
requests and failed/incomplete attempts. Counts are records, not unique files;
the same transfer can appear in both client and server logs. An inbound upload
to an investigated FTP/HTTP server is not an outbound exfiltration event.

Supported retained sources:

- Standard FTP `xferlog`: file path, transferred bytes, peer, logged identity,
  incoming/outgoing direction and completion indicator. The source is a server;
  local timestamps lack a timezone, and spaces in file names become underscores.
- OpenSSH SFTP server close records: filename and handle bytes read/written,
  interpreted from the server perspective. Reads are outbound download records;
  writes are inbound upload records. Counters can include repeated ranges and
  exclude wire overhead. A close log does not prove close success or whole-file
  completion, so normal records are observed and forced closes are interrupted.
  Zero-byte closes have no inferred transfer direction. Journal records retain
  their recorded timestamp and current UID-name mapping; plain syslog lines do
  not gain an invented year/timezone, peer or account. This needs existing
  SFTP transaction logging; ordinary SSH login logs do not retain file counters.
- rclone JSON logs: recorded object name and copy outcome. Direction and remote
  destination require retained command context plus a recognized network backend
  record. Copy/sync/move/copyto/moveto accept recognized global/command flags;
  single-file commands retain the explicitly named destination. Without command
  and backend context, with unknown flag arity, or during interleaved runs,
  direction stays unknown. A new run can be attributed after all observed runs
  have logged their terminal markers. Byte counts remain unknown unless logged per object.
  Named remotes alone are not assumed to be network destinations.
- HTTP combined and JSON access logs: PUT/POST/PATCH upload requests and GET
  download requests, target, time, user/peer when logged and response outcome.
  `request_length` includes headers; response bytes are not upload bytes. These
  formats generally do not retain the original local file name or payload.
- Imported `.har` archives: request URL/method/time, response outcome and uploaded
  `postData.params[].fileName` when retained. Each named file gets a record; request
  body bytes are not divided among files. Negative/missing sizes remain unknown.
  A HAR must already exist; ordinary browser history does not retain these fields.
- Chromium download metadata: local path, source URL when available and received
  bytes. Completion state is not inferred from matching byte counts.
- Firefox Places download annotations: latest recorded file URI and metadata for
  each source URL, including logged completion/failure/cancellation, file size and
  completion time when available. Repeated downloads to earlier destinations
  cannot be reconstructed from the latest annotation. Missing fields remain
  unknown; malformed metadata is preserved and reported without stopping other rows.

`/var/log` transfer logs are collected with system logs. rclone `.log`/`.jsonl`
files are also discovered under user `.cache/rclone`, `.local/state/rclone`,
`.local/share/rclone`, `.config/rclone/logs` (depth 3), `~/rclone.log` and
`~/.cache/rclone.log`. Other locations and HAR archives can be selected in the TUI
or passed with repeated `--import PATH`. No logging is enabled on the source device;
missing records remain explicit coverage gaps. Uploaded file contents are recovered
only when independently retained; a file name does not imply payload recovery.

Format references: [NGINX access logging](https://docs.nginx.com/nginx/admin-guide/monitoring/logging/),
[NGINX byte variables](https://nginx.org/en/docs/http/ngx_http_core_module.html),
[rclone JSON logging](https://rclone.org/docs/#use-json-log),
[Firefox download history](https://searchfox.org/firefox-main/source/toolkit/components/downloads/DownloadHistory.sys.mjs),
[vsftpd transfer logging](https://security.appspot.com/vsftpd/vsftpd_conf.html),
[HAR request metadata](https://w3c.github.io/web-performance/specs/HAR/Overview.html),
and [OpenSSH SFTP handle accounting](https://github.com/openssh/openssh-portable/blob/master/sftp-server.c).

## Application log discovery

The runner searches existing log locations beneath each distinct user home:
rclone, rsync, OpenSSH, FileZilla, AWS/Azure/gcloud CLI, Nextcloud, Syncthing,
Thunderbird, Evolution, Slack, Discord, Element, Signal, curl and wget. Discovery
uses a fixed location list, a depth limit of eight and log names such as `.log`,
`.log.*` and `.jsonl`. Custom paths and operator exports still need `--import`.
It does not enable logging or create missing history. A missing discovery path
does not establish whether the application was installed or used.

Text records retain application/user context from their discovery location.
The account label identifies the current discovery home, rather than an
unlogged transaction identity. A username explicitly retained in a transaction
record takes precedence over discovery context.
Unrecognized records remain leads, with their original lines and raw hashes.
AWS CLI `history.db` is copied with its available SQLite sidecars, then read from
an isolated working copy. Command/request IDs, event type, recorded time and
payload are retained. Matched S3 PutObject/UploadPart/CompleteMultipartUpload and
GetObject HTTP responses appear as upload/download request records. Successful
HTTP responses are labelled accepted, rather than full-file completion. A
unique prior request supplies the actual endpoint, including custom/local
endpoints; ambiguous targets stay unknown. Local filenames and file byte counts
are not inferred from stream representations or HTTP header lengths. An API call
alone has no transfer outcome. Unknown schemas and malformed rows remain visible
failures. The isolated working database gets an index for request correlation;
the retained raw database is unchanged.
Other application database schemas, mail/chat messages and attachment stores
are not decoded by this discovery slice. Compressed log files are retained but
are not decompressed yet. Log and history payloads can contain sensitive data.

Discovery roots that are symbolic links are skipped explicitly; import their
trusted targets to collect them. Credential/configuration files are outside
the log-name search. Live SQLite copies retain the same consistency limitation
as browser collection.

AWS history format: [CLI history reference](https://docs.aws.amazon.com/cli/latest/reference/history/),
[SQLite record implementation](https://github.com/aws/aws-cli/blob/v2/awscli/customizations/history/db.py).

Browser collection preserves the database and any available SQLite WAL,
shared-memory, and rollback journal files. Parsing uses a separate working copy
under `normalized/`, so an open browser's exclusive database lock cannot stall
collection or change the retained originals. SQLite checks the working copy
before parsing; unreadable or inconsistent copies appear as failed sources.
These live file copies are not an atomic snapshot. A browser changing its files
during acquisition can leave gaps; acquisition coverage records this limit.
System accounts whose home is `/` do not trigger a second device-wide browser
scan or attribute other users' profiles to a service account.

Deep inventory excludes volatile `/proc`, `/sys`, `/dev`, and `/run` trees and
the case directory itself. Raw browser databases and packet captures can
contain private data. Share only with the intended case reviewers.
