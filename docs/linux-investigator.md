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

## Case files

Cases are created at `/var/lib/opsforge/cases/HOST-investigate-YYYYMMDD-HHMMSS/`
by default, or under a selected root-owned parent directory. Every ancestor of
the selected location must be root-owned and lack group or world write access;
this prevents an unprivileged process from redirecting root-owned case writes.
The cases contain:

- `raw/`: copied logs, browser database snapshots, command output, packet
  capture, and decoded packet text.
- `normalized/events.jsonl`: one event per line, written during collection.
- `normalized/coverage.jsonl`: source status and reason, including failures,
  empty sources, and unsupported formats.
- `normalized/file-inventory.jsonl`: path, size, and modification time when
  deep inventory is selected.
- `manifest.jsonl`: source path, copy time, byte count, and SHA-256 for each
  saved raw file.
- `case-info.json`, `completion.json`, and `checksums.sha256`: run identity,
  completion marker, and hashes of the finished case files. An interrupted
  case keeps saved evidence but has no completion marker.
- `findings.json`, `report.md`, `summary.txt`, and `dashboard/` with Overview,
  Exfiltration, Timeline, Downloads, and Coverage HTML pages.

The dashboard opens locally without a server. It shows a bounded sample of
events so large journals do not exhaust report memory; JSONL retains every
normalized row. Keep the whole case directory when sharing it. The bootstrap
removes only its temporary files. It does not compress or remove the case.

## Sources and interpretation

The runner inventories active sockets and installed application lists, saves
the retained system journal and `/var/log` files, snapshots Firefox and
Chromium-family history, reads Chromium download records, copies supplied
logs, and captures live packets on all interfaces. The live timer starts when
the case starts. Sources are saved and hashed as they are collected.

Generic text logs are normalized line by line. Keyword matches appear as
network leads; their original lines remain in `raw/`. Browser visits are
leads, and a browser visit does not prove upload. Current sockets are observed
at one point in time. Historical application attribution depends on retained
records with application names. Packet summaries do not identify an
application by themselves. Firefox downloads, upload payloads, and binary or
compressed imported-log formats are not decoded yet; coverage records these
limits. No malware verdict or exfiltration conclusion is generated from weak
signals, so `findings.json` can be empty.

Deep inventory excludes volatile `/proc`, `/sys`, `/dev`, and `/run` trees and
the case directory itself. Raw browser databases and packet captures can
contain private data. Share only with the intended case reviewers.
