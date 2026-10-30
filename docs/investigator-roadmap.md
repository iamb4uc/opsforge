# Linux and Windows investigator implementation

Approved scope: Rust is the core orchestrator; Bash and PowerShell remain native
checks. Include current collection capabilities, saved-case review, disk imaging,
deleted-file recovery, RAM acquisition, and memory analysis on both platforms.
This file records implementation work, not a support claim.

## Delivery ledger

| Slice | Implementation | Validation |
|---|---|---|
| Policy and architecture alignment | documentation updated | diff reviewed |
| Portable case/runtime foundation | pending | pending |
| Saved-case verification and rebuilding | pending | pending |
| Windows collection and check parity | pending | pending |
| Disk acquisition and recovery | pending | pending |
| Memory acquisition and analysis | pending | pending |
| Cross-platform release and bootstraps | pending | pending |

The functional changes remain pending. Record test evidence before advancing a
status; documentation changes do not establish runtime support.

## Shared workflow and compatibility

Provide Collect, Review saved case, Acquire disk or memory, and Analyse acquired
images in the TUI and unattended CLI. Preserve existing flat collection flags,
Linux check names, saved configurations, standalone wrappers, and findings.

Planned command interfaces (not yet implemented):

```text
opsforge-investigate collect [existing options]
opsforge-investigate verify CASE [--json]
opsforge-investigate rebuild CASE --output DIRECTORY --mode bundle|linked
opsforge-investigate acquire disk --config FILE --execute
opsforge-investigate acquire memory --config FILE --execute
opsforge-investigate analyze disk --config FILE
opsforge-investigate analyze memory --config FILE
```

Dry-run validates configuration without acquisition, elevation, driver loading,
or dependency installation. Add format/platform metadata without rewriting old
cases; use portable internal artifact names and retain original source paths.

Verification compares raw sizes/hashes against the manifest and other retained
files against checksums. Distinguish source issues from generated-report issues.
Exit 0 means recorded integrity matches, 1 means discrepancies/unverified data,
and 2 means evaluation could not run. Hashes do not prove authenticity.

Rebuild only from normalized records. Missing or changed generated reports are
repairable; missing/changed required source data and malformed JSONL block a
rebuild. Missing final checksums require explicit `--allow-unverified`, with an
unverified banner; this never bypasses known mismatches. Preserve acquisition
completion state and record rebuilding provenance separately.

Default bundle mode uses independent copies, never hardlinks, and works after
relocation. Linked mode snapshots analysis inputs but uses relative raw links;
require the source case to remain available. Reject impossible relative links
across Windows volumes and offer bundle mode. Refuse output overwrite, source
overlap, traversal, links/reparse points, special files, and ambiguous manifests.
Never render into or rehash the source case.

## Platform work

Isolate native discovery, elevation, private directories, and child cancellation
from shared parsers/reporting. Windows requires private ACLs and owned child-tree
cleanup; saved-case commands never enter collection or request elevation.

Windows must cover browser profiles (Chromium/Edge/Firefox), existing application
and transfer formats, EVTX and structured Event Logs, PowerShell activity,
TCP/UDP owners, software inventory, retained DNS/VPN/proxy/firewall records,
explicit local Docker, fixed-volume inventory, and timed Pktmon capture.
Preserve ETL, converted PCAPNG and summaries. Never disturb an unrelated capture.
Skip reparse points and automatic network-share traversal. All existing imported
formats must remain readable on either platform.

Reuse existing Windows checks. Add disk-pressure, TLS, process-tree,
privileged-object drift, Windows OpenSSH, config/registry drift, network-path,
log-source silence, web triage (IIS/Apache/nginx), and missing-process-image
review. Linux SUID and deleted-open-file semantics are not Windows semantics;
document native counterparts without changing legacy check meanings.

Every requested capability needs actual implementation; an unsupported stub is
not parity. Missing telemetry, denied access, unsupported source formats and
changing database snapshots remain explicit coverage limitations.

## Forensic backends

| Capability | Backend |
|---|---|
| Linux disk | ddrescue, raw image and mapfile |
| Windows disk | native libewf ewfacquire and ewfverify, E01 segments |
| Metadata recovery | Sleuth Kit, NTFS/FAT32/exFAT/ext4 |
| Carving | PhotoRec; ewfexport raw derivative for E01 inputs |
| Linux RAM | AVML or explicitly selected LiME module |
| Windows RAM | supplied WinPmem with trusted signed driver |
| Memory analysis | external Volatility 3 with supplied matching symbols |

Use existing dependency pins in linux-capabilities.md initially. Record actual
tool paths, versions, hashes, commands, exit states, raw results and provenance.
Do not auto-install tools, fetch symbols, or weaken host security. Validate
native Windows physical-device acquisition before claiming its availability.

Acquisition is opt-in. Record device identity/size/range; require separate
destination storage and refuse overwrite. Live disk capture needs explicit
acknowledgement and a changing-source label. Resume only with explicit selection
and matching device/image/mapfile identity. Keep partial artifacts on failure.
Clean up only drivers/modules/sessions started by the operation.

Recovered content goes into separate output with hashes and available offsets or
filesystem identifiers. XFS/Btrfs carving does not establish original paths or
timestamps. Memory analysis retains plugin results for processes, ancestry,
modules, network state, available history and suspicious-region leads. Missing
symbols/plugins are not empty findings. Add Acquisition, Recovered Files and
Memory report pages; subprocess success alone is not complete acquisition.

## Acceptance and release

Run Rust formatting, clippy, tests and builds on Linux and Windows; retain Linux
Docker/shell checks and PowerShell 5.1/7 plus Pester. Validate legacy config and
CLI behaviour, hostile paths/content, corrupt manifests, partial cases, source
immutability, both report modes, and cross-OS cases. Exercise TUI and every
offline page in real terminal/browser sessions.

Use disposable known-content disks and recovery fixtures, interrupted/resumed
images, known memory samples, incorrect symbols and blocked-driver scenarios.
Never acquire a user's real disk/RAM merely to validate the implementation.

Full VM gates include the existing Linux matrix and x64 Windows 10 22H2, Windows
11, Server 2022 and Server 2025. Hosted CI is not client-OS/acquisition evidence.
Unavailable targets remain pending and block the full compatibility claim.
Publish Linux tarballs and Windows ZIPs with checksums only after gates pass,
through signed commits, reviewed PRs and a signed release tag.

Deferred: raw-parser replay, cross-case correlation/comparison, annotations,
fleet management, automatic remediation and AI verdicts.
