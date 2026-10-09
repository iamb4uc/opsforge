# Linux workflow implementation and validation ledger

This tracks the approved complete Linux workflow. A row is complete only when
its implementation and successful, empty and failure scenarios have evidence.
Existing release observations do not prove a new row passed.

Implementation order: exfiltration, device timeline, downloads/file investigation,
unified operational checks, acquisition, memory analysis, complete release gates.
Optimization follows those gates. Windows tools keep their existing checks;
the Windows investigator is a later expansion.

## Workflow

- Keep the existing Rust investigator and Bash/PowerShell tools. The operator
  explicitly authorized the Rust TUI and optional external forensic tools.
- Launch one checksum-verified release with a download-and-run command and TUI.
  Embed Linux shell assets and stage them in a private root-owned directory.
- Add `--config FILE` and `--dry-run`, retaining existing CLI options and older
  configuration defaults. Acquisition and module loading require selection.
- Default output parent: `/var/lib/opsforge/cases`; prompt for the destination.
  A disk-image destination must be on storage separate from the source.
- Capture defaults to `5m`, starting at recorded capture start; accept positive
  integer `s/m/h/d` durations. Save raw evidence and normalized JSONL incrementally.
- Record root/sudo checks, dependency installations, commands, versions,
  timestamps, tool-created activity, results, source coverage and hashes.
- Preserve partial cases on failure/interruption. Remove temporary tools and
  only the kernel module loaded by this run. Preserve the case directory.
- Show collected, empty, unavailable, denied, unsupported, failed, skipped and
  cancelled sources separately. A finished case is not a clean-device verdict.

## Capabilities

| ID | Source or behavior | Required evidence | Status |
|---|---|---|---|
| EX-01 | Chromium-family and Firefox history/downloads | live/WAL, multiple users, normal/Flatpak/Snap paths, source records | pending |
| EX-02 | HAR, FTP xferlog and HTTP access records | correct client/server direction, outcome and byte basis | pending |
| EX-03 | rclone | copy/sync/move/copyto/moveto, flags, consecutive/interleaved runs, unknown context | pending |
| EX-04 | rsync, OpenSSH/SFTP and FileZilla retained transfers | explicit transaction records; history/connection leads labelled separately | pending |
| EX-05 | AWS/Azure/Google Cloud CLI retained history/logs | command intent vs actual API/transfer result; source locations | pending |
| EX-06 | Nextcloud and Syncthing retained activity | local/remote perspective, failed operations, absent logging | pending |
| EX-07 | email/chat applications and exports | artifact discovery/preservation, attachment metadata, encrypted/unsupported gaps | pending |
| EX-08 | DNS/VPN/proxy/firewall/container activity | retained logs, workload identity and source limits | pending |
| EX-09 | live traffic and socket ownership | timing, connection tuples, process identity and explicit unattributed records | pending |
| TL-01 | journal, auth/audit/session records, shell/package activity | original timestamp, UTC conversion/assumptions, source provenance | pending |
| TL-02 | rotated/compressed logs and filesystem timestamps | malformed/truncated streams, ambiguous years/timezones, metadata semantics | pending |
| DL-01 | referenced and recovered files | preserved content when available, type/size/SHA-256, source and timeline links | pending |
| OP-01 | all 15 existing Linux operational scripts | safe success/empty/denied/failed cases, output-contract validation | pending |
| OP-02 | target/baseline-dependent checks | explicit targets/configs; baseline comparison or selected creation | pending |
| AQ-01 | ddrescue disk/partition imaging | device identity, timestamps, mapfile, unreadable ranges and hashes | pending |
| AQ-02 | live disk imaging | explicit acceptance, changing-source label, separate-storage enforcement | pending |
| AQ-03 | image analysis and deleted-file recovery | ext4/FAT32/exFAT/NTFS metadata recovery, XFS/Btrfs carving limits, offsets | pending |
| AQ-04 | AVML RAM acquisition | supported and kernel-blocked paths, source/format/version/hash | pending |
| AQ-05 | LiME supplied/build module | matching headers/vermagic/signing, selected load, failure and owned-module cleanup | pending |
| MA-01 | Volatility analysis | matching symbols, processes/tree/modules/network/history/suspicious regions, raw results | pending |
| UI-01 | grouped TUI and unattended configuration | selection, required inputs, validation, cancel, progress and compatibility | pending |
| UI-02 | offline dashboard | existing pages plus Applications/Checks/Acquisition/Memory, graphs and original evidence links | pending |
| RT-01 | private output and trusted elevated code | symlink/path attacks, no overwrite, no untrusted shell code, no execution of evidence | pending |
| RT-02 | partial-case handling | failed child, interruption, full disk, readable incomplete status | pending |

## Dependency pins

- AVML: `v0.20.0`, x86_64 `avml-minimal`, SHA-256
  `79094391156f778db695cde0f84c36c3ad16987b51d80ea02f4a2ffe703b9f47`.
  Source: <https://github.com/microsoft/avml/releases/tag/v0.20.0>.
- LiME: `7511bffe797df9d87ae4db853ef123745cc5bc2c`.
  Source: <https://github.com/jtsylve/LiME>.
- Volatility 3: `v2.28.2`, optional external Python dependency and matching symbols.
  Source: <https://github.com/volatilityfoundation/volatility3/releases/tag/v2.28.2>.
- GNU ddrescue, Sleuth Kit and PhotoRec: platform packages; record the actual
  package versions and tool versions in each case and validation run.

## Release gates

| Platform | Required validation | Status |
|---|---|---|
| Ubuntu 24.04 and 26.04 | reproducible checks and full VM workflow | pending |
| Debian 13 | reproducible checks and full VM workflow | pending |
| AlmaLinux 9 and 10 | reproducible checks and full VM workflow | pending |
| Arch | pinned snapshot and full VM workflow | pending |
| Void glibc and musl | pinned snapshots, runit, full VM workflow | pending |
| Alpine 3.24 | reproducible checks, OpenRC, full VM workflow | pending |
| Windows existing tools | PowerShell 5.1, pwsh, Pester and existing runtime checks | pending |
| TUI/dashboard | actual terminal and browser, desktop/mobile, all generated pages | pending |
| Published artifact | download/hash verification, complete case, cleanup and reports | pending |

Keep synthetic validation evidence outside Git and link its retained location
from the work journal. Each release gate must record image/kernel/package
versions. Containers do not prove kernel, service or acquisition behavior.

Deliver atomic signed commits and separate reviewed PRs. Complete Linux/Windows
CI blocks merge; complete workflow validation blocks the signed release. Record
each meaningful slice in the project note and dated work journal.

Limits are evidence: absent history, overwritten/TRIMmed data, encryption and
kernel security can prevent recovery. Metadata/hashes are the selected file
analysis scope; no file execution or signature scanning is part of this work.
