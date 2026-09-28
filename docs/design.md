# Design

opsforge favors platform scripts that can run on constrained incident-response
hosts without installing a language runtime. The Linux investigator runner is
a prebuilt Rust binary for guided collection and offline reporting; it does not
require Rust on the investigated host.

## Principles

- Collect first, decide second: scripts preserve raw evidence before summarizing.
- Read-only by default: destructive cleanup or remediation requires an explicit flag.
- Structured output: every major script writes JSON findings and Markdown reports.
- Platform-native dependencies: Bash and standard Unix tools on Linux, PowerShell
  cmdlets on Windows.
- Defensive scope: detection, auditing, collection, drift monitoring, and reporting.

## Layout

- `bin/` contains dispatch wrappers.
- `investigate/` contains the Linux guided collector and report generator.
- `lib/` contains shared shell and PowerShell helpers.
- `scripts/linux/` and `scripts/windows/` contain operational tools by domain.
- `configs/` contains target lists and examples.
- `output/` is ignored except for `.gitkeep`.
