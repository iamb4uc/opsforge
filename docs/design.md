# Design

opsforge is intentionally shell-only. The toolkit favors scripts that can
run on constrained incident-response hosts without installing a language runtime.

## Principles

- Collect first, decide second: scripts preserve raw evidence before summarizing.
- Read-only by default: destructive cleanup or remediation requires an explicit flag.
- Structured output: every major script writes JSON findings and Markdown reports.
- Platform-native dependencies: Bash and standard Unix tools on Linux, PowerShell
  cmdlets on Windows.
- Defensive scope: detection, auditing, collection, drift monitoring, and reporting.

## Layout

- `bin/` contains dispatch wrappers.
- `lib/` contains shared shell and PowerShell helpers.
- `scripts/linux/` and `scripts/windows/` contain operational tools by domain.
- `configs/` contains target lists and examples.
- `output/` is ignored except for `.gitkeep`.
