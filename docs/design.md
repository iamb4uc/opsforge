# Design

opsforge favors platform scripts that can run on constrained incident-response
hosts without installing a language runtime. The Linux investigator runner is
a prebuilt Rust binary for guided collection and offline reporting; it does not
require Rust on the investigated host.

The approved direction makes Rust the shared Linux/Windows orchestrator and
keeps Bash and PowerShell as native, independently usable checks. Rust owns
configuration, subprocess lifecycle, case preservation, normalization,
verification, and reports. Established optional tools provide disk and memory
acquisition and analysis. This is the target architecture, not a claim that
Windows investigator support or forensic adapters have shipped.

See [the implementation roadmap](investigator-roadmap.md) for delivery order,
compatibility boundaries, and acceptance gates.

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
