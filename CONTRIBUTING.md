# Contributing

opsforge accepts shell-only defensive operations scripts.

## Scope

opsforge is a defensive SOC, NOC, incident response, and administration toolkit.
Contributions should solve real operational problems and produce usable
evidence, findings, reports, or baselines.

## Language Rules

- Use Bash for Linux-specific scripts.
- Use POSIX `sh` only when portability is realistic.
- Use PowerShell for Windows scripts.
- Do not add Python, Go, Rust, Node.js, Ruby, Perl, compiled helpers, or
  undocumented helper binaries for core functionality.

## Safety Rules

- Scripts must be read-only by default.
- Do not add exploit automation, credential theft logic, persistence creation,
  AV/EDR bypass, destructive behavior, or automatic privilege escalation.
- Any modifying behavior must require an explicit apply flag and clear help text.
- Do not add beginner recon wrappers or noisy toy scripts.

## Script Requirements

New scripts must include:

- help output
- safe defaults
- structured output
- timestamped output directories
- metadata following `docs/script-metadata.md`
- docs or catalog updates
- tests or fixture coverage

Do not add new scripts without updating `docs/script-catalog.md` and CI checks.

## Quality

- Quote shell variables and keep scripts ShellCheck-friendly.
- Prefer built-in PowerShell cmdlets on Windows.
- Document optional external dependencies in script help.
- Use the standard finding schema from `docs/output-format.md`.
- Reports should follow `docs/report-standard.md`.
- Compatibility expectations are tracked in `docs/compatibility.md`.
