# Contributing

opsforge-shell accepts shell-only defensive operations scripts.

## Rules

- Use Bash for Linux-specific scripts and POSIX sh only when portability is realistic.
- Use PowerShell for Windows scripts.
- Do not add Python, Go, Rust, Node.js, Ruby, compiled helpers, or undocumented helper binaries.
- Keep scripts read-only by default.
- Every major script must support help output and timestamped output folders.
- Produce operational evidence: raw data, normalized findings, a Markdown report, and a summary.
- Avoid offensive exploit automation and beginner recon wrappers.

## Quality

- Quote shell variables and keep scripts ShellCheck-friendly.
- Prefer built-in PowerShell cmdlets on Windows.
- Document optional external dependencies in script help.
- Use the standard finding schema from `docs/output-format.md`.
