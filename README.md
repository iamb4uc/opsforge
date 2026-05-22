# opsforge

opsforge is a shell-only toolkit for SOC, NOC, Linux, Windows, IR, and ops work.

It is built for the boring stuff that actually matters: triage, persistence checks, disk issues, timelines, network exposure, and reports you can use.

No fake polish. No random helper stack. No toy recon wrappers.

## Status

opsforge is beta. The scripts are useful, but they are still being tested across
real systems and CI runners.

The project stays shell-only:

- Linux and Unix scripts use Bash or POSIX sh where that makes sense.
- Windows scripts use PowerShell.
- Core tooling does not use Python, Go, Rust, Node.js, Ruby, Perl, or compiled
  helpers.
- Scripts are read-only by default unless a script clearly says otherwise and
  exposes an explicit action flag.

## What It Does

Current work focuses on:

- Linux and Windows host triage
- persistence checks
- deleted binary detection
- disk pressure notes
- TLS inventory
- firewall and network exposure checks
- event and log timelines
- output folders with raw evidence, findings, summaries, and reports

## Runtime Checks

CI runs selected tools on Linux and Windows runners.

Generated output is checked against the output contract after runtime execution.
Runtime artifacts are uploaded by CI and are not committed to the repo.

Fixture checks only prove the output contract parser. They are not proof that the
tools work. Runtime checks are what catch real script failures.

Linux:

```bash
./bin/test runtime-linux
```

Windows:

```powershell
.\bin\test.ps1 runtime
```

## Commands

Linux:

```bash
./bin/opsforge linux triage --output ./output --markdown --json
./bin/opsforge linux persistence --output ./output
./bin/opsforge linux deleted-binaries --output ./output
./bin/opsforge linux proc-tree --output ./output
./bin/opsforge linux suid --baseline --output ./output
./bin/opsforge linux suid --check --output ./output
./bin/opsforge linux priv-surface --output ./output
./bin/opsforge linux ssh-audit --output ./output
./bin/opsforge linux config-drift --baseline --output ./output
./bin/opsforge linux config-drift --check --output ./output
./bin/opsforge linux net-drift --targets configs/linux/network-targets.conf --output ./output
./bin/opsforge linux disk-rca --output ./output
./bin/opsforge linux tls --targets configs/linux/tls-targets.conf --output ./output
./bin/opsforge linux firewall --output ./output
./bin/opsforge linux log-silence --config configs/examples/log-sources.conf --output ./output
./bin/opsforge linux timeline --output ./output
./bin/opsforge linux web-triage --output ./output
```

Windows:

```powershell
.\bin\opsforge.ps1 windows triage -OutputPath .\output -Json -Markdown
.\bin\opsforge.ps1 windows persistence -OutputPath .\output
.\bin\opsforge.ps1 windows services -OutputPath .\output
.\bin\opsforge.ps1 windows tasks -OutputPath .\output
.\bin\opsforge.ps1 windows network -OutputPath .\output
.\bin\opsforge.ps1 windows firewall -OutputPath .\output
.\bin\opsforge.ps1 windows defender -OutputPath .\output
.\bin\opsforge.ps1 windows privilege -OutputPath .\output
.\bin\opsforge.ps1 windows timeline -OutputPath .\output
.\bin\opsforge.ps1 windows log-tampering -OutputPath .\output
```

## Output

Major scripts create timestamped output directories:

```text
output/HOSTNAME-scriptname-YYYYMMDD-HHMMSS/
├── raw/
├── normalized/
├── report.md
├── findings.json
├── summary.txt
└── evidence.tar.gz
```

`findings.json` uses the same fields everywhere:

```text
id, title, severity, host, category, evidence, recommendation
```

Validate a generated output directory with:

```bash
./bin/validate-output-contract output/HOSTNAME-scriptname-YYYYMMDD-HHMMSS
```

## Testing

Linux:

```bash
./bin/test syntax
./bin/test help
./bin/test wrapper-targets
./bin/test script-catalog
./bin/test forbidden-files
./bin/test readability
./bin/test output-contract
./bin/test linux-fixtures
./bin/test runtime-linux
```

Windows:

```powershell
.\bin\test.ps1 parser
.\bin\test.ps1 wrapper-targets
.\bin\test.ps1 static
.\bin\test.ps1 runtime
```

## Sensitive Output

opsforge collects host and system data.

Generated reports may contain hostnames, usernames, IP addresses, process
arguments, service names, file paths, registry values, and other operational
details.

Review and sanitize output before sharing it.

## Docs

- Runtime validation: `docs/runtime-validation.md`
- Manual testing: `docs/manual-testing.md`
- Compatibility: `docs/compatibility.md`
- Output format: `docs/output-format.md`
- Report standard: `docs/report-standard.md`
- Script catalog: `docs/script-catalog.md`
- Testing: `docs/testing.md`
- Changelog: `CHANGELOG.md`
