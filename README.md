# opsforge

opsforge is a shell-only defensive operations toolkit for SOC analysts,
NOC engineers, Linux administrators, Windows administrators, incident responders,
and security engineers.

The project focuses on real operational automation:
- Linux and Windows host triage
- persistence hunting
- network drift checks
- TLS inventory
- firewall exposure review
- disk pressure root cause analysis
- log source silence detection
- timeline generation
- endpoint hardening audits

This repository avoids beginner-level recon wrappers and noisy toy scripts.
Every script should produce useful evidence, structured findings, and a readable
report that can help during real investigations.

## Runtime Policy

- Linux/Unix: POSIX sh where possible, Bash where needed.
- Windows: PowerShell 5.1+.
- No Python, Go, Rust, Node.js, Ruby, or compiled helper binaries for the core toolkit.
- Optional external tools must be standard on the platform or documented by the script.
- Scripts are read-only by default unless an explicit execution or apply flag is implemented.

## Commands

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

Major scripts create timestamped directories:

```text
output/HOSTNAME-scriptname-YYYYMMDD-HHMMSS/
├── raw/
├── normalized/
├── report.md
├── findings.json
├── summary.txt
└── evidence.tar.gz
```

`findings.json` uses a stable schema with `id`, `title`, `severity`, `host`,
`category`, `evidence`, and `recommendation`.
