# Usage

Run scripts directly or through the wrapper.

## Linux

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
./bin/opsforge linux firewall --output ./output
./bin/opsforge linux disk-rca --output ./output
./bin/opsforge linux tls --targets configs/linux/tls-targets.conf --output ./output
./bin/opsforge linux net-drift --targets configs/linux/network-targets.conf --output ./output
./bin/opsforge linux log-silence --config configs/examples/log-sources.conf --output ./output
./bin/opsforge linux timeline --output ./output
./bin/opsforge linux web-triage --output ./output
```

Most Linux scripts can collect more evidence when run as root, but they still
produce useful partial output as an unprivileged user.

## Windows

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

Run PowerShell as Administrator for full service, event log, Defender, and
network visibility.
