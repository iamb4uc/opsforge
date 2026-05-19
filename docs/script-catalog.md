# Script Catalog

Status labels:

- `runtime`: executed in CI and checked against the output contract.
- `feasibility`: executed in Linux Docker feasibility checks.
- `parser`: parsed or structurally checked in CI, but not runtime-tested yet.

## Linux

- `scripts/linux/endpoint/linux-triage-collector.sh` (`feasibility`): live incident triage collection.
- `scripts/linux/persistence/linux-persistence-hunter.sh` (`feasibility`): persistence location review.
- `scripts/linux/forensic/deleted-binary-detector.sh` (`feasibility`): deleted executable process detection.
- `scripts/linux/noc/disk-pressure-rca.sh` (`feasibility`): disk pressure root cause analysis.
- `scripts/linux/network/tls-inventory-scanner.sh` (`feasibility`): TLS certificate inventory and expiry review.
- `scripts/linux/endpoint/process-tree-anomaly.sh` (`feasibility`): suspicious process ancestry detection.
- `scripts/linux/hardening/suid-drift-monitor.sh` (`feasibility`): SUID/SGID baseline and drift monitor.
- `scripts/linux/hardening/linux-privilege-surface-audit.sh` (`feasibility`): local privilege exposure audit.
- `scripts/linux/hardening/ssh-hardening-audit.sh` (`feasibility`): SSH configuration and key permission audit.
- `scripts/linux/hardening/config-drift-monitor.sh` (`feasibility`): risky config baseline and drift monitor.
- `scripts/linux/network/network-path-drift.sh` (`feasibility`): DNS, TCP, TLS, HTTP, and route drift monitor.
- `scripts/linux/network/firewall-rule-analyzer.sh` (`feasibility`): firewall exposure review.
- `scripts/linux/siem/log-source-silence-detector.sh` (`feasibility`): stale or missing log source detection.
- `scripts/linux/forensic/timeline-builder.sh` (`feasibility`): Linux event and mtime timeline builder.
- `scripts/linux/forensic/web-compromise-triage.sh` (`feasibility`): nginx/apache compromise triage.

## Windows

- `scripts/windows/endpoint/Invoke-WinTriage.ps1` (`parser`): Windows host triage.
- `scripts/windows/persistence/Find-WinPersistence.ps1` (`parser`): autorun and persistence review.
- `scripts/windows/persistence/Test-WinScheduledTasks.ps1` (`runtime`): scheduled task audit.
- `scripts/windows/network/Get-WinNetworkExposure.ps1` (`runtime`): listening socket and network exposure mapping.
- `scripts/windows/forensic/New-WinEventTimeline.ps1` (`parser`): event timeline generation.
- `scripts/windows/endpoint/Test-WinServiceAnomaly.ps1` (`runtime`): suspicious service path and argument review.
- `scripts/windows/network/Test-WinFirewallExposure.ps1` (`parser`): firewall profile and inbound allow audit.
- `scripts/windows/hardening/Test-WinDefenderStatus.ps1` (`parser`): Defender status, exclusions, and signature audit.
- `scripts/windows/hardening/Test-WinPrivilegeSurface.ps1` (`parser`): local privilege surface review.
- `scripts/windows/forensic/Test-WinLogTampering.ps1` (`parser`): log clearing, audit weakening, and service-stop detection.
