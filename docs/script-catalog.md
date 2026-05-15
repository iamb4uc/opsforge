# Script Catalog

## Linux

- `scripts/linux/endpoint/linux-triage-collector.sh`: live incident triage collection.
- `scripts/linux/persistence/linux-persistence-hunter.sh`: persistence location review.
- `scripts/linux/forensic/deleted-binary-detector.sh`: deleted executable process detection.
- `scripts/linux/noc/disk-pressure-rca.sh`: disk pressure root cause analysis.
- `scripts/linux/network/tls-inventory-scanner.sh`: TLS certificate inventory and expiry review.
- `scripts/linux/endpoint/process-tree-anomaly.sh`: suspicious process ancestry detection.
- `scripts/linux/hardening/suid-drift-monitor.sh`: SUID/SGID baseline and drift monitor.
- `scripts/linux/hardening/linux-privilege-surface-audit.sh`: local privilege exposure audit.
- `scripts/linux/hardening/ssh-hardening-audit.sh`: SSH configuration and key permission audit.
- `scripts/linux/hardening/config-drift-monitor.sh`: risky config baseline and drift monitor.
- `scripts/linux/network/network-path-drift.sh`: DNS, TCP, TLS, HTTP, and route drift monitor.
- `scripts/linux/network/firewall-rule-analyzer.sh`: firewall exposure review.
- `scripts/linux/siem/log-source-silence-detector.sh`: stale or missing log source detection.
- `scripts/linux/forensic/timeline-builder.sh`: Linux event and mtime timeline builder.
- `scripts/linux/forensic/web-compromise-triage.sh`: nginx/apache compromise triage.

## Windows

- `scripts/windows/endpoint/Invoke-WinTriage.ps1`: Windows host triage.
- `scripts/windows/persistence/Find-WinPersistence.ps1`: autorun and persistence review.
- `scripts/windows/persistence/Test-WinScheduledTasks.ps1`: scheduled task audit.
- `scripts/windows/network/Get-WinNetworkExposure.ps1`: listening socket and network exposure mapping.
- `scripts/windows/forensic/New-WinEventTimeline.ps1`: event timeline generation.
- `scripts/windows/endpoint/Test-WinServiceAnomaly.ps1`: suspicious service path and argument review.
- `scripts/windows/network/Test-WinFirewallExposure.ps1`: firewall profile and inbound allow audit.
- `scripts/windows/hardening/Test-WinDefenderStatus.ps1`: Defender status, exclusions, and signature audit.
- `scripts/windows/hardening/Test-WinPrivilegeSurface.ps1`: local privilege surface review.
- `scripts/windows/forensic/Test-WinLogTampering.ps1`: log clearing, audit weakening, and service-stop detection.
