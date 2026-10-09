# Linux checks in an investigation case

Open **Linux checks** in setup. Space selects a check; Enter opens its settings.
Checks run sequentially after retained logs. They are off in older configurations
and by default. The Checks page shows outcomes, findings and original evidence.

The available checks are triage, persistence, deleted-binaries, process-tree,
suid, privilege-surface, ssh, config-drift, network-path, disk-pressure, tls,
firewall, log-silence, timeline and web-triage.

For unattended runs, use `--check ssh --check firewall`, or a JSON configuration:

```json
{
  "checks": [
    {"tool": "ssh"},
    {"tool": "log-silence", "input": "/root/log-sources.conf"},
    {"tool": "tls", "input": "/root/tls-targets.conf"},
    {"tool": "suid", "baseline": "/root/previous-suid.tsv"},
    {"tool": "config-drift", "create_baseline": true}
  ]
}
```

TLS and network-path require explicit target files. These checks send active
probes to the listed targets. Log-silence requires a source config. Their formats
match the existing shell tools; see [the script catalog](script-catalog.md).
SUID/config drift require an existing baseline or selected baseline creation.
New baselines stay inside the case; existing baselines and input files are
preserved before use. Directory baselines containing symlinks are rejected.
Network-path accepts an optional existing baseline.

The release embeds its Bash scripts and libraries. It stages them under the
private case directory and removes the staged tools when the check run ends.
It clears the shell environment and uses the system command path. Input files
are data; they are never sourced as shell code. Asset hashes and command details
are retained alongside stdout, stderr, findings and original script reports.

The investigator sets `OPSFORGE_SKIP_ARCHIVE=1` for these runs. The case remains
a directory. Standalone shell tools retain their normal archive behavior.

A finding is a check result requiring investigation. It does not establish
exfiltration or compromise. Failed or unavailable commands remain visible;
zero findings do not establish a clean device. Script-specific collection limits
remain in their reports, including timeline windows and filesystem scan scope.
