# Compatibility Matrix

opsforge is shell-only by design. Scripts should run with platform-native tools
and degrade clearly when optional commands are missing.

## Supported Shells

- Linux Bash scripts: Bash 4+ where possible.
- POSIX scripts: `/bin/sh` with portable syntax only.
- Windows scripts: Windows PowerShell 5.1+.

## Linux Status

| Platform | Status | Notes |
|---|---|---|
| Ubuntu 24.04 | CI tested | Linux feasibility suite runs in Docker. |
| Debian | planned/manual testing | Expected to work with standard GNU userland. |
| RHEL-like systems | planned/manual testing | Some command output may differ. |
| Arch | planned/manual testing | Rolling package versions may expose parser differences. |
| Void Linux | planned/manual testing | Non-systemd behavior should be handled explicitly. |

## Windows Status

| Platform | Status | Notes |
|---|---|---|
| GitHub Windows latest runner | CI runtime tested | Parser, wrapper paths, command availability, Pester structural checks, and safe runtime checks run in CI. |
| Windows 10 | planned/manual testing | Runtime validation needed on real hosts. |
| Windows 11 | planned/manual testing | Runtime validation needed on real hosts. |
| Windows Server | planned/manual testing | Runtime validation needed on domain and standalone hosts. |

## Privileges

- Most collection scripts can run as a normal user but produce richer evidence
  with administrative or root privileges.
- Scripts must not assume elevated privileges unless they check and document it.
- Read-only behavior is mandatory by default.

## Optional Dependencies

Optional tools may improve output but must not be required unless documented in
script help and metadata. Examples include `journalctl`, `systemctl`, `ss`,
`openssl`, `curl`, `lsof`, and Windows Defender cmdlets.

## Known Limitations

- Containers do not expose the same process, service, and kernel state as full
  hosts.
- Some Linux distributions lack systemd, journalctl, or GNU-specific `find`
  features.
- Windows CI uses GitHub-hosted Server 2025 runners. It proves parser,
  wrapper, command availability, and selected runtime behavior, not every
  real audit-policy setup.
- Windows security telemetry varies by audit policy, edition, EDR configuration,
  and PowerShell logging policy.
