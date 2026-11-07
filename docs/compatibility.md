# Compatibility Matrix

opsforge combines a Rust investigator with native Bash and PowerShell checks.
Scripts degrade clearly when optional commands are missing. The existing
collector is Linux x86_64. Windows saved-case commands are implemented, with
native CI validation pending. Windows collection remains planned and must not
be inferred from Windows script CI results.

The [approved roadmap](investigator-roadmap.md) targets x64 Windows 10 22H2,
Windows 11, and Windows Server 2022/2025 alongside the Linux validation matrix.
Each target requires real VM workflow evidence before a compatibility claim.

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
| Void Linux | CI Docker tested | runit service paths and `sv` status are handled where scripts inspect init data. |
| Alpine Linux | CI Docker tested | OpenRC paths and `rc-status` are handled where scripts inspect init data. |

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
script help and metadata. Examples include `journalctl`, `systemctl`, `sv`,
`rc-status`, `rc-service`, `ss`, `openssl`, `curl`, `lsof`, and Windows
Defender cmdlets.

## Init Systems

Linux checks should not assume systemd.

Current init/service coverage:

- systemd: `/etc/systemd/system`, `/usr/lib/systemd/system`,
  `/lib/systemd/system`, user units, and `systemctl` when available.
- runit: `/etc/runit`, `/etc/sv`, `/var/service`, `/service`, `/etc/service`,
  and `sv status` when available.
- OpenRC: `/etc/init.d`, `/etc/conf.d`, `/etc/runlevels`, and `rc-status`
  when available.
- SysV-style fallback: `/etc/init.d` and `service --status-all` when present.

## Known Limitations

- Containers do not expose the same process, service, and kernel state as full
  hosts.
- Some Linux distributions lack systemd, journalctl, runit/OpenRC tools, or
  GNU-specific `find` features.
- Windows CI uses GitHub-hosted Server 2025 runners. It proves parser,
  wrapper, command availability, and selected runtime behavior, not every
  real audit-policy setup.
- Windows security telemetry varies by audit policy, edition, EDR configuration,
  and PowerShell logging policy.
