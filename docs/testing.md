# Testing

opsforge tests are split by what they can honestly prove.

## Linux

Fast local checks:

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

Docker feasibility check:

```bash
docker run -i --rm -v "$PWD:/repo" -w /repo ubuntu:24.04 /bin/sh -s <<'CONTAINER'
set -eu
apt-get update >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  bash ca-certificates coreutils findutils gawk grep gzip iproute2 \
  openssl procps sed tar util-linux \
  >/dev/null
OPSFORGE_TEST_OUTPUT=/repo/.ci-artifacts bash ./bin/test linux-feasibility
CONTAINER
```

CI runs the same feasibility suite across:

- Ubuntu 24.04 for systemd-style paths and commands.
- Void Linux for runit paths and `sv` handling.
- Alpine Linux for OpenRC paths and `rc-status` handling.

This catches syntax, wrapper drift, catalog drift, forbidden language files,
output contract fixture failures, and read-only Linux script runtime failures.

## Windows

PowerShell checks:

```powershell
.\bin\test.ps1 parser
.\bin\test.ps1 static
.\bin\test.ps1 wrapper-targets
.\bin\test.ps1 runtime
```

The runtime check currently executes:

- `Invoke-WinTriage.ps1`
- `Find-WinPersistence.ps1`
- `Test-WinScheduledTasks.ps1`
- `Get-WinNetworkExposure.ps1`
- `New-WinEventTimeline.ps1`
- `windows quick`
- `windows ir`
- `windows full`
- `windows all`

Each runtime output is checked for the standard `raw/`, `normalized/`,
`report.md`, `findings.json`, and `summary.txt` shape.

## CI Notes

- Linux runtime checks run on the GitHub Linux runner.
- Linux feasibility checks run in Ubuntu, Void, and Alpine containers.
- Windows runtime checks run on GitHub's Windows runner.
- Parser-only Windows scripts are still useful, but they should not be treated
  as runtime-proven until added to `bin/test.ps1 runtime`.
