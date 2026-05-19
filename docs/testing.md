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
./bin/test sample-output
./bin/test linux-fixtures
```

Docker feasibility check:

```bash
docker run -i --rm -v "$PWD:/repo" -w /repo ubuntu:24.04 bash -s <<'CONTAINER'
set -euo pipefail
apt-get update >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  bash ca-certificates coreutils findutils gawk grep gzip iproute2 openssl procps sed tar util-linux \
  >/dev/null
OPSFORGE_TEST_OUTPUT=/repo/.ci-artifacts ./bin/test linux-feasibility
CONTAINER
```

This catches syntax, wrapper drift, catalog drift, forbidden language files,
sample output contract failures, and read-only Linux script runtime failures.

## Windows

PowerShell checks:

```powershell
.\bin\test.ps1 parser
.\bin\test.ps1 static
.\bin\test.ps1 wrapper-targets
.\bin\test.ps1 runtime
```

The runtime check currently executes:

- `Get-WinNetworkExposure.ps1`
- `Test-WinScheduledTasks.ps1`
- `Test-WinServiceAnomaly.ps1`

Each runtime output is checked for the standard `raw/`, `normalized/`,
`report.md`, `findings.json`, and `summary.txt` shape.

## CI Notes

- Linux runtime checks run in Ubuntu 24.04 Docker.
- Windows runtime checks run on GitHub's Windows runner.
- Parser-only Windows scripts are still useful, but they should not be treated
  as runtime-proven until added to `bin/test.ps1 runtime`.
