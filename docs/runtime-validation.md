# Runtime Validation

opsforge is validated by running tools against real CI hosts instead of relying
on fixture output.

## Linux runtime validation

Command:

```bash
./bin/test runtime-linux
```

Runs:

- Linux triage collector
- Linux persistence hunter
- deleted binary detector
- disk pressure RCA
- TLS inventory scanner when target config exists

Each run must produce:

- `raw/`
- `normalized/`
- `report.md`
- `findings.json`
- `summary.txt`

Each generated output directory is validated with:

```bash
./bin/validate-output-contract <output-dir>
```

## Windows runtime validation

Command:

```powershell
.\bin\test.ps1 runtime
```

Runs:

- Windows triage collector
- Windows persistence hunter
- scheduled task auditor
- network exposure mapper
- event timeline builder

Each run must produce:

- `raw/`
- `normalized/`
- `report.md`
- `findings.json`
- `summary.txt`

## CI artifacts

Runtime output is uploaded as GitHub Actions artifacts:

- `opsforge-linux-runtime-output`
- `opsforge-windows-runtime-output`

These artifacts are generated during workflow runs and are not committed to the
repository.

## Safety

Runtime validation must be read-only by default.

It must not:

- delete files
- kill processes
- modify firewall rules
- edit registry keys
- create persistence
- change permissions
- disable services

## Limitations

CI hosts are small test systems, not real company fleets.

Some checks may produce partial data because of:

- missing privileges
- missing services
- minimal CI runner configuration
- unavailable logs
- platform differences

Scripts must record limitations instead of failing silently.
