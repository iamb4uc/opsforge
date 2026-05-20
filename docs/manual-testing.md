# Manual Testing

## Goal

Manual testing verifies behavior on real systems outside CI.

## Linux manual test plan

Run:

```bash
./bin/test syntax
./bin/test help
./bin/test wrapper-targets
./bin/test readability
./bin/test runtime-linux
```

Run individual tools:

```bash
./bin/opsforge linux triage --output ./output --markdown --json
./bin/opsforge linux persistence --output ./output --markdown --json
./bin/opsforge linux deleted-binaries --output ./output --markdown --json
./bin/opsforge linux disk-rca --output ./output --markdown --json
```

Validate output:

```bash
./bin/validate-output-contract output/<generated-dir>
```

## Void Linux dogfooding plan

Run the Linux manual test plan on Void Linux.

Record:

- shell version
- kernel version
- missing dependencies
- commands that produced partial collection
- output contract validation result
- warnings observed
- scripts that need compatibility fixes

## Windows manual test plan

Run:

```powershell
.\bin\test.ps1 parser
.\bin\test.ps1 wrapper-targets
.\bin\test.ps1 static
.\bin\test.ps1 runtime
```

Run individual tools:

```powershell
.\bin\opsforge.ps1 windows triage -OutputPath .\output -Json -Markdown
.\bin\opsforge.ps1 windows persistence -OutputPath .\output -Json -Markdown
.\bin\opsforge.ps1 windows tasks -OutputPath .\output -Json -Markdown
.\bin\opsforge.ps1 windows network -OutputPath .\output -Json -Markdown
.\bin\opsforge.ps1 windows timeline -OutputPath .\output -Json -Markdown
```

## Evidence to capture

For each system:

- OS name and version
- shell or PowerShell version
- command run
- generated output path
- validation result
- warnings/errors
- limitations
- whether admin/root was used

## Sanitization guidance

Generated output may contain sensitive host data.

Before sharing output publicly, review and remove:

- hostnames
- usernames
- internal IP addresses
- domain names
- file paths containing personal names
- process arguments containing secrets
- SSH keys
- tokens
- URLs with secrets
- registry values containing sensitive data
- logs with private identifiers
