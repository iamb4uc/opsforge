# Script Metadata Standard

Every operational script should carry a short metadata block near the top of the
file. The block is meant for humans first and automation second: it should tell a
reviewer what the script does, where it runs, what it needs, what it writes, and
why it is safe to run during an incident.

## Bash Metadata

Use this block after the shebang and strict-mode lines:

```bash
# opsforge:name:
# opsforge:description:
# opsforge:platform:
# opsforge:category:
# opsforge:requires:
# opsforge:optional:
# opsforge:outputs:
# opsforge:safety:
```

## PowerShell Metadata

Use this block after the initial `#Requires` line:

```powershell
<#
opsforge:name:
opsforge:description:
opsforge:platform:
opsforge:category:
opsforge:requires:
opsforge:optional:
opsforge:outputs:
opsforge:safety:
#>
```

## Field Guidance

- `name`: stable script name, matching the command or filename.
- `description`: one sentence describing the operational use case.
- `platform`: `linux`, `unix`, or `windows`.
- `category`: endpoint, persistence, forensic, hardening, network, noc, or siem.
- `requires`: required shell, cmdlets, or platform commands.
- `optional`: optional commands that improve output when present.
- `outputs`: expected output files or directories.
- `safety`: read-only behavior, required privileges, and whether any action flags exist.

New scripts should not be merged without metadata, help output, documented safety
behavior, script catalog coverage, and tests.
