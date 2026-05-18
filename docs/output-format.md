# Output Format

Major scripts create:

```text
output/HOSTNAME-scriptname-YYYYMMDD-HHMMSS/
├── raw/
├── normalized/
├── report.md
├── findings.json
├── summary.txt
└── evidence.tar.gz
```

Finding schema:

```json
{
  "id": "STRING",
  "title": "STRING",
  "severity": "critical|high|medium|low|info",
  "host": "STRING",
  "category": "STRING",
  "evidence": "STRING",
  "recommendation": "STRING"
}
```

`raw/` is for original command output. `normalized/` is for derived data that is
easier to parse or compare. `report.md` is for investigator-readable context.

When scripts collect command output through shared helpers, they should also
record collection metadata in:

```text
normalized/collection-status.tsv
```

The status file uses these columns:

```text
command	output_file	exit_code	status	started_at	ended_at
```

A failed collection command should not abort the whole script by default. It
should be recorded as partial collection so the report and raw evidence remain
usable.
