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
