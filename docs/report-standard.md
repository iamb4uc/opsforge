# Report Standard

`report.md` is the human-readable investigation artifact. It should be useful on
its own, but it must not replace raw evidence or structured findings.

Reports should include:

- title
- host
- script name
- timestamp
- collection mode
- privilege status
- finding count by severity
- top findings
- evidence files
- collection limitations
- recommended next actions

## Expectations

- Keep reports factual and concise.
- Link or name evidence files in `raw/` and `normalized/`.
- Distinguish confirmed findings from collection limitations.
- Do not hide partial collection. If a command fails, report the limitation or
  ensure it is recorded in `normalized/collection-status.tsv`.
- Avoid remediation claims unless the script actually performed a documented
  action under an explicit apply flag.

## Finding Counts

Reports should summarize findings by severity when practical:

```text
critical: 0
high: 2
medium: 4
low: 1
info: 3
```

The authoritative machine-readable source remains `findings.json`.
