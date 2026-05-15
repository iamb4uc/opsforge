# Threat Model

opsforge-shell supports defensive operations on hosts where responders need
fast evidence without deploying new runtimes.

## In Scope

- Host triage
- Persistence hunting
- Service and network exposure review
- Disk pressure root cause analysis
- TLS inventory
- Event timeline generation
- Hardening and drift evidence

## Out of Scope

- Exploit execution
- Credential theft
- Payload delivery
- Unauthorized scanning
- Automatic remediation without explicit operator approval

## Assumptions

- Scripts may run with partial privileges and should degrade gracefully.
- Output directories may contain sensitive host evidence and should be protected.
- Findings are triage signals, not final attribution.
