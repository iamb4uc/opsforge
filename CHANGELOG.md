# Changelog

## v0.7.0

- Added retained FTP, rclone, HTTP access-log and HAR upload/download records
  with file names, endpoints, outcomes, byte basis and raw evidence references.
- Replaced the dashboard with seven classic HTML pages, complete-case search,
  filters, pagination and an evidence index.
- Kept client/server direction, source-local timestamps and missing fields
  explicit; ordinary browser visits remain leads rather than upload proof.

## v0.6.0

- Added a Linux investigator with guided setup, source coverage, and a shareable
  offline case dashboard.
- Added sequential raw and JSONL collection for retained logs, browser history,
  Chromium downloads, active sockets, imports, file inventory, and timed packets.
- Added case hashes and a verified release bootstrap for Linux x86_64.
- Added Rust checks and a case smoke test to Linux CI.

## v0.5.0 - 2026-05-20

- Reformatted source files for readability and reviewability.
- Added Linux runtime validation for real script execution.
- Added Windows runtime validation for real script execution.
- Added runtime output artifact upload in CI.
- Added runtime validation documentation.
- Added manual real-host testing documentation.
- Added readability checks to prevent minified source files.
- Improved output contract validation.

## v0.4.0

- Added Windows runtime checks.
- Improved CI validation for Windows scripts.

## v0.3.0

- Added output contract tests.
- Added output validator and fixture checks.

## v0.2.1

- Improved test runner and fixtures.

## v0.2.0

- Added test runner and fixture structure.

## v0.1.0

- Added initial shell-only SOC/NOC operations toolkit structure.
