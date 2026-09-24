#!/usr/bin/env bash

create_evidence_archive() {
  local out_dir="$1"
  local archive
  archive="$(cd "$out_dir" && pwd)/evidence.tar.gz"
  if command -v tar >/dev/null 2>&1; then
    (cd "$out_dir" && tar -czf "$archive" raw normalized report.md summary.txt findings.json 2>/dev/null) || true
  fi
}
