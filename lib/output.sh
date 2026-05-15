#!/usr/bin/env bash

write_basic_summary() {
  local file="$1"
  local title="$2"
  local out_dir="$3"
  local findings_count="$4"
  {
    printf '%s\n' "$title"
    printf 'Output: %s\n' "$out_dir"
    printf 'Findings: %s\n' "$findings_count"
  } > "$file"
}

count_findings() {
  local file="$1"
  local count
  if [ ! -s "$file" ]; then
    printf '0\n'
    return 0
  fi
  count="$(grep -c '"id"' "$file" 2>/dev/null || true)"
  printf '%s\n' "${count:-0}"
}
