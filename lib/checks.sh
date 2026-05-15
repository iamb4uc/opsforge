#!/usr/bin/env bash

require_any_command() {
  local label="$1"
  shift
  local cmd
  for cmd in "$@"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      return 0
    fi
  done
  printf '[ERROR] Missing required command for %s: %s\n' "$label" "$*" >&2
  exit 1
}

warn_missing_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[WARN] Optional command not found: %s\n' "$1" >&2
    return 1
  fi
  return 0
}
