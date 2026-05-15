#!/usr/bin/env bash

QUIET="${QUIET:-0}"
VERBOSE="${VERBOSE:-0}"

log_info() {
  [ "$QUIET" = "1" ] && return 0
  printf '[INFO] %s\n' "$*" >&2
}

log_warn() {
  [ "$QUIET" = "1" ] && return 0
  printf '[WARN] %s\n' "$*" >&2
}

log_verbose() {
  [ "$VERBOSE" = "1" ] || return 0
  printf '[DEBUG] %s\n' "$*" >&2
}

die() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}
