#!/usr/bin/env bash

opsforge_repo_root() {
  local src
  src="${BASH_SOURCE[0]}"
  while [ -h "$src" ]; do
    src="$(readlink "$src")"
  done
  cd "$(dirname "$src")/.." && pwd
}

opsforge_timestamp() {
  date '+%Y%m%d-%H%M%S'
}

opsforge_hostname() {
  hostname 2>/dev/null || uname -n 2>/dev/null || printf 'unknown-host'
}

opsforge_mkdir() {
  mkdir -p "$1/raw" "$1/normalized"
}

opsforge_make_output_dir() {
  local base="$1"
  local script_name="$2"
  local host
  host="$(opsforge_hostname | tr ' /' '__')"
  if ! mkdir -p "$base" 2>/dev/null || [ ! -w "$base" ]; then
    base="${OPSFORGE_FALLBACK_OUTPUT:-$(opsforge_repo_root)/.ci-artifacts/runtime-output}"
    printf '[WARN] output path is not writable; using %s\n' "$base" >&2
    mkdir -p "$base"
  fi
  local dir="${base%/}/${host}-${script_name}-$(opsforge_timestamp)"
  local candidate="$dir"
  local n=1
  while [ -e "$candidate" ]; do
    n=$((n + 1))
    candidate="${dir}-${n}"
  done
  dir="$candidate"
  opsforge_mkdir "$dir"
  printf '%s\n' "$dir"
}

opsforge_init_paths() {
  printf '%s\n' \
    /etc/systemd/system \
    /usr/lib/systemd/system \
    /lib/systemd/system \
    "$HOME/.config/systemd/user" \
    /etc/runit \
    /etc/sv \
    /var/service \
    /service \
    /etc/service \
    /etc/init.d \
    /etc/conf.d \
    /etc/runlevels
}

json_escape() {
  local s="${1-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

write_finding_json() {
  local file="$1"
  local id="$2"
  local title="$3"
  local severity="$4"
  local host="$5"
  local category="$6"
  local evidence="$7"
  local recommendation="$8"
  local prefix=""
  if [ -s "$file" ]; then
    prefix=","
  fi
  {
    printf '%s\n' "$prefix"
    printf '  {"id":"%s","title":"%s","severity":"%s","host":"%s","category":"%s","evidence":"%s","recommendation":"%s"}' \
      "$(json_escape "$id")" \
      "$(json_escape "$title")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$host")" \
      "$(json_escape "$category")" \
      "$(json_escape "$evidence")" \
      "$(json_escape "$recommendation")"
  } >> "$file"
}

finalize_findings_json() {
  local tmp="$1"
  local dest="$2"
  {
    printf '[\n'
    if [ -s "$tmp" ]; then
      sed '1{/^,$/d;}' "$tmp"
      printf '\n'
    fi
    printf ']\n'
  } > "$dest"
}

safe_run() {
  local outfile="$1"
  shift
  local out_dir status_file started_at ended_at exit_code status command_text
  out_dir="$(cd "$(dirname "$outfile")/.." && pwd)"
  status_file="$out_dir/normalized/collection-status.tsv"
  started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  command_text="$(printf '%s ' "$@")"
  command_text="${command_text% }"
  if [ "${VERBOSE:-0}" = "1" ] && [ "${QUIET:-0}" != "1" ]; then
    printf '[DEBUG] running: %s\n' "$command_text" >&2
    printf '[DEBUG] writing: %s\n' "$outfile" >&2
  fi
  {
    printf '$'
    printf ' %s' "$@"
    printf '\n\n'
    set +e
    "$@" 2>&1
    exit_code="$?"
    set -e
  } > "$outfile"
  ended_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  status="ok"
  [ "$exit_code" -eq 0 ] || status="failed"
  if [ "${VERBOSE:-0}" = "1" ] && [ "${QUIET:-0}" != "1" ]; then
    printf '[DEBUG] finished: %s exit=%s status=%s\n' "$command_text" "$exit_code" "$status" >&2
  fi
  if [ ! -s "$status_file" ]; then
    printf 'command\toutput_file\texit_code\tstatus\tstarted_at\tended_at\n' > "$status_file"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(printf '%s' "$command_text" | tr '\t\n' '  ')" \
    "${outfile#$out_dir/}" \
    "$exit_code" \
    "$status" \
    "$started_at" \
    "$ended_at" >> "$status_file"
  return 0
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}
