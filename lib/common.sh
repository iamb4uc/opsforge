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
  {
    printf '$'
    printf ' %s' "$@"
    printf '\n\n'
    "$@" 2>&1 || true
  } > "$outfile"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}
