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

opsforge_init_has_systemd() {
  [ -d /run/systemd/system ] || [ -d /etc/systemd/system ] || [ -d /usr/lib/systemd/system ] || [ -d /lib/systemd/system ]
}

opsforge_init_has_runit() {
  [ -d /run/runit ] || [ -d /etc/runit ] || [ -d /etc/sv ] || [ -d /var/service ] || [ -d /service ] || [ -d /etc/service ]
}

opsforge_init_has_openrc() {
  [ -d /run/openrc ] || [ -d /etc/init.d ] || [ -d /etc/conf.d ] || [ -d /etc/runlevels ]
}

opsforge_pid1_comm() {
  if [ -r /proc/1/comm ]; then
    tr -d '\n' < /proc/1/comm 2>/dev/null || true
  fi
}

opsforge_pid1_exe() {
  if [ -L /proc/1/exe ]; then
    readlink /proc/1/exe 2>/dev/null || true
  fi
}

opsforge_detect_init_system() {
  local pid1_comm pid1_exe
  case "${OPSFORGE_EXPECT_INIT:-${OPSFORGE_INIT_SYSTEM:-}}" in
    systemd|runit|openrc|sysv/service)
      printf '%s\n' "${OPSFORGE_EXPECT_INIT:-${OPSFORGE_INIT_SYSTEM:-}}"
      return 0
      ;;
  esac

  pid1_comm="$(opsforge_pid1_comm)"
  pid1_exe="$(opsforge_pid1_exe)"

  if [ "$pid1_comm" = "systemd" ] || [ "$pid1_exe" = "/usr/lib/systemd/systemd" ] || [ "$pid1_exe" = "/lib/systemd/systemd" ]; then
    printf 'systemd\n'
  elif [ "$pid1_comm" = "runit-init" ] || [ "$pid1_exe" = "/sbin/runit-init" ] || [ -d /run/runit ] || [ -d /etc/runit ]; then
    printf 'runit\n'
  elif [ "$pid1_comm" = "openrc-init" ] || [ "$pid1_exe" = "/sbin/openrc-init" ] || [ -d /run/openrc ]; then
    printf 'openrc\n'
  elif command_exists service; then
    printf 'sysv/service\n'
  else
    printf 'unknown\n'
  fi
}

opsforge_collect_init_services() {
  local mode="$1"
  case "$mode" in
    systemd)
      if command_exists systemctl; then
        printf '%s\n' "--- systemd units ---"
        systemctl list-units --type=service --all --no-pager 2>&1 || true
      else
        printf '%s\n' "systemctl unavailable"
      fi
      ;;
    runit)
      if command_exists sv; then
        printf '%s\n' "--- runit services ---"
        for d in /var/service /service /etc/service; do
          [ -d "$d" ] || continue
          printf '%s\n' "# active service dir: $d"
          find "$d" -mindepth 1 -maxdepth 1 -print 2>/dev/null |
            while IFS= read -r svc; do sv status "$svc" 2>&1 || true; done
        done
        printf '%s\n' "--- runit service definitions ---"
        for d in /etc/sv /etc/runit; do
          [ -d "$d" ] || continue
          printf '%s\n' "# definition dir: $d"
          find "$d" -mindepth 1 -maxdepth 2 \( -type f -o -type l \) 2>/dev/null |
            while IFS= read -r item; do ls -ld "$item" 2>/dev/null || true; done
        done
      else
        printf '%s\n' "sv unavailable"
      fi
      ;;
    openrc)
      if command_exists rc-status; then
        printf '%s\n' "--- openrc services ---"
        rc-status -a 2>&1 || true
        printf '%s\n' "--- openrc runlevels ---"
        find /etc/runlevels /etc/init.d /etc/conf.d -maxdepth 2 -print 2>/dev/null || true
      elif command_exists rc-service; then
        printf '%s\n' "--- openrc services ---"
        rc-service --help 2>&1 || true
        printf '%s\n' "--- openrc runlevels ---"
        find /etc/runlevels /etc/init.d /etc/conf.d -maxdepth 2 -print 2>/dev/null || true
      else
        printf '%s\n' "rc-status/rc-service unavailable"
      fi
      ;;
    sysv/service)
      if command_exists service; then
        printf '%s\n' "--- sysv service status ---"
        service --status-all 2>&1 || true
      else
        printf '%s\n' "service unavailable"
      fi
      ;;
  esac
}

opsforge_collect_init_failed_services() {
  local mode="$1"
  case "$mode" in
    systemd)
      if command_exists systemctl; then
        printf '%s\n' "--- systemd failed units ---"
        systemctl --failed --no-pager 2>&1 || true
      fi
      ;;
    runit)
      if command_exists sv; then
        printf '%s\n' "--- runit down/problem services ---"
        for d in /var/service /service /etc/service; do
          [ -d "$d" ] || continue
          find "$d" -mindepth 1 -maxdepth 1 -print 2>/dev/null |
            while IFS= read -r svc; do sv status "$svc" 2>&1 || true; done
        done | grep -Ei "^(down|fail|unable|warning):|supervise not running" || true
      fi
      ;;
    openrc)
      if command_exists rc-status; then
        printf '%s\n' "--- openrc crashed/inactive services ---"
        rc-status -a 2>&1 | grep -Ei "crashed|failed|inactive" || true
      elif command_exists rc-service; then
        printf '%s\n' "--- openrc service status ---"
        for svc in $(find /etc/init.d -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort); do
          rc-service "$svc" status 2>&1 || true
        done
      fi
      ;;
    sysv/service)
      if command_exists service; then
        printf '%s\n' "--- sysv service status ---"
        service --status-all 2>&1 || true
      fi
      ;;
  esac
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

opsforge_allowlist_file() {
  local name="$1"
  printf '%s/configs/linux/allowlist-%s.conf\n' "$(opsforge_repo_root)" "$name"
}

opsforge_is_allowlisted() {
  local name="$1"
  local value="$2"
  local file entry
  file="$(opsforge_allowlist_file "$name")"
  [ -r "$file" ] || return 1

  while IFS= read -r entry || [ -n "$entry" ]; do
    case "$entry" in
      ''|'#'*) continue ;;
    esac
    case "$value" in
      *"$entry"*) return 0 ;;
    esac
  done < "$file"

  return 1
}

opsforge_reduced_severity() {
  case "$1" in
    critical) printf 'high\n' ;;
    high) printf 'medium\n' ;;
    medium) printf 'low\n' ;;
    low) printf 'info\n' ;;
    *) printf 'info\n' ;;
  esac
}
