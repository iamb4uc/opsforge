#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="linux-triage-collector"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
JSON=0
MARKDOWN=0
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: linux-triage-collector.sh [options]

Collect live incident response data from a Linux host and flag common triage risks.

Options:
  -h, --help          Show this help
  -o, --output DIR    Base output directory
  --json              Write findings.json
  --markdown          Write report.md
  --quiet             Suppress progress output
  --verbose           Enable debug output
  --dry-run           Show intended output directory and exit
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -o|--output) OUTPUT_BASE="${2:?missing output directory}"; shift 2 ;;
    --json) JSON=1; shift ;;
    --markdown) MARKDOWN=1; shift ;;
    --quiet) QUIET=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

HOST="$(opsforge_hostname)"
if [ "$DRY_RUN" = "1" ]; then
  printf 'Would collect Linux triage data under %s/%s-%s-TIMESTAMP\n' "$OUTPUT_BASE" "$HOST" "$SCRIPT_NAME"
  exit 0
fi

OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
: > "$TMP_FINDINGS"

collect() {
  local name="$1"
  shift
  log_verbose "Collecting $name"
  safe_run "$OUT_DIR/raw/$name.txt" "$@"
}

count_data_lines() {
  local file="$1"
  if [ ! -s "$file" ]; then
    printf '0\n'
    return 0
  fi
  awk 'NR > 2 && length($0) > 0 {count++} END {print count + 0}' "$file"
}

count_status() {
  local wanted="$1"
  awk -F '\t' -v wanted="$wanted" 'NR > 1 && $4 == wanted {count++} END {print count + 0}' \
    "$OUT_DIR/normalized/collection-status.tsv" 2>/dev/null || printf '0\n'
}

severity_count() {
  local severity="$1"
  grep -c "\"severity\":\"$severity\"" "$OUT_DIR/findings.json" 2>/dev/null || true
}

write_collection_limitations() {
  awk -F '\t' '
    NR > 1 && $4 != "ok" {
      printf "- `%s` exited %s. Evidence file: `%s`\n", $1, $3, $2
    }
  ' "$OUT_DIR/normalized/collection-status.tsv" 2>/dev/null || true
}

write_top_findings() {
  local line title severity evidence shown
  shown=0
  while IFS= read -r line; do
    case "$line" in
      *'"id":'*) ;;
      *) continue ;;
    esac
    title="$(printf '%s\n' "$line" | sed 's/.*"title":"\([^"]*\)".*/\1/')"
    severity="$(printf '%s\n' "$line" | sed 's/.*"severity":"\([^"]*\)".*/\1/')"
    evidence="$(printf '%s\n' "$line" | sed 's/.*"evidence":"\([^"]*\)".*/\1/')"
    if [ "${#evidence}" -gt 140 ]; then
      evidence="${evidence:0:137}..."
    fi
    printf '%s\n' "- **$severity** $title - \`$evidence\`"
    shown=$((shown + 1))
    [ "$shown" -lt 10 ] || break
  done < "$OUT_DIR/findings.json"
}

bounded_find() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 45 find "$@"
  else
    find "$@"
  fi
}

collect hostname hostname
collect kernel uname -a
collect uptime uptime
collect users who
collect last-logins sh -c 'last -a 2>/dev/null | head -100 || true'
collect processes ps auxww
collect process-tree sh -c 'command -v pstree >/dev/null 2>&1 && pstree -apul || ps -eo pid,ppid,user,lstart,args'
collect network sh -c 'if command -v ss >/dev/null 2>&1; then ss -tunap; elif command -v netstat >/dev/null 2>&1; then netstat -tunap; else printf "ss/netstat unavailable\n"; fi'
collect listening-sockets sh -c 'if command -v ss >/dev/null 2>&1; then ss -lntup; elif command -v netstat >/dev/null 2>&1; then netstat -lntup; else printf "ss/netstat unavailable\n"; fi'
collect routing-table sh -c 'if command -v ip >/dev/null 2>&1; then ip route show table all; elif command -v route >/dev/null 2>&1; then route -n; else printf "ip/route unavailable\n"; fi'
collect dns-config sh -c 'cat /etc/resolv.conf 2>/dev/null; printf "\n--- hosts ---\n"; cat /etc/hosts 2>/dev/null'
collect services sh -c 'if command -v systemctl >/dev/null 2>&1; then systemctl list-units --type=service --all --no-pager; elif command -v service >/dev/null 2>&1; then service --status-all; else printf "systemctl/service unavailable\n"; fi'
collect failed-services sh -c 'if command -v systemctl >/dev/null 2>&1; then systemctl --failed --no-pager; else printf "systemctl unavailable; failed service list skipped\n"; fi'
collect cron-jobs sh -c 'for p in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do [ -e "$p" ] && ls -la "$p" && { [ -f "$p" ] && cat "$p" || find "$p" -maxdepth 2 -type f -print -exec sed -n "1,80p" {} \; ; }; done; crontab -l 2>/dev/null || true'
collect sudoers sh -c 'find /etc/sudoers /etc/sudoers.d -maxdepth 2 -type f -print -exec sed -n "1,120p" {} \; 2>/dev/null || true'
collect authorized-keys sh -c 'find /root /home -path "*/.ssh/authorized_keys" -type f -print -exec ls -l {} \; -exec sed -n "1,80p" {} \; 2>/dev/null || true'
collect recent-modified-files sh -c 'find /etc /usr/local /opt /tmp /var/tmp -xdev -type f -mtime -7 -printf "%TY-%Tm-%Td %TH:%TM %m %u %g %p\n" 2>/dev/null | sort | tail -500'
collect suid-sgid-files bash -c 'if command -v timeout >/dev/null 2>&1; then timeout 45 find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%TY-%Tm-%Td %TH:%TM %m %u %g %p\n" 2>/dev/null || true; else find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%TY-%Tm-%Td %TH:%TM %m %u %g %p\n" 2>/dev/null || true; fi | sort'
collect kernel-modules sh -c 'lsmod 2>/dev/null || cat /proc/modules'
collect journal-errors sh -c 'command -v journalctl >/dev/null 2>&1 && journalctl -p err -n 300 --no-pager || true'
collect auth-log sh -c 'found=0; for f in /var/log/auth.log /var/log/secure; do if [ -r "$f" ]; then found=1; tail -500 "$f"; fi; done; [ "$found" -eq 1 ] || printf "No readable auth log found at /var/log/auth.log or /var/log/secure\n"'
collect disk-usage df -h
collect deleted-running-binaries sh -c 'for e in /proc/[0-9]*/exe; do t=$(readlink "$e" 2>/dev/null || true); case "$t" in *" (deleted)") pid=${e#/proc/}; pid=${pid%/exe}; printf "%s\t%s\n" "$pid" "$t";; esac; done'

ps -eo pid,user,args 2>/dev/null | awk '$0 ~ /\/tmp\/|\/dev\/shm\// {print}' > "$OUT_DIR/normalized/suspicious-process-paths.txt" || true
while IFS= read -r line; do
  [ -n "$line" ] || continue
  severity="medium"
  case "$line" in *"/dev/shm/"*) severity="high" ;; esac
  write_finding_json "$TMP_FINDINGS" "LINUX-TRIAGE-PROC-$(printf '%s' "$line" | cksum | awk '{print $1}')" \
    "Process command references temporary execution path" "$severity" "$HOST" "endpoint" "$line" \
    "Validate process lineage, binary hash, and whether execution from temporary paths is expected."
done < "$OUT_DIR/normalized/suspicious-process-paths.txt"

if [ -s "$OUT_DIR/raw/deleted-running-binaries.txt" ]; then
  tail -n +3 "$OUT_DIR/raw/deleted-running-binaries.txt" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    write_finding_json "$TMP_FINDINGS" "LINUX-TRIAGE-DELETED-$(printf '%s' "$line" | cksum | awk '{print $1}')" \
      "Deleted binary still running" "high" "$HOST" "forensic" "$line" \
      "Preserve evidence, inspect open network sockets and parent process, then terminate only after approval."
  done
fi

find /etc /var/spool/cron /etc/systemd/system -xdev -type f -perm -0002 -print 2>/dev/null > "$OUT_DIR/normalized/world-writable-sensitive-files.txt" || true
while IFS= read -r file; do
  [ -n "$file" ] || continue
  write_finding_json "$TMP_FINDINGS" "LINUX-TRIAGE-WW-$(printf '%s' "$file" | cksum | awk '{print $1}')" \
    "World-writable sensitive file" "high" "$HOST" "hardening" "$file" \
    "Remove world-write permissions and investigate recent modification history."
done < "$OUT_DIR/normalized/world-writable-sensitive-files.txt"

bounded_find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -mtime -14 -print 2>/dev/null > "$OUT_DIR/normalized/recent-suid-sgid.txt" || true
while IFS= read -r file; do
  [ -n "$file" ] || continue
  write_finding_json "$TMP_FINDINGS" "LINUX-TRIAGE-SUID-$(printf '%s' "$file" | cksum | awk '{print $1}')" \
    "Recent SUID or SGID file" "medium" "$HOST" "hardening" "$file" \
    "Validate package ownership, timestamp, hash, and whether privileged mode is expected."
done < "$OUT_DIR/normalized/recent-suid-sgid.txt"

if command -v systemctl >/dev/null 2>&1; then
  systemctl list-unit-files --type=service --no-pager 2>/dev/null | awk '/enabled|static/ {print $1}' | while IFS= read -r unit; do
    fragment="$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null || true)"
    execs="$(systemctl show "$unit" -p ExecStart --value 2>/dev/null || true)"
    case "$fragment $execs" in
      *"/tmp/"*|*"/dev/shm/"*|*"/var/tmp/"*)
        write_finding_json "$TMP_FINDINGS" "LINUX-TRIAGE-SYSTEMD-$(printf '%s' "$unit" | cksum | awk '{print $1}')" \
          "Systemd service references temporary path" "high" "$HOST" "persistence" "$unit $fragment $execs" \
          "Disable unauthorized service units after preserving the unit file and referenced binary."
        ;;
    esac
  done
fi

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"

findings_count="$(count_findings "$OUT_DIR/findings.json")"

{
  printf '# Linux Triage Collector\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n\n' "- Output: \`$OUT_DIR\`"
  printf '%s\n\n' "- Collection mode: read-only"
  printf '## Quick Counts\n\n'
  printf '%s\n' "- Findings: \`$findings_count\`"
  printf '%s\n' "- Collection commands OK: \`$(count_status ok)\`"
  printf '%s\n' "- Collection commands failed: \`$(count_status failed)\`"
  printf '%s\n' "- Processes: \`$(count_data_lines "$OUT_DIR/raw/processes.txt")\`"
  printf '%s\n' "- Listening sockets: \`$(count_data_lines "$OUT_DIR/raw/listening-sockets.txt")\`"
  printf '%s\n' "- Recent modified files: \`$(count_data_lines "$OUT_DIR/raw/recent-modified-files.txt")\`"
  printf '%s\n' "- SUID/SGID files: \`$(count_data_lines "$OUT_DIR/raw/suid-sgid-files.txt")\`"
  printf '%s\n\n' "- Deleted running binaries: \`$(count_data_lines "$OUT_DIR/raw/deleted-running-binaries.txt")\`"
  printf '## Findings By Severity\n\n'
  for severity in critical high medium low info; do
    printf '%s\n' "- $severity: \`$(severity_count "$severity")\`"
  done
  printf '\n## Top Findings\n\n'
  if [ "$findings_count" -gt 0 ]; then
    write_top_findings
  else
    printf '%s\n' '- No findings were generated by this run.'
  fi
  printf '\n## Collection Limitations\n\n'
  limitations="$(write_collection_limitations)"
  if [ -n "$limitations" ]; then
    printf '%s\n' "$limitations"
  else
    printf '%s\n' '- No command collection failures were recorded.'
  fi
  printf '\n'
  printf '## Collected Evidence\n\n'
  find "$OUT_DIR/raw" -maxdepth 1 -type f -printf '- `%f`\n' | sort
  printf '\n## Notable Normalized Outputs\n\n'
  find "$OUT_DIR/normalized" -maxdepth 1 -type f -printf '- `%f`\n' | sort
} > "$OUT_DIR/report.md"

{
  printf 'Linux triage collector\n'
  printf 'Host: %s\n' "$HOST"
  printf 'Output: %s\n' "$OUT_DIR"
  printf 'Findings: %s\n' "$findings_count"
  printf 'Collection commands OK: %s\n' "$(count_status ok)"
  printf 'Collection commands failed: %s\n' "$(count_status failed)"
  printf 'Processes: %s\n' "$(count_data_lines "$OUT_DIR/raw/processes.txt")"
  printf 'Listening sockets: %s\n' "$(count_data_lines "$OUT_DIR/raw/listening-sockets.txt")"
  printf 'Recent modified files: %s\n' "$(count_data_lines "$OUT_DIR/raw/recent-modified-files.txt")"
  printf 'SUID/SGID files: %s\n' "$(count_data_lines "$OUT_DIR/raw/suid-sgid-files.txt")"
  printf 'Deleted running binaries: %s\n' "$(count_data_lines "$OUT_DIR/raw/deleted-running-binaries.txt")"
} > "$OUT_DIR/summary.txt"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
