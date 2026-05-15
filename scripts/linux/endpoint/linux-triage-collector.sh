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
collect network sh -c 'command -v ss >/dev/null 2>&1 && ss -tunap || netstat -tunap'
collect listening-sockets sh -c 'command -v ss >/dev/null 2>&1 && ss -lntup || netstat -lntup'
collect routing-table sh -c 'command -v ip >/dev/null 2>&1 && ip route show table all || route -n'
collect dns-config sh -c 'cat /etc/resolv.conf 2>/dev/null; printf "\n--- hosts ---\n"; cat /etc/hosts 2>/dev/null'
collect services sh -c 'command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --all --no-pager || service --status-all'
collect failed-services sh -c 'command -v systemctl >/dev/null 2>&1 && systemctl --failed --no-pager || true'
collect cron-jobs sh -c 'for p in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do [ -e "$p" ] && ls -la "$p" && { [ -f "$p" ] && cat "$p" || find "$p" -maxdepth 2 -type f -print -exec sed -n "1,80p" {} \; ; }; done; crontab -l 2>/dev/null || true'
collect sudoers sh -c 'find /etc/sudoers /etc/sudoers.d -maxdepth 2 -type f -print -exec sed -n "1,120p" {} \; 2>/dev/null || true'
collect authorized-keys sh -c 'find /root /home -path "*/.ssh/authorized_keys" -type f -print -exec ls -l {} \; -exec sed -n "1,80p" {} \; 2>/dev/null || true'
collect recent-modified-files sh -c 'find /etc /usr/local /opt /tmp /var/tmp -xdev -type f -mtime -7 -printf "%TY-%Tm-%Td %TH:%TM %m %u %g %p\n" 2>/dev/null | sort | tail -500'
collect suid-sgid-files bash -c 'if command -v timeout >/dev/null 2>&1; then timeout 45 find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%TY-%Tm-%Td %TH:%TM %m %u %g %p\n" 2>/dev/null || true; else find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%TY-%Tm-%Td %TH:%TM %m %u %g %p\n" 2>/dev/null || true; fi | sort'
collect kernel-modules sh -c 'lsmod 2>/dev/null || cat /proc/modules'
collect journal-errors sh -c 'command -v journalctl >/dev/null 2>&1 && journalctl -p err -n 300 --no-pager || true'
collect auth-log sh -c 'for f in /var/log/auth.log /var/log/secure; do [ -r "$f" ] && tail -500 "$f"; done'
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

{
  printf '# Linux Triage Collector\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n\n' "- Output: \`$OUT_DIR\`"
  printf '## Collected Evidence\n\n'
  find "$OUT_DIR/raw" -maxdepth 1 -type f -printf '- `%f`\n' | sort
  printf '\n## Notable Normalized Outputs\n\n'
  find "$OUT_DIR/normalized" -maxdepth 1 -type f -printf '- `%f`\n' | sort
} > "$OUT_DIR/report.md"

findings_count="$(count_findings "$OUT_DIR/findings.json")"
write_basic_summary "$OUT_DIR/summary.txt" "Linux triage collector" "$OUT_DIR" "$findings_count"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
