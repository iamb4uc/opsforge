#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="web-compromise-triage"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
LOG_DIRS="/var/log/nginx /var/log/apache2 /var/log/httpd"

usage() {
  cat <<'USAGE'
Usage: web-compromise-triage.sh [options]

Triage nginx/apache logs for common web compromise indicators.

Options:
  --log-dir DIR       Add log directory to scan
  -o, --output DIR    Base output directory
  --json --markdown   Accepted for compatibility
  --quiet --verbose   Logging controls
  -h, --help          Show help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --log-dir) LOG_DIRS="$LOG_DIRS ${2:?missing log dir}"; shift 2 ;;
    -o|--output) OUTPUT_BASE="${2:?missing output directory}"; shift 2 ;;
    --json|--markdown) shift ;;
    --quiet) QUIET=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

HOST="$(opsforge_hostname)"
OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
: > "$TMP_FINDINGS"
: > "$OUT_DIR/suspicious-requests.csv"
printf 'file,line,indicator,request\n' > "$OUT_DIR/suspicious-requests.csv"

PATTERN='(\.php[0-9]?|cmd=|/shell|/upload|/wp-admin|/xmlrpc\.php|(\.\./)|%2e%2e|union[+%20]+select|select[+%20].*from|/etc/passwd|/bin/sh|/bin/bash|powershell|curl[+%20]|wget[+%20]|base64|;|%3b|`|\$\( )'
for dir in $LOG_DIRS; do
  [ -d "$dir" ] || continue
  find "$dir" -type f \( -name '*access*' -o -name '*error*' \) -print 2>/dev/null | while IFS= read -r file; do
    grep -Eni "$PATTERN" "$file" 2>/dev/null | while IFS= read -r match; do
      line_no="${match%%:*}"
      request="${match#*:}"
      indicator="web-compromise-pattern"
      printf '"%s","%s","%s","%s"\n' "$file" "$line_no" "$indicator" "$(printf '%s' "$request" | sed 's/"/""/g')" >> "$OUT_DIR/suspicious-requests.csv"
    done
  done
done

if [ "$(wc -l < "$OUT_DIR/suspicious-requests.csv")" -gt 1 ]; then
  write_finding_json "$TMP_FINDINGS" "LINUX-WEB-SUSPICIOUS-REQUESTS" "Suspicious web requests detected" "high" "$HOST" "forensic" "suspicious-requests.csv" "Review source IPs, request payloads, response codes, and webroot file changes."
fi

awk '{print $1}' "$OUT_DIR/suspicious-requests.csv" 2>/dev/null | sort | uniq -c | sort -nr | head -50 > "$OUT_DIR/top-source-ips.txt" || true

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
{
  printf '# Web Server Compromise Triage\n\n'
  printf 'Suspicious requests: `%s`\n' "$(( $(wc -l < "$OUT_DIR/suspicious-requests.csv") - 1 ))"
} > "$OUT_DIR/web-ir-report.md"
cp "$OUT_DIR/web-ir-report.md" "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "Web server compromise triage" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
