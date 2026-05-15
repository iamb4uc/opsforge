#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="timeline-builder"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
SINCE_HOURS=24

usage() {
  cat <<'USAGE'
Usage: timeline-builder.sh [options]

Build a CSV and Markdown timeline from Linux logs and filesystem mtimes.

Options:
  --since-hours N     Hours of history to collect, default 24
  -o, --output DIR    Base output directory
  --json --markdown   Accepted for compatibility
  --quiet --verbose   Logging controls
  -h, --help          Show help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --since-hours) SINCE_HOURS="${2:?missing hours}"; shift 2 ;;
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
CSV="$OUT_DIR/timeline.csv"
printf 'timestamp,source,event_type,user,process,summary,severity\n' > "$CSV"

csv_escape() {
  printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"
}

emit_event() {
  local ts="$1" source="$2" type="$3" user="$4" process="$5" summary="$6" severity="$7"
  csv_escape "$ts"; printf ','
  csv_escape "$source"; printf ','
  csv_escape "$type"; printf ','
  csv_escape "$user"; printf ','
  csv_escape "$process"; printf ','
  csv_escape "$summary"; printf ','
  csv_escape "$severity"; printf '\n'
}

if command_exists journalctl; then
  { journalctl --since "${SINCE_HOURS} hours ago" --no-pager -o short-iso 2>/dev/null || true; } |
    while IFS= read -r line; do
      ts="$(printf '%s' "$line" | awk '{print $1}')"
      proc="$(printf '%s' "$line" | awk '{print $4}' | sed 's/\[[0-9]*\]://')"
      emit_event "$ts" "journalctl" "journal" "" "$proc" "$line" "info" >> "$CSV"
    done
fi

for file in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/nginx/access.log /var/log/apache2/access.log; do
  [ -r "$file" ] || continue
  tail -1000 "$file" 2>/dev/null | while IFS= read -r line; do
    severity="info"
    if printf '%s' "$line" | grep -Eiq 'failed|invalid|error|sudo|session opened|Accepted|POST|union|passwd'; then
      severity="medium"
    fi
    emit_event "" "$file" "log" "" "" "$line" "$severity" >> "$CSV"
  done
done

{ find /etc /var/www /tmp /var/tmp -xdev -type f -mmin "-$((SINCE_HOURS * 60))" -printf '%TY-%Tm-%TdT%TH:%TM:%TS,%p\n' 2>/dev/null || true; } |
  while IFS=, read -r ts path; do
    severity="info"
    case "$path" in /tmp/*|/var/tmp/*|/var/www/*) severity="medium" ;; esac
    emit_event "$ts" "filesystem" "mtime" "" "" "$path" "$severity" >> "$CSV"
  done

{
  printf '# Linux Timeline\n\n'
  printf '| timestamp | source | event_type | severity | summary |\n'
  printf '|---|---|---|---|---|\n'
  awk -F, 'NR > 1 && NR <= 501 {gsub(/"/,""); print "| "$1" | "$2" | "$3" | "$7" | "$6" |"}' "$CSV"
} > "$OUT_DIR/timeline.md"
cp "$OUT_DIR/timeline.md" "$OUT_DIR/report.md"
finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
write_basic_summary "$OUT_DIR/summary.txt" "Linux timeline builder" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
