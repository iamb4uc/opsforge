#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="log-source-silence-detector"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
CONFIG=""
MAX_AGE_MINUTES=60

usage() {
  cat <<'USAGE'
Usage: log-source-silence-detector.sh --config FILE [options]

Detect log files or journal sources that stopped producing events.
Config format: name|path|criticality|max_age_minutes

Options:
  --config FILE       Log source config
  --max-age MIN       Default silence threshold
  -o, --output DIR    Base output directory
  --json --markdown   Accepted for compatibility
  --quiet --verbose   Logging controls
  -h, --help          Show help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) CONFIG="${2:?missing config file}"; shift 2 ;;
    --max-age) MAX_AGE_MINUTES="${2:?missing age}"; shift 2 ;;
    -o|--output) OUTPUT_BASE="${2:?missing output directory}"; shift 2 ;;
    --json|--markdown) shift ;;
    --quiet) QUIET=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done
[ -n "$CONFIG" ] || die "--config is required"
[ -r "$CONFIG" ] || die "Cannot read config: $CONFIG"

HOST="$(opsforge_hostname)"
OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
STATE_DIR="$REPO_ROOT/output/.state/log-source-silence"
mkdir -p "$STATE_DIR"
: > "$TMP_FINDINGS"
printf 'name\tpath\tmtime_epoch\tage_minutes\tsize\tstatus\n' > "$OUT_DIR/raw/log-source-status.tsv"

now="$(date +%s)"
while IFS='|' read -r name path critical max_age rest; do
  [ -n "${name:-}" ] || continue
  case "$name" in \#*) continue ;; esac
  threshold="${max_age:-$MAX_AGE_MINUTES}"
  severity="high"
  [ "${critical:-}" = "critical" ] && severity="critical"
  if [ ! -e "$path" ]; then
    printf '%s\t%s\t\t\t\tmissing\n' "$name" "$path" >> "$OUT_DIR/raw/log-source-status.tsv"
    write_finding_json "$TMP_FINDINGS" "LINUX-LOG-MISSING-$(printf '%s' "$name$path" | cksum | awk '{print $1}')" "Log source disappeared" "$severity" "$HOST" "siem" "$name $path" "Restore the log source or update collection configuration if intentionally removed."
    continue
  fi
  mtime="$(stat -c %Y "$path" 2>/dev/null || printf '0')"
  size="$(stat -c %s "$path" 2>/dev/null || printf '0')"
  age=$(( (now - mtime) / 60 ))
  printf '%s\t%s\t%s\t%s\t%s\tpresent\n' "$name" "$path" "$mtime" "$age" "$size" >> "$OUT_DIR/raw/log-source-status.tsv"
  if [ "$age" -gt "$threshold" ]; then
    write_finding_json "$TMP_FINDINGS" "LINUX-LOG-SILENT-$(printf '%s' "$name$path" | cksum | awk '{print $1}')" "Log source is silent" "$severity" "$HOST" "siem" "$name $path age=${age}m threshold=${threshold}m" "Check agent health, application logging, disk pressure, and forwarding pipeline status."
  fi
done < "$CONFIG"

if command_exists journalctl; then
  journalctl -n 50 --no-pager > "$OUT_DIR/raw/journal-recent.txt" 2>/dev/null || true
fi

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
{
  printf '# Log Source Silence Detector\n\n'
  printf '%s\n' "- Config: \`$CONFIG\`"
  printf 'Status: `raw/log-source-status.tsv`\n'
} > "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "Log source silence detector" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"

