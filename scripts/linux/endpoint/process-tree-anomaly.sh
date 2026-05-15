#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="process-tree-anomaly"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"

usage() {
  cat <<'USAGE'
Usage: process-tree-anomaly.sh [options]

Detect suspicious parent-child process chains.

Options:
  -h, --help          Show this help
  -o, --output DIR    Base output directory
  --json              Accepted for standard output compatibility
  --markdown          Accepted for standard output compatibility
  --quiet             Suppress progress output
  --verbose           Enable debug output
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -o|--output) OUTPUT_BASE="${2:?missing output directory}"; shift 2 ;;
    --json|--markdown) shift ;;
    --quiet) QUIET=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

HOST="$(opsforge_hostname)"
OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
: > "$TMP_FINDINGS"

ps -eo pid=,ppid=,user=,comm=,args= > "$OUT_DIR/raw/processes.txt"
if command_exists pstree; then
  pstree -apul > "$OUT_DIR/process-tree.txt" 2>/dev/null || cp "$OUT_DIR/raw/processes.txt" "$OUT_DIR/process-tree.txt"
else
  cp "$OUT_DIR/raw/processes.txt" "$OUT_DIR/process-tree.txt"
fi

awk '
  { pid=$1; ppid=$2; user=$3; comm=$4; $1=$2=$3=$4=""; args=$0; proc[pid]=comm; procargs[pid]=args; procuser[pid]=user; parent[pid]=ppid }
  END {
    for (pid in proc) {
      p=parent[pid]; pc=proc[p]; cc=proc[pid]; a=procargs[pid]; u=procuser[pid]
      if ((pc ~ /^(nginx|apache2|httpd)$/ && cc ~ /^(bash|sh)$/) ||
          (u ~ /^(www-data|apache|nginx)$/ && cc ~ /^(python|python3|perl|php|bash|sh)$/) ||
          (pc == "sshd" && cc ~ /^(curl|wget)$/) ||
          (pc ~ /^(cron|crond)$/ && cc ~ /^(nc|ncat|socat)$/) ||
          (pc == "systemd" && a ~ /\/tmp\/|\/dev\/shm\/|\/var\/tmp\//) ||
          (pc == "docker" && cc == "nsenter")) {
        print pid "\t" p "\t" pc " -> " cc "\t" u "\t" a
      }
    }
  }
' "$OUT_DIR/raw/processes.txt" > "$OUT_DIR/raw/process-anomalies.tsv"

while IFS= read -r line; do
  [ -n "$line" ] || continue
  write_finding_json "$TMP_FINDINGS" "LINUX-PROCTREE-$(printf '%s' "$line" | cksum | awk '{print $1}')" \
    "Suspicious parent-child process chain" "high" "$HOST" "endpoint" "$line" \
    "Validate process ancestry, command line, user context, and network activity."
done < "$OUT_DIR/raw/process-anomalies.tsv"

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/process-anomalies.json"
{
  printf '# Process Tree Anomaly Detector\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n\n' "- Findings: \`$(count_findings "$OUT_DIR/findings.json")\`"
  printf 'See `process-tree.txt` and `raw/process-anomalies.tsv`.\n'
} > "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "Process tree anomaly detector" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"

