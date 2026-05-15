#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="deleted-binary-detector"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../../../lib/common.sh
. "$REPO_ROOT/lib/common.sh"
# shellcheck source=../../../lib/logging.sh
. "$REPO_ROOT/lib/logging.sh"
# shellcheck source=../../../lib/archive.sh
. "$REPO_ROOT/lib/archive.sh"
# shellcheck source=../../../lib/output.sh
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
JSON=0
MARKDOWN=0

usage() {
  cat <<'USAGE'
Usage: deleted-binary-detector.sh [options]

Detect running Linux processes whose executable has been deleted from disk.

Options:
  -h, --help          Show this help
  -o, --output DIR    Base output directory
  --json              Write findings.json
  --markdown          Write report.md
  --quiet             Suppress progress output
  --verbose           Enable debug output
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
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

HOST="$(opsforge_hostname)"
OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
RAW="$OUT_DIR/raw/deleted-processes.tsv"
: > "$TMP_FINDINGS"

has_network_connection() {
  local pid="$1"
  if command_exists ss; then
    ss -tunap 2>/dev/null | grep -Eq "pid=${pid}," && return 0
  fi
  return 1
}

process_user() {
  local pid="$1"
  ps -o user= -p "$pid" 2>/dev/null | awk '{$1=$1; print}' || printf 'unknown'
}

process_command() {
  local pid="$1"
  if [ -r "/proc/$pid/cmdline" ]; then
    tr '\0' ' ' < "/proc/$pid/cmdline" | sed 's/[[:space:]]*$//'
  else
    ps -o args= -p "$pid" 2>/dev/null || true
  fi
}

process_start() {
  local pid="$1"
  ps -o lstart= -p "$pid" 2>/dev/null | awk '{$1=$1; print}' || true
}

printf 'pid\tuser\tppid\texe\tcommand\thas_network\tstart_time\n' > "$RAW"
for exe in /proc/[0-9]*/exe; do
  [ -e "$exe" ] || continue
  pid="${exe#/proc/}"
  pid="${pid%/exe}"
  target="$(readlink "$exe" 2>/dev/null || true)"
  case "$target" in
    *" (deleted)")
      user="$(process_user "$pid")"
      ppid="$(awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null || printf 'unknown')"
      cmd="$(process_command "$pid")"
      start="$(process_start "$pid")"
      net="no"
      if has_network_connection "$pid"; then
        net="yes"
      fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$user" "$ppid" "$target" "$cmd" "$net" "$start" >> "$RAW"
      severity="medium"
      [ "$net" = "yes" ] && severity="high"
      [ "$user" = "root" ] && severity="high"
      case "$target" in
        */tmp/*|*/dev/shm/*|*/var/tmp/*) severity="high" ;;
      esac
      write_finding_json "$TMP_FINDINGS" "LINUX-DELETED-BINARY-$pid" \
        "Deleted executable still running" "$severity" "$HOST" "forensic" \
        "pid=$pid exe=$target command=$cmd network=$net" \
        "Preserve memory and process metadata, validate parent process, then terminate only after evidence capture."
      ;;
  esac
done

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"

{
  printf '# Deleted Binary Detector\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n\n' "- Output: \`$OUT_DIR\`"
  printf '## Deleted Executables\n\n'
  if [ "$(wc -l < "$RAW")" -gt 1 ]; then
    printf 'See `raw/deleted-processes.tsv`.\n'
  else
    printf 'No deleted executables were detected in `/proc`.\n'
  fi
} > "$OUT_DIR/report.md"

findings_count="$(count_findings "$OUT_DIR/findings.json")"
write_basic_summary "$OUT_DIR/summary.txt" "Deleted binary detector" "$OUT_DIR" "$findings_count"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
