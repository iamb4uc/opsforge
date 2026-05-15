#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="disk-pressure-rca"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
JSON=0
MARKDOWN=0
EXECUTE=0

usage() {
  cat <<'USAGE'
Usage: disk-pressure-rca.sh [options]

Read-only disk pressure investigation. It reports cleanup candidates but does not delete data
unless a future explicit execution mode is implemented.

Options:
  -h, --help          Show this help
  -o, --output DIR    Base output directory
  --json              Write findings.json
  --markdown          Write disk-rca.md/report.md
  --quiet             Suppress progress output
  --verbose           Enable debug output
  --dry-run           Explicit read-only mode
  --execute           Reserved; currently refuses to delete anything
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
    --dry-run) shift ;;
    --execute) EXECUTE=1; shift ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

[ "$EXECUTE" = "0" ] || die "--execute is reserved for a future guarded cleanup mode; this MVP is read-only."

HOST="$(opsforge_hostname)"
OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
: > "$TMP_FINDINGS"

safe_run "$OUT_DIR/raw/filesystem-usage.txt" df -h
safe_run "$OUT_DIR/raw/inode-usage.txt" df -ih
safe_run "$OUT_DIR/raw/largest-directories.txt" sh -c 'if command -v timeout >/dev/null 2>&1; then timeout 60 du -xhd1 / /var /home /opt 2>/dev/null; else du -xhd1 / /var /home /opt 2>/dev/null; fi | sort -h | tail -100'
safe_run "$OUT_DIR/raw/largest-files.txt" sh -c 'if command -v timeout >/dev/null 2>&1; then timeout 60 find /var /home /opt /tmp -xdev -type f -size +10M -printf "%s\t%p\n" 2>/dev/null; else find /var /home /opt /tmp -xdev -type f -size +10M -printf "%s\t%p\n" 2>/dev/null; fi | sort -n | tail -100'
safe_run "$OUT_DIR/raw/old-compressed-logs.txt" sh -c 'if command -v timeout >/dev/null 2>&1; then timeout 60 find /var/log -type f \( -name "*.gz" -o -name "*.xz" -o -name "*.zip" -o -name "*.1" \) -mtime +14 -printf "%s\t%TY-%Tm-%Td\t%p\n" 2>/dev/null; else find /var/log -type f \( -name "*.gz" -o -name "*.xz" -o -name "*.zip" -o -name "*.1" \) -mtime +14 -printf "%s\t%TY-%Tm-%Td\t%p\n" 2>/dev/null; fi | sort -n'
safe_run "$OUT_DIR/raw/deleted-open-files.txt" sh -c 'command -v lsof >/dev/null 2>&1 && lsof +L1 2>/dev/null || true'
safe_run "$OUT_DIR/raw/journal-disk-usage.txt" sh -c 'command -v journalctl >/dev/null 2>&1 && journalctl --disk-usage 2>&1 || true'
safe_run "$OUT_DIR/raw/docker-usage.txt" sh -c 'command -v docker >/dev/null 2>&1 && docker system df -v 2>&1 || true'
safe_run "$OUT_DIR/raw/security-platform-dirs.txt" sh -c 'du -sh /var/ossec /var/lib/wazuh-indexer /var/lib/opensearch /var/lib/elasticsearch 2>/dev/null || true'

awk 'NR>1 {gsub("%","",$5); if ($5+0 >= 95) print $0}' "$OUT_DIR/raw/filesystem-usage.txt" | while IFS= read -r line; do
  write_finding_json "$TMP_FINDINGS" "LINUX-DISK-CRITICAL-$(printf '%s' "$line" | cksum | awk '{print $1}')" \
    "Filesystem usage is at or above 95 percent" "critical" "$HOST" "noc" "$line" \
    "Identify growth source from largest files and deleted-open files before deleting data."
done

awk 'NR>1 {gsub("%","",$5); if ($5+0 >= 90) print $0}' "$OUT_DIR/raw/inode-usage.txt" | while IFS= read -r line; do
  write_finding_json "$TMP_FINDINGS" "LINUX-INODE-HIGH-$(printf '%s' "$line" | cksum | awk '{print $1}')" \
    "Filesystem inode usage is at or above 90 percent" "high" "$HOST" "noc" "$line" \
    "Locate directories with many small files and rotate or archive safely."
done

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"

{
  printf '# Disk Pressure RCA\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n\n' "- Mode: read-only"
  printf '## Filesystem Usage\n\n```text\n'
  cat "$OUT_DIR/raw/filesystem-usage.txt"
  printf '\n```\n\n## Cleanup Candidates\n\n'
  printf 'See `raw/largest-files.txt`, `raw/old-compressed-logs.txt`, and `raw/deleted-open-files.txt`.\n'
} > "$OUT_DIR/disk-rca.md"
cp "$OUT_DIR/disk-rca.md" "$OUT_DIR/report.md"
cp "$OUT_DIR/raw/old-compressed-logs.txt" "$OUT_DIR/cleanup-candidates.txt"

findings_count="$(count_findings "$OUT_DIR/findings.json")"
write_basic_summary "$OUT_DIR/summary.txt" "Disk pressure RCA" "$OUT_DIR" "$findings_count"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
