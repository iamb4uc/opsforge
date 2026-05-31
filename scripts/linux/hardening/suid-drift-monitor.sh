#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="suid-drift-monitor"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
MODE=""
BASELINE=""

usage() {
  cat <<'USAGE'
Usage: suid-drift-monitor.sh --baseline|--check [options]

Track SUID/SGID privileged file drift.

Options:
  --baseline          Create baseline
  --check             Compare against baseline
  --baseline-file F   Override baseline file
  -o, --output DIR    Base output directory
  --json --markdown   Accepted for compatibility
  --quiet --verbose   Logging controls
  -h, --help          Show help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --baseline) MODE="baseline"; shift ;;
    --check) MODE="check"; shift ;;
    --baseline-file) BASELINE="${2:?missing baseline file}"; shift 2 ;;
    -o|--output) OUTPUT_BASE="${2:?missing output directory}"; shift 2 ;;
    --json|--markdown) shift ;;
    --quiet) QUIET=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done
[ -n "$MODE" ] || die "Choose --baseline or --check"

HOST="$(opsforge_hostname)"
[ -n "$BASELINE" ] || BASELINE="$REPO_ROOT/configs/linux/suid-baseline.$HOST.txt"
OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
CURRENT="$OUT_DIR/raw/current-suid-sgid.tsv"
: > "$TMP_FINDINGS"

{ find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m\t%u\t%g\t%s\t%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null || true; } |
  while IFS= read -r line; do
    path="${line##*	}"
    hash="$(sha256sum "$path" 2>/dev/null | awk '{print $1}' || printf 'unreadable')"
    printf '%s\t%s\n' "$line" "$hash"
  done | sort -k6 > "$CURRENT"

if [ "$MODE" = "baseline" ]; then
  mkdir -p "$(dirname "$BASELINE")"
  cp "$CURRENT" "$BASELINE"
else
  [ -r "$BASELINE" ] || die "Baseline not readable: $BASELINE"
  cut -f6 "$CURRENT" | sort > "$OUT_DIR/normalized/current.paths"
  cut -f6 "$BASELINE" | sort > "$OUT_DIR/normalized/baseline.paths"
  comm -13 "$OUT_DIR/normalized/baseline.paths" "$OUT_DIR/normalized/current.paths" > "$OUT_DIR/raw/new-privileged-files.txt"
  comm -23 "$OUT_DIR/normalized/baseline.paths" "$OUT_DIR/normalized/current.paths" > "$OUT_DIR/raw/removed-privileged-files.txt"
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    severity="medium"
    case "$path" in /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*) severity="low" ;; *) severity="high" ;; esac
    title="New SUID/SGID file detected"
    recommendation="Validate package ownership, hash, and change approval."
    if opsforge_is_allowlisted suid "$path" || opsforge_is_allowlisted paths "$path"; then
      severity="$(opsforge_reduced_severity "$severity")"
      title="$title (allowlisted)"
      recommendation="$recommendation This matched an allowlist; verify the entry is still wanted."
    fi
    write_finding_json "$TMP_FINDINGS" "LINUX-SUID-NEW-$(printf '%s' "$path" | cksum | awk '{print $1}')" \
      "$title" "$severity" "$HOST" "hardening" "$path" \
      "$recommendation"
  done < "$OUT_DIR/raw/new-privileged-files.txt"
  awk -F '\t' '$1 ~ /7..|.7.|..7/ {print}' "$CURRENT" > "$OUT_DIR/raw/world-writable-privileged-files.txt"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    severity="critical"
    title="World-writable privileged file"
    recommendation="Remove write permissions immediately and investigate file provenance."
    if opsforge_is_allowlisted suid "$line" || opsforge_is_allowlisted paths "$line"; then
      severity="$(opsforge_reduced_severity "$severity")"
      title="$title (allowlisted)"
      recommendation="$recommendation This matched an allowlist; verify the entry is still wanted."
    fi
    write_finding_json "$TMP_FINDINGS" "LINUX-SUID-WW-$(printf '%s' "$line" | cksum | awk '{print $1}')" \
      "$title" "$severity" "$HOST" "hardening" "$line" \
      "$recommendation"
  done < "$OUT_DIR/raw/world-writable-privileged-files.txt"
fi

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
{
  printf '# SUID/SGID Drift Monitor\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n' "- Mode: \`$MODE\`"
  printf '%s\n' "- Baseline: \`$BASELINE\`"
} > "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "SUID/SGID drift monitor" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
