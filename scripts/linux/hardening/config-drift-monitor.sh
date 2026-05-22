#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="config-drift-monitor"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
MODE=""
BASELINE_DIR=""

usage() {
  cat <<'USAGE'
Usage: config-drift-monitor.sh --baseline|--check [options]

Track risky Linux configuration drift.

Options:
  --baseline          Create baseline archive directory
  --check             Compare current files against baseline
  --baseline-dir DIR  Baseline directory
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
    --baseline-dir) BASELINE_DIR="${2:?missing baseline directory}"; shift 2 ;;
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
[ -n "$BASELINE_DIR" ] || BASELINE_DIR="$REPO_ROOT/configs/linux/config-baseline.$HOST"
OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
: > "$TMP_FINDINGS"

TRACK_PATHS="
/etc/ssh/sshd_config
/etc/sudoers
/etc/passwd
/etc/group
/etc/fstab
/etc/crontab
/etc/nginx
/etc/apache2
"

copy_tree() {
  local src="$1" dest="$2"
  if [ -f "$src" ]; then
    mkdir -p "$(dirname "$dest")"
    cp -p "$src" "$dest" 2>/dev/null || true
  elif [ -d "$src" ]; then
    mkdir -p "$dest"
    while IFS= read -r file; do
      rel="${file#$src/}"
      mkdir -p "$(dirname "$dest/$rel")"
      cp -p "$file" "$dest/$rel" 2>/dev/null || true
    done < <(find "$src" -maxdepth 4 -type f -print 2>/dev/null || true)
  fi
}

{
  printf '%s\n' $TRACK_PATHS
  opsforge_init_paths
} | while IFS= read -r path; do
  [ -n "$path" ] || continue
  safe="${path#/}"
  copy_tree "$path" "$OUT_DIR/raw/current/$safe"
done

if [ "$MODE" = "baseline" ]; then
  mkdir -p "$BASELINE_DIR"
  cp -a "$OUT_DIR/raw/current/." "$BASELINE_DIR/" 2>/dev/null || true
else
  [ -d "$BASELINE_DIR" ] || die "Baseline directory not found: $BASELINE_DIR"
  diff -ru "$BASELINE_DIR" "$OUT_DIR/raw/current" > "$OUT_DIR/raw/config.diff" 2>/dev/null || true
  grep -Ei '^\+[^+].*PasswordAuthentication[[:space:]]+yes' "$OUT_DIR/raw/config.diff" >/dev/null &&
    write_finding_json "$TMP_FINDINGS" "LINUX-CONFIG-SSH-PASSWORD" "PasswordAuthentication changed to yes" "high" "$HOST" "hardening" "raw/config.diff" "Revert PasswordAuthentication to no unless approved."
  grep -Ei '^\+[^+].*NOPASSWD' "$OUT_DIR/raw/config.diff" >/dev/null &&
    write_finding_json "$TMP_FINDINGS" "LINUX-CONFIG-SUDO-NOPASSWD" "New sudoers NOPASSWD rule detected" "medium" "$HOST" "hardening" "raw/config.diff" "Validate the sudo exception and restrict scope."
  grep -Ei '^\+[^+].*(ExecStart=.*(/tmp/|/dev/shm/|/var/tmp/)|/opt/tmp|/tmp/|/dev/shm/|/var/tmp/)' "$OUT_DIR/raw/config.diff" >/dev/null &&
    write_finding_json "$TMP_FINDINGS" "LINUX-CONFIG-INIT-TMP" "New init or service config references a suspicious path" "high" "$HOST" "persistence" "raw/config.diff" "Investigate the service config and referenced binary."
fi

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
{
  printf '# Config Drift Monitor\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n' "- Mode: \`$MODE\`"
  printf '%s\n' "- Baseline: \`$BASELINE_DIR\`"
} > "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "Config drift monitor" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
