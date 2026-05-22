#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="linux-persistence-hunter"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
JSON=0
MARKDOWN=0

usage() {
  cat <<'USAGE'
Usage: linux-persistence-hunter.sh [options]

Inspect common Linux persistence locations and flag suspicious command patterns.

Options:
  -h, --help          Show this help
  -o, --output DIR    Base output directory
  --json              Write findings.json
  --markdown          Write persistence-report.md/report.md
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
RAW="$OUT_DIR/raw/persistence-files.txt"
MATCHES="$OUT_DIR/raw/suspicious-matches.txt"
: > "$TMP_FINDINGS"
: > "$RAW"
: > "$MATCHES"

PATTERN='curl[[:space:]].*\|[[:space:]]*(bash|sh)|wget[[:space:]].*\|[[:space:]]*sh|base64[[:space:]]+-d|nc[[:space:]]+-e|socat[[:space:]]+exec|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|/dev/tcp|/tmp/|/dev/shm|chmod[[:space:]]+\+s|chattr[[:space:]]+\+i'

scan_path() {
  local path="$1"
  if [ -f "$path" ]; then
    printf '%s\n' "$path" >> "$RAW"
    grep -Eni "$PATTERN" "$path" >> "$MATCHES" 2>/dev/null || true
  elif [ -d "$path" ]; then
    while IFS= read -r file; do
      printf '%s\n' "$file" >> "$RAW"
      grep -Eni "$PATTERN" "$file" >> "$MATCHES" 2>/dev/null || true
    done < <(find "$path" -xdev -maxdepth 3 -type f -print 2>/dev/null || true)
  fi
}

while IFS= read -r path; do
  scan_path "$path"
done < <(opsforge_init_paths)

for path in \
  /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/crontab \
  /var/spool/cron \
  /etc/rc.local \
  /etc/profile /etc/profile.d \
  "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.ssh/authorized_keys" \
  /etc/ld.so.preload \
  /etc/sudoers /etc/sudoers.d; do
  scan_path "$path"
done

if [ -s "$MATCHES" ]; then
  while IFS= read -r line; do
    file="${line%%:*}"
    rest="${line#*:}"
    lineno="${rest%%:*}"
    text="${line#*:*:}"
    severity="medium"
    case "$text" in
      *"/dev/shm"*|*"/tmp/"*|*"nc -e"*|*"socat exec"*|*"chattr +i"*|*"chmod +s"*) severity="high" ;;
    esac
    write_finding_json "$TMP_FINDINGS" "LINUX-PERSISTENCE-$(printf '%s' "$file:$lineno" | cksum | awk '{print $1}')" \
      "Suspicious persistence content" "$severity" "$HOST" "persistence" \
      "$file:$lineno $text" \
      "Review the referenced persistence location, validate owner and change history, and remove unauthorized entries."
  done < "$MATCHES"
fi

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"

{
  printf '# Linux Persistence Hunter\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n\n' "- Output: \`$OUT_DIR\`"
  printf '## Scanned Locations\n\n'
  awk 'NR <= 200 { printf "- `%s`\n", $0 }' "$RAW"
  printf '\n## Suspicious Matches\n\n'
  if [ -s "$MATCHES" ]; then
    awk '{ printf "- `%s`\n", $0 }' "$MATCHES"
  else
    printf 'No suspicious persistence strings were detected.\n'
  fi
} > "$OUT_DIR/persistence-report.md"
cp "$OUT_DIR/persistence-report.md" "$OUT_DIR/report.md"

findings_count="$(count_findings "$OUT_DIR/findings.json")"
write_basic_summary "$OUT_DIR/summary.txt" "Linux persistence hunter" "$OUT_DIR" "$findings_count"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
