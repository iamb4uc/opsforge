#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="linux-privilege-surface-audit"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"

usage() {
  cat <<'USAGE'
Usage: linux-privilege-surface-audit.sh [options]

Audit Linux privilege exposure without executing exploits.

Options:
  -o, --output DIR    Base output directory
  --json --markdown   Accepted for compatibility
  --quiet --verbose   Logging controls
  -h, --help          Show help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
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

safe_run "$OUT_DIR/raw/sudo-l.txt" sh -c 'sudo -l -n 2>&1 || true'
safe_run "$OUT_DIR/raw/sudoers.txt" sh -c 'find /etc/sudoers /etc/sudoers.d -maxdepth 2 -type f -print -exec sed -n "1,160p" {} \; 2>/dev/null || true'
safe_run "$OUT_DIR/raw/groups.txt" getent group
safe_run "$OUT_DIR/raw/path-permissions.txt" sh -c 'printf "%s\n" "$PATH" | tr ":" "\n" | while read -r d; do [ -n "$d" ] && [ -e "$d" ] && stat -c "%A %U %G %n" "$d"; done'
safe_run "$OUT_DIR/raw/capabilities.txt" sh -c 'command -v getcap >/dev/null 2>&1 && getcap -r / 2>/dev/null || true'
safe_run "$OUT_DIR/raw/suid-sgid.txt" sh -c 'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%m %u %g %p\n" 2>/dev/null'
safe_run "$OUT_DIR/raw/writable-cron-systemd.txt" sh -c 'find /etc/cron* /var/spool/cron /etc/systemd/system -type f -writable -print 2>/dev/null || true'
safe_run "$OUT_DIR/raw/home-permissions.txt" sh -c 'find /home -maxdepth 1 -type d -printf "%m %u %g %p\n" 2>/dev/null || true'

grep -Rni 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null > "$OUT_DIR/normalized/nopasswd-rules.txt" || true
while IFS= read -r line; do
  [ -n "$line" ] || continue
  write_finding_json "$TMP_FINDINGS" "LINUX-PRIV-NOPASSWD-$(printf '%s' "$line" | cksum | awk '{print $1}')" "sudo NOPASSWD rule present" "medium" "$HOST" "hardening" "$line" "Validate whether passwordless sudo is required and restrict command scope."
done < "$OUT_DIR/normalized/nopasswd-rules.txt"

awk -F: '$1=="docker" || $1=="lxd" {print}' "$OUT_DIR/raw/groups.txt" | while IFS= read -r line; do
  members="${line##*:}"
  [ -n "$members" ] || continue
  write_finding_json "$TMP_FINDINGS" "LINUX-PRIV-GROUP-$(printf '%s' "$line" | cksum | awk '{print $1}')" "Privileged container group has users" "high" "$HOST" "hardening" "$line" "Review Docker/LXD group membership as root-equivalent access."
done

awk '$1 ~ /^..w|^.....w|^........w/ {print}' "$OUT_DIR/raw/path-permissions.txt" | while IFS= read -r line; do
  write_finding_json "$TMP_FINDINGS" "LINUX-PRIV-PATH-$(printf '%s' "$line" | cksum | awk '{print $1}')" "Writable PATH directory" "high" "$HOST" "hardening" "$line" "Remove write access from PATH directories or remove them from privileged execution paths."
done

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
{
  printf '# Linux Privilege Surface Audit\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf 'Raw audit evidence is in `raw/`.\n'
} > "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "Linux privilege surface audit" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"

