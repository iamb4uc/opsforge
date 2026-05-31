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
safe_run "$OUT_DIR/raw/capabilities.txt" sh -c 'if command -v getcap >/dev/null 2>&1; then for path in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt; do [ -e "$path" ] || continue; if command -v timeout >/dev/null 2>&1; then timeout 20 getcap -r "$path" 2>/dev/null || true; else getcap -r "$path" 2>/dev/null || true; fi; done; fi'
safe_run "$OUT_DIR/raw/suid-sgid.txt" sh -c 'if command -v timeout >/dev/null 2>&1; then timeout 60 find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%m %u %g %p\n" 2>/dev/null || true; else find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%m %u %g %p\n" 2>/dev/null || true; fi'
safe_run "$OUT_DIR/raw/writable-scheduled-service-paths.txt" bash -c '
{
  find /etc/cron* /var/spool/cron -type f -writable -print 2>/dev/null || true
  for path in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
    /etc/runit /etc/sv /var/service /service /etc/service \
    /etc/init.d /etc/conf.d /etc/runlevels; do
    [ -e "$path" ] || continue
    find "$path" -type f -writable -print 2>/dev/null || true
  done
} | sort -u
'
safe_run "$OUT_DIR/raw/home-permissions.txt" sh -c 'find /home -maxdepth 1 -type d -printf "%m %u %g %p\n" 2>/dev/null || true'

grep -Rni 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null > "$OUT_DIR/normalized/nopasswd-rules.txt" || true
while IFS= read -r line; do
  [ -n "$line" ] || continue
  severity="medium"
  title="sudo NOPASSWD rule present"
  recommendation="Validate whether passwordless sudo is required and restrict command scope."
  if opsforge_is_allowlisted users "$line"; then
    severity="$(opsforge_reduced_severity "$severity")"
    title="$title (allowlisted)"
    recommendation="$recommendation This matched allowlist-users.conf; verify the entry is still wanted."
  fi
  write_finding_json "$TMP_FINDINGS" "LINUX-PRIV-NOPASSWD-$(printf '%s' "$line" | cksum | awk '{print $1}')" "$title" "$severity" "$HOST" "hardening" "$line" "$recommendation"
done < "$OUT_DIR/normalized/nopasswd-rules.txt"

awk -F: '$1=="docker" || $1=="lxd" {print}' "$OUT_DIR/raw/groups.txt" | while IFS= read -r line; do
  members="${line##*:}"
  [ -n "$members" ] || continue
  severity="high"
  title="Privileged container group has users"
  recommendation="Review Docker/LXD group membership as root-equivalent access."
  if opsforge_is_allowlisted users "$line"; then
    severity="$(opsforge_reduced_severity "$severity")"
    title="$title (allowlisted)"
    recommendation="$recommendation This matched allowlist-users.conf; verify the entry is still wanted."
  fi
  write_finding_json "$TMP_FINDINGS" "LINUX-PRIV-GROUP-$(printf '%s' "$line" | cksum | awk '{print $1}')" "$title" "$severity" "$HOST" "hardening" "$line" "$recommendation"
done

awk '$1 ~ /^..w|^.....w|^........w/ {print}' "$OUT_DIR/raw/path-permissions.txt" | while IFS= read -r line; do
  severity="high"
  title="Writable PATH directory"
  recommendation="Remove write access from PATH directories or remove them from privileged execution paths."
  if opsforge_is_allowlisted paths "$line"; then
    severity="$(opsforge_reduced_severity "$severity")"
    title="$title (allowlisted)"
    recommendation="$recommendation This matched allowlist-paths.conf; verify the entry is still wanted."
  fi
  write_finding_json "$TMP_FINDINGS" "LINUX-PRIV-PATH-$(printf '%s' "$line" | cksum | awk '{print $1}')" "$title" "$severity" "$HOST" "hardening" "$line" "$recommendation"
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
