#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="ssh-hardening-audit"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
SSHD_CONFIG="/etc/ssh/sshd_config"

usage() {
  cat <<'USAGE'
Usage: ssh-hardening-audit.sh [options]

Audit OpenSSH server hardening and authorized_keys permissions.

Options:
  --config FILE       sshd_config path
  -o, --output DIR    Base output directory
  --json --markdown   Accepted for compatibility
  --quiet --verbose   Logging controls
  -h, --help          Show help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) SSHD_CONFIG="${2:?missing config file}"; shift 2 ;;
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
[ -r "$SSHD_CONFIG" ] && cp "$SSHD_CONFIG" "$OUT_DIR/raw/sshd_config" || true

cfg_value() {
  local key="$1"
  [ -r "$SSHD_CONFIG" ] || return 0
  awk -v k="$key" 'tolower($1)==tolower(k) && $0 !~ /^[[:space:]]*#/ {v=$2} END{print v}' "$SSHD_CONFIG" 2>/dev/null
}

check_value() {
  local key="$1" expected="$2" severity="$3" rec="$4"
  local value
  value="$(cfg_value "$key")"
  if [ -n "$value" ] && [ "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" != "$expected" ]; then
    write_finding_json "$TMP_FINDINGS" "LINUX-SSH-$key" "SSH $key is set to $value" "$severity" "$HOST" "hardening" "$SSHD_CONFIG: $key $value" "$rec"
  fi
}

check_value PermitRootLogin no high "Set PermitRootLogin to no unless an exception is documented."
check_value PasswordAuthentication no high "Disable password authentication and require key-based access."
check_value X11Forwarding no medium "Disable X11Forwarding unless explicitly required."
check_value AllowTcpForwarding no medium "Disable TCP forwarding unless explicitly required."

max_auth="$(cfg_value MaxAuthTries)"
[ -n "$max_auth" ] && [ "$max_auth" -gt 4 ] 2>/dev/null && write_finding_json "$TMP_FINDINGS" "LINUX-SSH-MAXAUTHTRIES" "SSH MaxAuthTries is high" "medium" "$HOST" "hardening" "$SSHD_CONFIG: MaxAuthTries $max_auth" "Set MaxAuthTries to 4 or lower for exposed servers."

grep -Eiq '^(Ciphers|MACs|KexAlgorithms).*(cbc|3des|arcfour|md5|sha1)' "$SSHD_CONFIG" 2>/dev/null &&
  write_finding_json "$TMP_FINDINGS" "LINUX-SSH-WEAK-CRYPTO" "Weak SSH cryptographic algorithms configured" "high" "$HOST" "hardening" "$SSHD_CONFIG" "Remove weak ciphers, MACs, and key exchange algorithms."

find /root /home -path '*/.ssh/authorized_keys' -type f -printf '%m\t%u\t%g\t%p\n' 2>/dev/null > "$OUT_DIR/raw/authorized-keys-permissions.txt" || true
awk -F '\t' '$1 !~ /^[46]00$/ {print}' "$OUT_DIR/raw/authorized-keys-permissions.txt" | while IFS= read -r line; do
  write_finding_json "$TMP_FINDINGS" "LINUX-SSH-AUTHKEYS-$(printf '%s' "$line" | cksum | awk '{print $1}')" \
    "authorized_keys permissions are weak" "medium" "$HOST" "hardening" "$line" \
    "Restrict authorized_keys to owner-read/write only and validate entries."
done

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/ssh-findings.json"
cp "$OUT_DIR/ssh-findings.json" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
{
  printf '# SSH Hardening Audit\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n' "- Config: \`$SSHD_CONFIG\`"
} > "$OUT_DIR/ssh-audit-report.md"
cp "$OUT_DIR/ssh-audit-report.md" "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "SSH hardening audit" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
