#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="tls-inventory-scanner"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/checks.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
TARGETS=""
BASELINE=""
JSON=0
MARKDOWN=0

usage() {
  cat <<'USAGE'
Usage: tls-inventory-scanner.sh --targets FILE [options]

Inventory TLS certificates using openssl. Target config lines may be host|port or name|host|port.

Options:
  -h, --help          Show this help
  -o, --output DIR    Base output directory
  --targets FILE      Target config file
  --baseline FILE     Previous fingerprint inventory for change detection
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
    --targets) TARGETS="${2:?missing targets file}"; shift 2 ;;
    --baseline) BASELINE="${2:?missing baseline file}"; shift 2 ;;
    --json) JSON=1; shift ;;
    --markdown) MARKDOWN=1; shift ;;
    --quiet) QUIET=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

[ -n "$TARGETS" ] || die "--targets is required"
[ -r "$TARGETS" ] || die "Cannot read targets file: $TARGETS"
require_any_command "TLS collection" openssl

HOST="$(opsforge_hostname)"
OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
INVENTORY="$OUT_DIR/raw/tls-inventory.tsv"
BASELINE_OUT="$OUT_DIR/normalized/tls-fingerprints.tsv"
: > "$TMP_FINDINGS"
printf 'name\thost\tport\tsubject\tissuer\tnot_after\tdays_remaining\tfingerprint\tself_signed\n' > "$INVENTORY"
: > "$BASELINE_OUT"

lookup_baseline() {
  local name="$1"
  local host="$2"
  local port="$3"
  [ -n "$BASELINE" ] && [ -r "$BASELINE" ] || return 1
  awk -F '\t' -v n="$name" -v h="$host" -v p="$port" '($1==n && $2==h && $3==p){print $4; found=1; exit} END{exit found?0:1}' "$BASELINE"
}

fetch_certificate() {
  local host="$1"
  local port="$2"
  if command_exists timeout; then
    timeout 15 openssl s_client -servername "$host" -connect "$host:$port" -showcerts
  else
    openssl s_client -servername "$host" -connect "$host:$port" -showcerts
  fi
}

while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|\#*) continue ;; esac
  name=""
  host=""
  port=""
  old_ifs="$IFS"
  IFS='|'
  set -- $line
  IFS="$old_ifs"
  if [ "$#" -eq 2 ]; then
    name="$1"
    host="$1"
    port="$2"
  else
    name="$1"
    host="$2"
    port="$3"
  fi

  cert="$OUT_DIR/raw/${name}-${host}-${port}.pem"
  if ! fetch_certificate "$host" "$port" </dev/null 2>"$OUT_DIR/raw/${name}-${host}-${port}.connect.err" \
    | awk '/BEGIN CERTIFICATE/{p=1} p{print} /END CERTIFICATE/{exit}' > "$cert"; then
    write_finding_json "$TMP_FINDINGS" "TLS-CONNECT-$(printf '%s' "$name$host$port" | cksum | awk '{print $1}')" \
      "TLS connection failed" "high" "$HOST" "network" "$name $host:$port" \
      "Validate reachability, DNS, firewall policy, and service health."
    continue
  fi
  [ -s "$cert" ] || {
    write_finding_json "$TMP_FINDINGS" "TLS-NO-CERT-$(printf '%s' "$name$host$port" | cksum | awk '{print $1}')" \
      "No certificate returned" "high" "$HOST" "network" "$name $host:$port" \
      "Confirm the target is a TLS service and inspect the listener."
    continue
  }

  subject="$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject=//')"
  issuer="$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
  not_after="$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
  fingerprint="$(openssl x509 -in "$cert" -noout -fingerprint -sha256 2>/dev/null | sed 's/^sha256 Fingerprint=//;s/^SHA256 Fingerprint=//')"
  end_epoch="$(date -d "$not_after" +%s 2>/dev/null || printf '0')"
  now_epoch="$(date +%s)"
  days_remaining=$(( (end_epoch - now_epoch) / 86400 ))
  self_signed="no"
  [ "$subject" = "$issuer" ] && self_signed="yes"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$host" "$port" "$subject" "$issuer" "$not_after" "$days_remaining" "$fingerprint" "$self_signed" >> "$INVENTORY"
  printf '%s\t%s\t%s\t%s\n' "$name" "$host" "$port" "$fingerprint" >> "$BASELINE_OUT"

  if [ "$days_remaining" -lt 0 ]; then
    write_finding_json "$TMP_FINDINGS" "TLS-EXPIRED-$(printf '%s' "$name$host$port" | cksum | awk '{print $1}')" "TLS certificate is expired" "critical" "$HOST" "network" "$name $host:$port expires $not_after" "Replace the certificate and validate dependent services."
  elif [ "$days_remaining" -le 15 ]; then
    write_finding_json "$TMP_FINDINGS" "TLS-EXPIRING-$(printf '%s' "$name$host$port" | cksum | awk '{print $1}')" "TLS certificate expires within 15 days" "high" "$HOST" "network" "$name $host:$port expires $not_after" "Renew certificate and confirm deployment before expiry."
  fi
  if [ "$self_signed" = "yes" ]; then
    write_finding_json "$TMP_FINDINGS" "TLS-SELF-SIGNED-$(printf '%s' "$name$host$port" | cksum | awk '{print $1}')" "TLS certificate appears self-signed" "medium" "$HOST" "network" "$name $host:$port subject=$subject" "Confirm whether this is approved for the service trust model."
  fi
  previous="$(lookup_baseline "$name" "$host" "$port" || true)"
  if [ -n "$previous" ] && [ "$previous" != "$fingerprint" ]; then
    write_finding_json "$TMP_FINDINGS" "TLS-FINGERPRINT-CHANGED-$(printf '%s' "$name$host$port" | cksum | awk '{print $1}')" "TLS certificate fingerprint changed since baseline" "medium" "$HOST" "network" "$name $host:$port old=$previous new=$fingerprint" "Validate the certificate rotation or investigate unexpected TLS interception."
  fi
done < "$TARGETS"

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"

{
  printf '# TLS Inventory Scanner\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf '%s\n\n' "- Targets: \`$TARGETS\`"
  printf '## Inventory\n\n```text\n'
  column -t -s "$(printf '\t')" "$INVENTORY" 2>/dev/null || cat "$INVENTORY"
  printf '\n```\n'
} > "$OUT_DIR/report.md"

findings_count="$(count_findings "$OUT_DIR/findings.json")"
write_basic_summary "$OUT_DIR/summary.txt" "TLS inventory scanner" "$OUT_DIR" "$findings_count"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
