#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="firewall-rule-analyzer"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"

usage() {
  cat <<'USAGE'
Usage: firewall-rule-analyzer.sh [options]

Analyze Linux firewall exposure from iptables, nftables, ufw, and firewalld.

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

collect_firewall() {
  local name="$1" outfile="$2"
  shift 2
  local started ended rc status
  started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  if ! command_exists "$name"; then
    printf '%s unavailable\n' "$name" > "$outfile"
    ended="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    opsforge_record_collection_status "$OUT_DIR" "$outfile" 127 "unavailable" "$started" "$ended" "$name" "$@"
    return
  fi
  set +e
  "$name" "$@" > "$outfile" 2>&1
  rc=$?
  set -e
  ended="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  status="collected"
  if [ "$rc" -ne 0 ]; then
    status="failed"
    grep -Eiq 'permission denied|operation not permitted|access is denied' "$outfile" && status="denied"
  fi
  opsforge_record_collection_status "$OUT_DIR" "$outfile" "$rc" "$status" "$started" "$ended" "$name" "$@"
}

collect_firewall iptables-save "$OUT_DIR/raw/iptables.txt"
collect_firewall nft "$OUT_DIR/raw/nftables.txt" list ruleset
collect_firewall ufw "$OUT_DIR/raw/ufw.txt" status verbose
collect_firewall firewall-cmd "$OUT_DIR/raw/firewalld.txt" --list-all-zones
cat "$OUT_DIR/raw/"*.txt > "$OUT_DIR/raw/firewall-all.txt"

grep -Eiq '(^|[[:space:]])(ACCEPT|allow)([[:space:]]|$).*(dpt:22|dport[[:space:]]+22|22/tcp).*(0\.0\.0\.0/0|anywhere)|(^|[[:space:]])(ACCEPT|allow).*(0\.0\.0\.0/0|anywhere).*(dpt:22|dport[[:space:]]+22|22/tcp)' "$OUT_DIR/raw/firewall-all.txt" &&
  write_finding_json "$TMP_FINDINGS" "LINUX-FW-OPEN-ADMIN" "Firewall may expose administrative services broadly" "high" "$HOST" "network" "raw/firewall-all.txt" "Restrict SSH, RDP, WinRM, and management ports to trusted source ranges."

grep -Eiq '(^|[[:space:]])(ACCEPT|allow)([[:space:]]|$).*(dpt:(22|3389|5985|5986|9200|5601|2375)|dport[[:space:]]+(22|3389|5985|5986|9200|5601|2375)|((22|3389|5985|5986|9200|5601|2375)/tcp))' "$OUT_DIR/raw/firewall-all.txt" &&
  write_finding_json "$TMP_FINDINGS" "LINUX-FW-ADMIN-PORTS" "Administrative or sensitive service ports allowed inbound" "medium" "$HOST" "network" "raw/firewall-all.txt" "Confirm each exposed service has a business owner and source restriction."

grep -v '^[[:space:]]*$' "$OUT_DIR/raw/firewall-all.txt" | sort | uniq -d > "$OUT_DIR/raw/duplicate-rules.txt"
[ -s "$OUT_DIR/raw/duplicate-rules.txt" ] &&
  write_finding_json "$TMP_FINDINGS" "LINUX-FW-DUPLICATES" "Duplicate firewall rules detected" "low" "$HOST" "network" "raw/duplicate-rules.txt" "Consolidate duplicate rules to reduce policy ambiguity."

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
{
  printf '# Firewall Rule Analyzer\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf 'Raw firewall output is in `raw/`.\n'
  printf '\n## Collection Status\n\n'
  awk -F '\t' 'NR == 1 { next } { printf "- %s: %s\n", $2, $4 }' "$OUT_DIR/normalized/collection-status.tsv"
} > "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "Firewall rule analyzer" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
