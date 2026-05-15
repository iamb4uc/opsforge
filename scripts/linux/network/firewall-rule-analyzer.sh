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

safe_run "$OUT_DIR/raw/iptables.txt" sh -c 'command -v iptables-save >/dev/null 2>&1 && iptables-save || true'
safe_run "$OUT_DIR/raw/nftables.txt" sh -c 'command -v nft >/dev/null 2>&1 && nft list ruleset || true'
safe_run "$OUT_DIR/raw/ufw.txt" sh -c 'command -v ufw >/dev/null 2>&1 && ufw status verbose || true'
safe_run "$OUT_DIR/raw/firewalld.txt" sh -c 'command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --list-all-zones || true'
cat "$OUT_DIR/raw/"*.txt > "$OUT_DIR/raw/firewall-all.txt"

grep -Eiq 'ACCEPT.*0\.0\.0\.0/0|allow[[:space:]]+anywhere|services:.*ssh|ports:.*22/tcp' "$OUT_DIR/raw/firewall-all.txt" &&
  write_finding_json "$TMP_FINDINGS" "LINUX-FW-OPEN-ADMIN" "Firewall may expose administrative services broadly" "high" "$HOST" "network" "raw/firewall-all.txt" "Restrict SSH, RDP, WinRM, and management ports to trusted source ranges."

grep -Eiq 'ACCEPT.*dpt:(22|3389|5985|5986|9200|5601|2375)|dport (22|3389|5985|5986|9200|5601|2375)' "$OUT_DIR/raw/firewall-all.txt" &&
  write_finding_json "$TMP_FINDINGS" "LINUX-FW-ADMIN-PORTS" "Administrative or sensitive service ports allowed inbound" "medium" "$HOST" "network" "raw/firewall-all.txt" "Confirm each exposed service has a business owner and source restriction."

sort "$OUT_DIR/raw/firewall-all.txt" | uniq -d > "$OUT_DIR/raw/duplicate-rules.txt"
[ -s "$OUT_DIR/raw/duplicate-rules.txt" ] &&
  write_finding_json "$TMP_FINDINGS" "LINUX-FW-DUPLICATES" "Duplicate firewall rules detected" "low" "$HOST" "network" "raw/duplicate-rules.txt" "Consolidate duplicate rules to reduce policy ambiguity."

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
{
  printf '# Firewall Rule Analyzer\n\n'
  printf '%s\n' "- Host: \`$HOST\`"
  printf 'Raw firewall output is in `raw/`.\n'
} > "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "Firewall rule analyzer" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"

