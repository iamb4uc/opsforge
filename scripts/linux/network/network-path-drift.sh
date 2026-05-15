#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="network-path-drift"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/lib/logging.sh"
. "$REPO_ROOT/lib/archive.sh"
. "$REPO_ROOT/lib/output.sh"

OUTPUT_BASE="$REPO_ROOT/output"
TARGETS="$REPO_ROOT/configs/linux/network-targets.conf"
BASELINE=""

usage() {
  cat <<'USAGE'
Usage: network-path-drift.sh [options]

Track DNS, TCP reachability, TLS fingerprint, HTTP status, and route changes.

Options:
  --targets FILE      name|host|port target config
  --baseline FILE     Previous normalized network inventory
  -o, --output DIR    Base output directory
  --json --markdown   Accepted for compatibility
  --quiet --verbose   Logging controls
  -h, --help          Show help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --targets) TARGETS="${2:?missing targets file}"; shift 2 ;;
    --baseline) BASELINE="${2:?missing baseline file}"; shift 2 ;;
    -o|--output) OUTPUT_BASE="${2:?missing output directory}"; shift 2 ;;
    --json|--markdown) shift ;;
    --quiet) QUIET=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done
[ -r "$TARGETS" ] || die "Cannot read targets file: $TARGETS"

HOST="$(opsforge_hostname)"
OUT_DIR="$(opsforge_make_output_dir "$OUTPUT_BASE" "$SCRIPT_NAME")"
TMP_FINDINGS="$OUT_DIR/normalized/findings.tmp"
INV="$OUT_DIR/normalized/network-paths.tsv"
: > "$TMP_FINDINGS"
printf 'name\thost\tport\tips\ttcp\tlatency_ms\thttp_status\ttls_fingerprint\troute\n' > "$INV"

tcp_check() {
  local host="$1" port="$2"
  if command_exists timeout; then
    timeout 5 bash -c ': > "/dev/tcp/$1/$2"' _ "$host" "$port" >/dev/null 2>&1 && printf 'ok' || printf 'failed'
  else
    bash -c ': > "/dev/tcp/$1/$2"' _ "$host" "$port" >/dev/null 2>&1 && printf 'ok' || printf 'failed'
  fi
}

while IFS='|' read -r name target port rest; do
  [ -n "${name:-}" ] || continue
  case "$name" in \#*) continue ;; esac
  [ -n "${port:-}" ] || continue
  ips="$(getent ahosts "$target" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || true)"
  tcp="$(tcp_check "$target" "$port")"
  latency="$(ping -c 1 -W 2 "$target" 2>/dev/null | awk -F'time=' '/time=/{split($2,a," "); print a[1]; exit}' || true)"
  route="$(command -v traceroute >/dev/null 2>&1 && traceroute -m 8 "$target" 2>/dev/null | awk 'NR>1{print $2}' | paste -sd'>' - || true)"
  http_status="$(command -v curl >/dev/null 2>&1 && curl -k -s -o /dev/null -w '%{http_code}' --max-time 8 "https://$target:$port/" 2>/dev/null || true)"
  if command_exists openssl; then
    if command_exists timeout; then
      tls_fp="$(timeout 8 openssl s_client -servername "$target" -connect "$target:$port" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' || true)"
    else
      tls_fp="$(openssl s_client -servername "$target" -connect "$target:$port" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' || true)"
    fi
  else
    tls_fp=""
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$target" "$port" "$ips" "$tcp" "${latency:-}" "${http_status:-}" "${tls_fp:-}" "${route:-}" >> "$INV"
  [ "$tcp" = "failed" ] && write_finding_json "$TMP_FINDINGS" "LINUX-NETPATH-TCP-$(printf '%s' "$name$target$port" | cksum | awk '{print $1}')" "TCP reachability failed" "high" "$HOST" "network" "$name $target:$port" "Check service health, DNS, routing, and firewall state."
done < "$TARGETS"

if [ -n "$BASELINE" ] && [ -r "$BASELINE" ]; then
  diff -u "$BASELINE" "$INV" > "$OUT_DIR/raw/network-path-drift.diff" 2>/dev/null || true
  [ -s "$OUT_DIR/raw/network-path-drift.diff" ] &&
    write_finding_json "$TMP_FINDINGS" "LINUX-NETPATH-DRIFT" "Network path inventory changed since baseline" "medium" "$HOST" "network" "raw/network-path-drift.diff" "Review DNS, TLS, HTTP, and route changes against approved maintenance."
fi

finalize_findings_json "$TMP_FINDINGS" "$OUT_DIR/findings.json"
cp "$OUT_DIR/findings.json" "$OUT_DIR/normalized/findings.json"
{
  printf '# Network Path Drift\n\n'
  printf '%s\n' "- Targets: \`$TARGETS\`"
  printf 'Inventory: `normalized/network-paths.tsv`\n'
} > "$OUT_DIR/report.md"
write_basic_summary "$OUT_DIR/summary.txt" "Network path drift monitor" "$OUT_DIR" "$(count_findings "$OUT_DIR/findings.json")"
create_evidence_archive "$OUT_DIR"
log_info "Output written to $OUT_DIR"
