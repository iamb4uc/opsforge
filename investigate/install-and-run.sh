#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

VERSION="latest"
REMOVE_BOOTSTRAP=0
INSTALL_DEPS=0
ARGS=()

usage() {
  cat <<'HELP'
Usage: install-and-run.sh [--version TAG] [--install-deps] [--remove-bootstrap] [investigator options]

Downloads and verifies the Linux x86_64 release binary, then launches the TUI.
--install-deps installs missing capture tools through the package manager.
The binary and download files are removed when the run ends. Case output stays.

Investigator options are passed through. Use --help-investigator to see them.
HELP
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?missing version}"; shift 2 ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --remove-bootstrap) REMOVE_BOOTSTRAP=1; shift ;;
    --help-investigator) ARGS+=(--help); shift ;;
    -h|--help) usage; exit 0 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

if [ "$VERSION" != latest ] && ! [[ "$VERSION" =~ ^v[0-9]+([.][0-9]+){1,2}(-[A-Za-z0-9.]+)?$ ]]; then
  printf 'invalid version: %s\n' "$VERSION" >&2
  exit 2
fi
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  printf 'this bundle supports Linux x86_64 only\n' >&2
  exit 2
fi
for tool in curl sha256sum tar; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'missing bootstrap tool: %s\n' "$tool" >&2; exit 2; }
done

tmp_dir="$(mktemp -d)"
cleanup() {
  if [ -d "$tmp_dir" ]; then
    rm -r -- "$tmp_dir"
  fi
  if [ "$REMOVE_BOOTSTRAP" = 1 ] && [ "$0" = /tmp/opsforge-investigate-bootstrap ] && [ -f "$0" ]; then
    unlink "$0"
  fi
}
trap cleanup EXIT

asset=opsforge-investigate-linux-x86_64.tar.gz
base="https://github.com/iamb4uc/opsforge/releases"
if [ "$VERSION" = latest ]; then
  base="$base/latest/download"
else
  base="$base/download/$VERSION"
fi
curl -fsSL "$base/$asset" -o "$tmp_dir/$asset"
curl -fsSL "$base/$asset.sha256" -o "$tmp_dir/$asset.sha256"
(
  cd "$tmp_dir"
  sha256sum -c "$asset.sha256"
)
tar -xzf "$tmp_dir/$asset" -C "$tmp_dir" opsforge-investigate
chmod 700 "$tmp_dir/opsforge-investigate"

if [ "$INSTALL_DEPS" = 1 ] && [ "${ARGS[*]-}" != --help ]; then
  missing=()
  command -v tcpdump >/dev/null 2>&1 || missing+=(tcpdump)
  command -v ss >/dev/null 2>&1 || missing+=(iproute2)
  command -v timeout >/dev/null 2>&1 || missing+=(coreutils)
  if [ "${#missing[@]}" -gt 0 ]; then
    privilege=()
    if [ "$(id -u)" != 0 ]; then
      command -v sudo >/dev/null 2>&1 || { printf 'sudo is required to install capture tools\n' >&2; exit 2; }
      privilege=(sudo)
    fi
    if command -v apt-get >/dev/null 2>&1; then
      "${privilege[@]}" apt-get update
      "${privilege[@]}" apt-get install -y "${missing[@]}"
    elif command -v dnf >/dev/null 2>&1; then
      for index in "${!missing[@]}"; do
        if [ "${missing[index]}" = iproute2 ]; then missing[index]=iproute; fi
      done
      "${privilege[@]}" dnf install -y "${missing[@]}"
    elif command -v pacman >/dev/null 2>&1; then
      "${privilege[@]}" pacman -Sy --needed --noconfirm "${missing[@]}"
    elif command -v xbps-install >/dev/null 2>&1; then
      "${privilege[@]}" xbps-install -Sy "${missing[@]}"
    else
      printf 'unsupported package manager; install: %s\n' "${missing[*]}" >&2
      exit 2
    fi
  fi
fi

"$tmp_dir/opsforge-investigate" "${ARGS[@]}"
