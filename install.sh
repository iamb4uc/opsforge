#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

REPO_URL="${OPSFORGE_REPO_URL:-https://github.com/iamb4uc/opsforge}"
REF="${OPSFORGE_REF:-main}"
SOURCE_DIR=""
PREFIX="/usr/local"
APP_DIR=""
BIN_DIR=""
PREFIX_SET=0
FORCE=0
DRY_RUN=0
CHECK_ONLY=0
CLEANUP_DIR=""

usage() {
  cat <<'USAGE'
Usage:
  install.sh [options]

Options:
  --ref REF          Git ref to install from when downloading. Default: main
  --source DIR      Install from a local checkout instead of downloading.
  --prefix DIR      Prefix for user-facing commands. Default: /usr/local
  --app-dir DIR     Directory for opsforge files. Default: /opt/opsforge
  --bin-dir DIR     Directory for the opsforge command. Default: PREFIX/bin
  --force           Replace an existing install directory.
  --dry-run         Print what would happen without writing files.
  --check           Check dependencies and paths without installing.
  -h, --help        Show this help.

Examples:
  curl -fsSL https://raw.githubusercontent.com/iamb4uc/opsforge/main/install.sh -o /tmp/opsforge-install
  bash /tmp/opsforge-install

  bash install.sh --source . --prefix "$HOME/.local"
  bash install.sh --source . --dry-run
USAGE
}

fail() {
  printf 'install: %s\n' "$*" >&2
  exit 1
}

say() {
  printf 'install: %s\n' "$*"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

is_root() {
  [ "$(id -u 2>/dev/null || printf 1)" = "0" ]
}

abs_path() {
  local path="$1"
  case "$path" in
    /*) printf '%s\n' "$path" ;;
    *) printf '%s/%s\n' "$PWD" "$path" ;;
  esac
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --ref)
        REF="${2:?missing ref}"
        shift 2
        ;;
      --source)
        SOURCE_DIR="$(abs_path "${2:?missing source directory}")"
        shift 2
        ;;
      --prefix)
        PREFIX="${2:?missing prefix}"
        PREFIX_SET=1
        shift 2
        ;;
      --app-dir)
        APP_DIR="${2:?missing app dir}"
        shift 2
        ;;
      --bin-dir)
        BIN_DIR="${2:?missing bin dir}"
        shift 2
        ;;
      --force)
        FORCE=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --check)
        CHECK_ONLY=1
        DRY_RUN=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done
}

set_default_paths() {
  if ! is_root && [ "$PREFIX" = "/usr/local" ] && [ "$PREFIX_SET" != "1" ]; then
    PREFIX="$HOME/.local"
  fi

  if [ -z "$APP_DIR" ]; then
    if is_root; then
      APP_DIR="/opt/opsforge"
    else
      APP_DIR="$HOME/.local/share/opsforge"
    fi
  fi

  if [ -z "$BIN_DIR" ]; then
    BIN_DIR="${PREFIX%/}/bin"
  fi
}

check_deps() {
  have bash || fail "bash is required"
  have tar || fail "tar is required"
  have mkdir || fail "mkdir is required"
  have cp || fail "cp is required"

  if [ -z "$SOURCE_DIR" ] && ! have curl && ! have wget; then
    fail "curl or wget is required to download opsforge"
  fi
}

assert_safe_install_paths() {
  case "$APP_DIR" in
    ""|"/"|"/bin"|"/sbin"|"/usr"|"/usr/bin"|"/usr/sbin"|"/usr/local"|"/usr/local/bin"|"/opt"|"/home"|"$HOME")
      fail "refusing unsafe app dir: $APP_DIR"
      ;;
  esac

  case "$BIN_DIR" in
    ""|"/")
      fail "refusing unsafe bin dir: $BIN_DIR"
      ;;
  esac

  case "$(basename "$APP_DIR")" in
    *opsforge*) ;;
    *) fail "app dir must include 'opsforge': $APP_DIR" ;;
  esac
}

check_paths() {
  local app_parent bin_parent
  app_parent="$(dirname "$APP_DIR")"
  bin_parent="$(dirname "$BIN_DIR")"

  [ -n "$app_parent" ] || fail "could not resolve app parent"
  [ -n "$bin_parent" ] || fail "could not resolve bin parent"

  if [ -e "$APP_DIR" ] && [ "$FORCE" != "1" ]; then
    fail "$APP_DIR already exists; use --force to replace it"
  fi

  if [ -n "$SOURCE_DIR" ] && [ ! -f "$SOURCE_DIR/bin/opsforge" ]; then
    fail "source does not look like opsforge: $SOURCE_DIR"
  fi
}

print_plan() {
  say "ref: $REF"
  if [ -n "$SOURCE_DIR" ]; then
    say "source: $SOURCE_DIR"
  else
    say "source: ${REPO_URL%/}"
  fi
  say "app dir: $APP_DIR"
  say "bin dir: $BIN_DIR"
  say "command: $BIN_DIR/opsforge"

  if [ "$FORCE" = "1" ] && [ -e "$APP_DIR" ]; then
    say "would replace existing app dir: $APP_DIR"
  fi
}

download_source() {
  local tmp="$1"
  local archive="$tmp/opsforge.tar.gz"
  local url="${REPO_URL%/}/archive/refs/heads/${REF}.tar.gz"

  case "$REF" in
    v*|[0-9]*)
      url="${REPO_URL%/}/archive/refs/tags/${REF}.tar.gz"
      ;;
  esac

  say "downloading $url"
  if have curl; then
    curl -fsSL "$url" -o "$archive"
  else
    wget -qO "$archive" "$url"
  fi

  mkdir -p "$tmp/src"
  tar -xzf "$archive" -C "$tmp/src" --strip-components=1
  SOURCE_DIR="$tmp/src"
}

copy_tree() {
  local src="$1"
  local dest="$2"
  local tmp="$3"

  [ -f "$src/bin/opsforge" ] || fail "source does not look like opsforge: $src"
  mkdir -p "$dest"

  (
    cd "$src"
    tar -cf "$tmp/opsforge-files.tar" \
      bin \
      lib \
      scripts \
      configs \
      docs \
      README.md \
      LICENSE \
      CONTRIBUTING.md \
      SECURITY.md \
      CHANGELOG.md \
      install.sh
  )
  tar -xf "$tmp/opsforge-files.tar" -C "$dest"
}

write_shim() {
  local shim="$1"
  local app_dir="$2"

  mkdir -p "$(dirname "$shim")"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -Eeuo pipefail\n'
    printf 'export OPSFORGE_HOME=%q\n' "$app_dir"
    printf 'exec "$OPSFORGE_HOME/bin/opsforge" "$@"\n'
  } > "$shim"
  chmod 755 "$shim"
}

install_opsforge() {
  local tmp

  check_paths
  print_plan

  if [ "$DRY_RUN" = "1" ]; then
    if [ "$CHECK_ONLY" = "1" ]; then
      say "check passed"
    else
      say "dry-run only; no files written"
    fi
    return 0
  fi

  tmp="$(mktemp -d "${TMPDIR:-/tmp}/opsforge-install.XXXXXX")"
  CLEANUP_DIR="$tmp"
  trap 'rm -rf "$CLEANUP_DIR"' EXIT

  if [ -z "$SOURCE_DIR" ]; then
    download_source "$tmp"
  fi

  if [ -e "$APP_DIR" ]; then
    say "removing existing app dir because --force was passed: $APP_DIR"
    rm -rf "$APP_DIR"
  fi

  say "installing files to $APP_DIR"
  copy_tree "$SOURCE_DIR" "$APP_DIR" "$tmp"

  chmod 755 "$APP_DIR/bin/opsforge" "$APP_DIR/bin/validate-output-contract" "$APP_DIR/bin/test"
  find "$APP_DIR/scripts/linux" -type f -name '*.sh' -exec chmod 755 {} +

  say "installing command to $BIN_DIR/opsforge"
  write_shim "$BIN_DIR/opsforge" "$APP_DIR"

  say "done"
  printf '\n'
  printf 'Run:\n'
  printf '  %s/opsforge doctor\n' "$BIN_DIR"
  printf '  %s/opsforge linux all --output ./output --markdown --json\n' "$BIN_DIR"
}

parse_args "$@"
set_default_paths
check_deps
assert_safe_install_paths
install_opsforge
