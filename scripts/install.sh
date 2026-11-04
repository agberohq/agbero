#!/usr/bin/env bash
# Agbero installer for Linux and macOS.
#
# This script requires bash. Piping it to `sh` (dash, ash) is not supported.

if [ -z "${BASH_VERSION:-}" ]; then
  echo "Error: this installer requires bash. Re-run with: curl -fsSL <url> | bash" >&2
  exit 1
fi
#
# The installer never publishes anything and never builds from source. It
# downloads a release archive, verifies its SHA-256 against checksums.txt, and
# installs the binary atomically. Signature verification is used when
# cosign/minisign and the signature assets are available.
#
# Usage:
#   curl -fsSL https://github.com/agberohq/agbero/releases/latest/download/install.sh | bash
#   ./install.sh --version v0.1.4 --dir "$HOME/.local/bin"
#   ./install.sh --system --version v0.1.4
#   ./install.sh --check --version v0.1.4
#   ./install.sh --from-file ./dist/release --check

set -euo pipefail

APP="agbero"
REPO="agberohq/agbero"
DEFAULT_BASE_URL="https://github.com/${REPO}/releases/download"
LATEST_API="https://api.github.com/repos/${REPO}/releases/latest"

VERSION="latest"
INSTALL_DIR=""
BASE_URL="${AGBERO_BASE_URL:-$DEFAULT_BASE_URL}"
BASE_URL="${BASE_URL%/}"
FROM_FILE=""
CHECK_ONLY=0
DRY_RUN=0
UNINSTALL=0
ASSUME_YES=0
QUIET=0
MODE="auto" # auto | system | user

CURL=""
WGET=""
TMP_DIR=""
ARCHIVE=""
CHECKSUMS=""
EXTRACTED=""
BACKUP=""

# Set before parse_args so die()/warn() are safe under `set -u` even when an
# option is invalid and setup_colors() has not run yet.
C_RESET="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE=""

setup_colors() {
  if [[ "$QUIET" -eq 1 || ! -t 1 ]]; then
    C_RESET="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE=""
  else
    C_RESET=$'\033[0m' C_RED=$'\033[0;31m' C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[1;33m' C_BLUE=$'\033[0;34m'
  fi
}

log()  { [[ "$QUIET" -eq 1 ]] || printf '%s\n' "$*"; }
info() { [[ "$QUIET" -eq 1 ]] || printf '%s%s%s\n' "$C_BLUE" "$*" "$C_RESET"; }
ok()   { [[ "$QUIET" -eq 1 ]] || printf '%s%s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
warn() { printf '%s%s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
die()  { printf '%sError:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Agbero installer

Usage: install.sh [options]

Options:
  --version VERSION   Release tag (default: latest stable)
  --dir DIRECTORY     Install directory (default: /usr/local/bin or ~/.local/bin)
  --system            System install (requires root)
  --user              User install (default when not root)
  --base-url URL      Release mirror base (default: GitHub Releases)
  --from-file DIR     Install from a local directory containing the archive and checksums.txt
  --check             Download, verify, and extract; do not install
  --dry-run           Print what would be done; do not download
  --uninstall         Remove the installed binary (config and data are kept)
  --yes               Do not prompt for confirmation
  --quiet             Suppress normal output
  --no-color          Disable color output
  -h, --help          Show this help

Examples:
  curl -fsSL https://github.com/${REPO}/releases/latest/download/install.sh | bash
  ./install.sh --version v0.1.4 --dir "\$HOME/.local/bin"
  sudo ./install.sh --system --version v0.1.4 --yes
  ./install.sh --from-file ./dist/release --check
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)      [[ $# -ge 2 ]] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
      --dir)          [[ $# -ge 2 ]] || die "--dir needs a value"; INSTALL_DIR="$2"; shift 2 ;;
      --system)       MODE="system"; shift ;;
      --user)         MODE="user"; shift ;;
      --base-url)     [[ $# -ge 2 ]] || die "--base-url needs a value"; BASE_URL="$2"; shift 2 ;;
      --from-file)    [[ $# -ge 2 ]] || die "--from-file needs a directory"; FROM_FILE="$2"; shift 2 ;;
      --check)        CHECK_ONLY=1; shift ;;
      --dry-run)      DRY_RUN=1; shift ;;
      --uninstall)    UNINSTALL=1; shift ;;
      --yes|-y)       ASSUME_YES=1; shift ;;
      --quiet)        QUIET=1; shift ;;
      --no-color)     NO_COLOR=1; shift ;;
      -h|--help)      usage; exit 0 ;;
      *)              die "unknown option: $1 (use --help)" ;;
    esac
  done
}

detect_platform() {
  local uname_s uname_m
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"

  case "$uname_s" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *)      die "unsupported operating system: $uname_s (use install.ps1 on Windows)" ;;
  esac

  case "$uname_m" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    armv7l|armv8l)
      die "32-bit ARM is not supported. Use a 64-bit OS/container (aarch64/arm64)." ;;
    *)              die "unsupported architecture: $uname_m" ;;
  esac
}

select_tools() {
  if [[ -n "$FROM_FILE" ]]; then
    [[ -d "$FROM_FILE" ]] || die "--from-file directory not found: $FROM_FILE"
  else
    if command -v curl >/dev/null 2>&1; then
      CURL="$(command -v curl)"
    elif command -v wget >/dev/null 2>&1; then
      WGET="$(command -v wget)"
    else
      die "curl or wget is required"
    fi
  fi

  command -v tar >/dev/null 2>&1 || die "tar is required"
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    die "sha256sum or shasum is required"
  fi
}

http_get() {
  local url="$1" out="$2"
  if [[ -n "$CURL" ]]; then
    "$CURL" -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 300 -o "$out" "$url"
  else
    "$WGET" -q --tries=3 --timeout=30 -O "$out" "$url"
  fi
}

normalize_version() {
  local v="$1"
  [[ -n "$v" ]] || die "empty version"
  if [[ "$v" != v* ]]; then
    v="v$v"
  fi
  printf '%s' "$v"
}

resolve_version() {
  if [[ "$VERSION" == "latest" ]]; then
    if [[ -n "$FROM_FILE" ]]; then
      # A local directory cannot know "latest"; require the archive name to
      # match exactly one version or pass --version explicitly.
      local found
      found=$(find "$FROM_FILE" -maxdepth 1 -type f -name "${APP}-${OS}-${ARCH}.*" -print | sed -n '1p' || true)
      [[ -n "$found" ]] || die "--from-file with --version latest requires ${APP}-${OS}-${ARCH}.* in $FROM_FILE"
      VERSION="local"
    else
      info "Fetching latest stable release..."
      local json="$TMP_DIR/latest.json"
      http_get "$LATEST_API" "$json"
      VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$json" | head -n1)"
      [[ -n "$VERSION" ]] || die "could not parse the latest release tag from GitHub"
    fi
  fi
  if [[ "$VERSION" != "local" ]]; then
    VERSION="$(normalize_version "$VERSION")"
  fi
}

archive_name() {
  if [[ "$OS" == "windows" ]]; then
    printf '%s-%s-%s.zip' "$APP" "$OS" "$ARCH"
  else
    printf '%s-%s-%s.tar.gz' "$APP" "$OS" "$ARCH"
  fi
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

prepare_assets() {
  local name="$1"
  if [[ -n "$FROM_FILE" ]]; then
    ARCHIVE="$FROM_FILE/$name"
    CHECKSUMS="$FROM_FILE/checksums.txt"
    [[ -f "$ARCHIVE" ]] || die "archive not found: $ARCHIVE"
    [[ -f "$CHECKSUMS" ]] || die "checksums.txt not found: $CHECKSUMS"
  else
    local url="${BASE_URL}/${VERSION}/${name}"
    info "Downloading ${url}"
    ARCHIVE="$TMP_DIR/$name"
    CHECKSUMS="$TMP_DIR/checksums.txt"
    http_get "$url" "$ARCHIVE"
    http_get "${BASE_URL}/${VERSION}/checksums.txt" "$CHECKSUMS"
  fi
}

verify_checksum() {
  local name expected actual
  name="$(basename "$ARCHIVE")"
  expected="$(awk -v n="$name" '{ k=$2; sub(/^\*/, "", k); if (k==n) { print $1; exit } }' "$CHECKSUMS")"
  [[ -n "$expected" ]] || die "no checksum entry for $name in $CHECKSUMS"
  actual="$(sha256_file "$ARCHIVE")"
  if [[ "$expected" != "$actual" ]]; then
    die "checksum mismatch for $name (expected $expected, got $actual)"
  fi
  ok "Checksum verified: $name"
}

verify_signature() {
  local sig="$CHECKSUMS.sig" pem="$CHECKSUMS.pem" mini="$CHECKSUMS.minisig"
  if [[ -f "$sig" && -f "$pem" ]] && command -v cosign >/dev/null 2>&1; then
    cosign verify-blob "$CHECKSUMS" \
      --signature "$sig" \
      --certificate "$pem" \
      --certificate-identity-regexp "^https://github.com/${REPO}/" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null
    ok "Signature verified (cosign)"
    return
  fi
  if [[ -f "$mini" ]] && command -v minisign >/dev/null 2>&1; then
    # The public key is published with the release; the operator must pass it
    # via AGBERO_MINISIGN_PUBKEY or place agbero.pub next to the checksums.
    local pub="${AGBERO_MINISIGN_PUBKEY:-$(dirname "$CHECKSUMS")/agbero.pub}"
    [[ -f "$pub" ]] || die "minisign public key not found: $pub"
    minisign -Vm "$CHECKSUMS" -x "$mini" -p "$pub" >/dev/null
    ok "Signature verified (minisign)"
    return
  fi
  warn "Signature not verified (cosign/minisign or signature assets unavailable)"
}

safe_extract() {
  local dest="$1" name
  name="$(basename "$ARCHIVE")"
  case "$name" in
    *.tar.gz|*.tgz)
      if tar -tzf "$ARCHIVE" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
        die "archive contains an unsafe path"
      fi
      local flags=(-xzf "$ARCHIVE" -C "$dest")
      if [[ "$(uname -s)" == "Linux" ]]; then
        flags+=(--no-same-owner --no-same-permissions)
      fi
      tar "${flags[@]}"
      ;;
    *.zip)
      command -v unzip >/dev/null 2>&1 || die "unzip is required for zip archives"
      if unzip -Z1 "$ARCHIVE" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
        die "archive contains an unsafe path"
      fi
      unzip -q "$ARCHIVE" -d "$dest"
      ;;
    *)
      die "unsupported archive format: $name"
      ;;
  esac

  local links
  links="$(find "$dest" -type l -print | sed -n '1p' || true)"
  if [[ -n "$links" ]]; then
    die "archive contains symlinks; refusing to install"
  fi

  EXTRACTED="$dest/$APP"
  if [[ ! -f "$EXTRACTED" ]]; then
    EXTRACTED="$dest/${APP}.exe"
  fi
  [[ -f "$EXTRACTED" ]] || die "archive did not contain a $APP binary"
}

default_install_dir() {
  if [[ -n "$INSTALL_DIR" ]]; then
    printf '%s' "$INSTALL_DIR"
  elif [[ "$MODE" == "system" ]]; then
    printf '/usr/local/bin'
  elif [[ "$MODE" == "user" ]]; then
    printf '%s/.local/bin' "$HOME"
  elif [[ "$(id -u)" -eq 0 ]]; then
    printf '/usr/local/bin'
  else
    printf '%s/.local/bin' "$HOME"
  fi
}

can_write_dir() {
  local dir="$1"
  [[ -d "$dir" && -w "$dir" ]] || [[ ! -e "$dir" && -w "$(dirname "$dir")" ]]
}

run_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
    return
  fi
  if [[ ! -t 0 || ! -t 1 ]]; then
    die "root privileges are required for this step, but no TTY is available. Re-run with sudo or use --user."
  fi
  sudo "$@"
}

# Set by install_binary/uninstall_binary when the target directory is not
# writable by the current user.
NEED_ROOT=0

do_target() {
  if [[ "$NEED_ROOT" -eq 1 ]]; then
    run_root "$@"
  else
    "$@"
  fi
}

install_binary() {
  local dir bin
  dir="$(default_install_dir)"
  bin="$dir/$APP"

  if ! can_write_dir "$dir"; then
    if [[ "$MODE" == "user" ]]; then
      die "cannot write to $dir; choose another --dir"
    fi
    info "Root privileges required to install into $dir"
    NEED_ROOT=1
  fi

  do_target mkdir -p "$dir"

  if [[ -e "$bin" ]]; then
    BACKUP="${bin}.bak.$(date +%Y%m%d%H%M%S)"
    info "Backing up existing binary to $BACKUP"
    do_target cp -p "$bin" "$BACKUP"
  fi

  local tmpbin="$dir/.${APP}.new.$$"
  do_target install -m 0755 "$EXTRACTED" "$tmpbin"
  do_target mv -f "$tmpbin" "$bin"

  if command -v restorecon >/dev/null 2>&1; then
    restorecon "$bin" >/dev/null 2>&1 || true
  fi

  if ! "$bin" --version >/dev/null 2>&1; then
    if [[ -n "$BACKUP" && -e "$BACKUP" ]]; then
      warn "installed binary failed to run; restoring $BACKUP"
      do_target mv -f "$BACKUP" "$bin"
    fi
    die "installed binary failed its --version check"
  fi

  ok "Installed $bin"
  "$bin" --version || true
}

uninstall_binary() {
  local dir bin
  dir="$(default_install_dir)"
  bin="$dir/$APP"
  [[ -e "$bin" ]] || { warn "$bin is not installed"; return 0; }

  NEED_ROOT=0
  if ! can_write_dir "$dir"; then
    NEED_ROOT=1
  fi

  if [[ "$ASSUME_YES" -ne 1 ]]; then
    if [[ ! -t 0 ]]; then
      die "refusing to remove $bin without --yes in a non-interactive shell"
    fi
    read -r -p "Remove $bin? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || { log "Cancelled"; return 0; }
  fi

  do_target rm -f "$bin"
  ok "Removed $bin (config and data were kept)"
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}

print_banner() {
  # C_* is only set for an interactive, non-quiet, colour-enabled run, so this
  # single check covers --quiet, --no-color and piped output (CI logs).
  [[ -n "$C_BLUE" ]] || return 0
  printf '%s' "$C_BLUE"
  cat <<'BANNER'
       _____         ___.
      /  _  \    ____\_ |__   ___________  ____
     /  /_\  \  / ___\| __ \_/ __ \_  __ \/  _ \
    /    |    \/ /_/  > \_\ \  ___/|  | \(  <_> )
    \____|__  /\___  /|___  /\___  >__|   \____/
            \//_____/     \/     \/
BANNER
  printf '%s\n' "$C_RESET"
  printf '%sAgbero%s — Modern Reverse Proxy & API Gateway\n\n' "$C_GREEN" "$C_RESET"
}

main() {
  parse_args "$@"
  setup_colors
  if [[ "${NO_COLOR:-0}" == "1" ]]; then
    C_RESET="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE=""
  fi

  print_banner

  detect_platform

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agbero-install.XXXXXX")"
  trap cleanup EXIT

  if [[ "$UNINSTALL" -eq 1 ]]; then
    uninstall_binary
    return 0
  fi

  select_tools

  resolve_version

  local name
  name="$(archive_name)"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "OS/arch:     $OS/$ARCH"
    info "Version:     $VERSION"
    info "Archive:     $name"
    info "Install dir: $(default_install_dir)"
    if [[ -n "$FROM_FILE" ]]; then
      info "From file:   $FROM_FILE"
    fi
    return 0
  fi

  prepare_assets "$name"
  verify_checksum
  verify_signature

  mkdir -p "$TMP_DIR/extract"
  safe_extract "$TMP_DIR/extract"

  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    ok "Verified and extracted $name (check-only; nothing installed)"
    return 0
  fi

  install_binary
  log ""
  log "Next steps:"
  if [[ "$MODE" == "system" || "$(id -u)" -eq 0 ]]; then
    log "  sudo $APP init"
    log "  sudo $APP service install"
    log "  sudo $APP service start"
  else
    log "  $APP init"
    log "  $APP run --dev"
  fi
  log ""
  log "Docs: https://github.com/${REPO}/blob/main/docs/install.md"
}

main "$@"
