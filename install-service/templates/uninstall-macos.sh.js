export const macosUninstallTemplate = `#!/bin/bash
# cert-ctrl macOS uninstallation script for system-wide launchd service

set -euo pipefail

if [[ \${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[ERROR] Run this uninstaller with sudo or as root." >&2
    exit 1
fi

BASE_URL="{{BASE_URL}}"
INSTALL_DIR="\${INSTALL_DIR:-{{INSTALL_DIR}}}"
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="/usr/local/bin"
fi
CONFIG_DIR="\${CONFIG_DIR:-{{CONFIG_DIR}}}"
STATE_DIR="\${STATE_DIR:-{{STATE_DIR}}}"
LOG_DIR="\${LOG_DIR:-{{LOG_DIR}}}"
if [ -z "$LOG_DIR" ]; then
    LOG_DIR="/var/log"
fi
SERVICE_LABEL="\${SERVICE_LABEL:-{{SERVICE_LABEL}}}"
if [ -z "$SERVICE_LABEL" ]; then
    SERVICE_LABEL="com.coderealm.certctrl"
fi
PLIST_PATH="/Library/LaunchDaemons/\${SERVICE_LABEL}.plist"

PURGE="false"
YES="false"
DRY_RUN="\${DRY_RUN:-{{DRY_RUN}}}"
VERBOSE="\${VERBOSE:-{{VERBOSE}}}"

RED='\x1b[0;31m'
GREEN='\x1b[0;32m'
BLUE='\x1b[0;34m'
YELLOW='\x1b[1;33m'
NC='\x1b[0m'

log_info() { echo -e "\${BLUE}[INFO]\${NC} $1" >&2; }
log_success() { echo -e "\${GREEN}[SUCCESS]\${NC} $1" >&2; }
log_warn() { echo -e "\${YELLOW}[WARNING]\${NC} $1" >&2; }
log_error() { echo -e "\${RED}[ERROR]\${NC} $1" >&2; }
log_verbose() { if [ "$VERBOSE" = "true" ]; then echo -e "\${BLUE}[VERBOSE]\${NC} $1" >&2; fi }

die() { log_error "$1"; exit 1; }

usage() {
  cat >&2 <<EOF
cert-ctrl uninstall (macOS)

Usage:
  curl -fsSL "\${BASE_URL}/uninstall-macos.sh" | sudo bash

Options:
  --install-dir <dir>     Override install directory (default: /usr/local/bin)
  --service-label <label> Override launchd label (default: com.coderealm.certctrl)
  --config-dir <dir>      Override config directory
  --state-dir <dir>       Override state directory
  --log-dir <dir>         Override log directory (default: /var/log)
  --purge                 Also remove config/state/log data (DANGEROUS)
  --yes                   Do not prompt (required for --purge in noninteractive)
  --dry-run               Print actions without changing anything
  --verbose               Verbose logging
  -h, --help              Show help
EOF
}

run() {
  if [ "$DRY_RUN" = "true" ]; then
    log_info "DRY RUN: $*"
    return 0
  fi
  "$@"
}

remove_file_if_exists() {
  local path="$1"
  if [ -e "$path" ]; then
    log_info "Removing $path"
    run rm -f "$path"
  else
    log_verbose "Not present: $path"
  fi
}

remove_dir_if_exists() {
  local path="$1"
  if [ -d "$path" ]; then
    log_info "Removing directory $path"
    run rm -rf "$path"
  else
    log_verbose "Not present: $path"
  fi
}

unload_launchd() {
  if launchctl list 2>/dev/null | grep -q "\${SERVICE_LABEL}"; then
    log_info "Unloading \${SERVICE_LABEL}"
    run launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || run launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
  else
    log_verbose "Launchd job not loaded: \${SERVICE_LABEL}"
  fi
}

confirm_purge() {
  if [ "$PURGE" != "true" ]; then
    return 0
  fi
  if [ "$YES" = "true" ]; then
    return 0
  fi

  cat >&2 <<EOF
\${YELLOW}[WARNING]\${NC} --purge will delete:
  - CONFIG_DIR: $CONFIG_DIR
  - STATE_DIR:  $STATE_DIR
  - Logs:       $LOG_DIR/certctrl.log and $LOG_DIR/certctrl.err.log (if present)

This may remove certificates, state, and configuration.
EOF

  printf "Type 'purge' to continue: " >&2
  local answer=""
  read -r answer
  if [ "$answer" != "purge" ]; then
    die "Purge cancelled."
  fi
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --install-dir) INSTALL_DIR="$2"; shift 2;;
      --service-label) SERVICE_LABEL="$2"; PLIST_PATH="/Library/LaunchDaemons/\${SERVICE_LABEL}.plist"; shift 2;;
      --config-dir) CONFIG_DIR="$2"; shift 2;;
      --state-dir) STATE_DIR="$2"; shift 2;;
      --log-dir) LOG_DIR="$2"; shift 2;;
      --purge) PURGE="true"; shift;;
      --yes) YES="true"; shift;;
      --dry-run) DRY_RUN="true"; shift;;
      --verbose) VERBOSE="true"; shift;;
      -h|--help) usage; exit 0;;
      *) die "Unknown argument: $1 (try --help)";;
    esac
  done
}

main() {
  parse_args "$@"

  log_info "Starting cert-ctrl uninstall (macOS)"
  log_info "Service label: $SERVICE_LABEL"
  log_info "Plist path: $PLIST_PATH"

  unload_launchd
  remove_file_if_exists "$PLIST_PATH"
  remove_file_if_exists "$INSTALL_DIR/cert-ctrl"

  confirm_purge
  if [ "$PURGE" = "true" ]; then
    if [ -n "$CONFIG_DIR" ]; then remove_dir_if_exists "$CONFIG_DIR"; fi
    if [ -n "$STATE_DIR" ]; then remove_dir_if_exists "$STATE_DIR"; fi
    remove_file_if_exists "$LOG_DIR/certctrl.log"
    remove_file_if_exists "$LOG_DIR/certctrl.err.log"
  else
    log_info "Leaving config/state/logs in place (use --purge to remove)"
  fi

  log_success "Uninstall complete."
}

main "$@"
`;