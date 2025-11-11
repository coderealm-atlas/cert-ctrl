export const macosTemplate = `#!/bin/bash
# cert-ctrl macOS installation script for system-wide launchd service

set -euo pipefail

if [[ \${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[ERROR] Run this installer with sudo or as root." >&2
    exit 1
fi

REPO_OWNER="{{GITHUB_REPO_OWNER}}"
REPO_NAME="{{GITHUB_REPO_NAME}}"
VERSION="{{VERSION}}"
BASE_URL="{{BASE_URL}}"
MIRROR_URL="{{MIRROR_URL}}"
INSTALL_DIR="\${INSTALL_DIR:-{{INSTALL_DIR}}}"
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="/usr/local/bin"
fi
CONFIG_DIR="\${CONFIG_DIR:-{{CONFIG_DIR}}}"
STATE_DIR="\${STATE_DIR:-{{STATE_DIR}}}"
LOG_DIR="\${LOG_DIR:-/var/log}"
SERVICE_LABEL="\${SERVICE_LABEL:-{{SERVICE_LABEL}}}"
PLIST_PATH="/Library/LaunchDaemons/\${SERVICE_LABEL}.plist"
DOWNLOAD_OS="macos"
FORCE="\${FORCE:-{{FORCE}}}"
RED='\x1b[0;31m'
GREEN='\x1b[0;32m'
BLUE='\x1b[0;34m'
YELLOW='\x1b[1;33m'
NC='\x1b[0m'
SHA256_CMD=()
ARCHIVE_TMPDIR=""

die() {
    echo -e "\${RED}[ERROR]\${NC} $1" >&2
    exit 1
}

log_info() {
    echo -e "\${BLUE}[INFO]\${NC} $1" >&2
}

log_success() {
    echo -e "\${GREEN}[SUCCESS]\${NC} $1" >&2
}

log_warn() {
    echo -e "\${YELLOW}[WARNING]\${NC} $1" >&2
}

get_installed_version() {
    local binary_path="$1"

    if [ ! -x "$binary_path" ]; then
        echo ""
        return 0
    fi

    local version_output=""
    if version_output=$("$binary_path" --version 2>/dev/null); then
        version_output=$(printf '%s\n' "$version_output" | head -n1)
    else
        version_output=""
    fi

    echo "$version_output"
}

maybe_skip_install() {
    local requested_version="$1"
    local binary_path="\${INSTALL_DIR}/cert-ctrl"

    if [ "\${FORCE}" = "true" ]; then
        log_info "Force install requested; continuing even if version matches."
        return 0
    fi

    if [ ! -x "$binary_path" ]; then
        return 0
    fi

    local installed_version
    installed_version=$(get_installed_version "$binary_path")

    if [ -z "$installed_version" ]; then
        log_warn "Existing cert-ctrl binary found but version could not be determined; continuing with reinstall."
        return 0
    fi

    local requested_trim="\${requested_version#v}"
    local installed_trim="\${installed_version#v}"

    if [ "$installed_trim" = "$requested_trim" ]; then
    log_success "cert-ctrl \${installed_version} is already installed at $binary_path"
    log_info ""
    log_info "To reinstall anyway, choose one of the following:"
        log_info "  1. URL parameter:   curl -fsSL \"\${BASE_URL}/install-macos.sh?force=1\" | sudo bash"
        log_info "  2. Environment var: FORCE=true curl -fsSL \"\${BASE_URL}/install-macos.sh\" | sudo -E bash"
    log_info "  3. Remove existing: sudo rm \"$binary_path\" && curl -fsSL \"\${BASE_URL}/install-macos.sh?force=1\" | sudo bash"
        exit 0
    fi

    log_info "Existing install version \${installed_version} differs from requested \${requested_version}; continuing with upgrade."
}

check_dependencies() {
    local deps=("curl" "tar" "gzip")
    for dep in "\${deps[@]}"; do
        command -v "$dep" >/dev/null 2>&1 || die "Required dependency '$dep' is not installed."
    done

    if command -v sha256sum >/dev/null 2>&1; then
        SHA256_CMD=(sha256sum)
    elif command -v shasum >/dev/null 2>&1; then
        SHA256_CMD=(shasum -a 256)
    else
        die "Install coreutils (brew install coreutils) to obtain sha256sum or shasum."
    fi
}

detect_arch() {
    case "$(uname -m)" in
        arm64) echo "arm64" ;;
        x86_64) echo "x64" ;;
        *) die "Unsupported architecture $(uname -m)" ;;
    esac
}

resolve_version() {
    if [[ "$VERSION" != "latest" ]]; then
        echo "$VERSION"
        return
    fi

    local api="https://api.github.com/repos/\${REPO_OWNER}/\${REPO_NAME}/releases/latest"
    if command -v jq >/dev/null 2>&1; then
        curl -fsSL "$api" | jq -r '.tag_name' || die "Failed to resolve latest version via GitHub API."
    else
        curl -fsSL "$api" | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": "([^"]+)".*/\\1/' || die "Failed to parse latest version."
    fi
}

download_archive() {
    local version="$1"
    local arch="$2"
    local temp_dir
    temp_dir=$(mktemp -d)
    ARCHIVE_TMPDIR="$temp_dir"
    local archive="\${temp_dir}/cert-ctrl.tar.gz"
    local checksum="\${archive}.sha256"
    local tarball="cert-ctrl-\${DOWNLOAD_OS}-\${arch}.tar.gz"
    local base_url=""

    if [ "$MIRROR_URL" = "$BASE_URL/releases/proxy" ]; then
        base_url="$MIRROR_URL/$version"
    else
        base_url="$MIRROR_URL/\${REPO_OWNER}/\${REPO_NAME}/releases/download/$version"
    fi

    log_info "Downloading \${tarball} ($version)"
    curl -fsSL "\${base_url}/\${tarball}" -o "$archive" || die "Failed to download archive."

    log_info "Downloading checksum"
    if curl -fsSL "\${base_url}/\${tarball}.sha256" -o "$checksum"; then
        local expected
        expected=$(awk 'NF>=1 {print $1; exit}' "$checksum")
        local actual_output
        actual_output=$("\${SHA256_CMD[@]}" "$archive")
        local actual=\${actual_output%% *}
        [[ -z "$expected" ]] && die "Checksum file is empty."
        if [[ "$expected" != "$actual" ]]; then
            die "Checksum mismatch (expected $expected, got $actual)."
        fi
        log_success "Checksum verified."
    else
        log_warn "Checksum file unavailable; skipping verification."
    fi

    echo "$archive"
}

install_binary() {
    local archive="$1"
    local temp_extract
    temp_extract=$(mktemp -d)
    tar -xzf "$archive" -C "$temp_extract" || die "Failed to extract archive."

    local binary_path
    if [[ -f "\${temp_extract}/cert-ctrl" ]]; then
        binary_path="\${temp_extract}/cert-ctrl"
    elif [[ -f "\${temp_extract}/bin/cert-ctrl" ]]; then
        binary_path="\${temp_extract}/bin/cert-ctrl"
    else
        die "cert-ctrl binary not found inside archive."
    fi

    mkdir -p "$INSTALL_DIR"
    install -m 755 "$binary_path" "\${INSTALL_DIR}/cert-ctrl"
    log_success "Installed cert-ctrl to \${INSTALL_DIR}."
}

prepare_directories() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$STATE_DIR"
    chmod 755 "$CONFIG_DIR" "$STATE_DIR"
    log_info "Configuration directory: $CONFIG_DIR"
    log_info "State directory: $STATE_DIR"

    mkdir -p "$LOG_DIR"
    : > "\${LOG_DIR}/certctrl.log"
    : > "\${LOG_DIR}/certctrl.err.log"
    chmod 644 "\${LOG_DIR}/certctrl.log" "\${LOG_DIR}/certctrl.err.log"
}

write_launchd_plist() {
    cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>\${SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>\${INSTALL_DIR}/cert-ctrl</string>
        <string>--config-dirs</string>
        <string>\${CONFIG_DIR}</string>
        <string>--keep-running</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>CERTCTRL_STATE_DIR</key>
        <string>\${STATE_DIR}</string>
    </dict>
    <key>WorkingDirectory</key>
    <string>\${CONFIG_DIR}</string>
    <key>StandardOutPath</key>
    <string>\${LOG_DIR}/certctrl.log</string>
    <key>StandardErrorPath</key>
    <string>\${LOG_DIR}/certctrl.err.log</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF
    chown root:wheel "$PLIST_PATH"
    chmod 644 "$PLIST_PATH"
    log_success "LaunchDaemon written to \${PLIST_PATH}."
}

reload_service() {
    if launchctl list | grep -q "\${SERVICE_LABEL}"; then
        log_info "Unloading existing service \${SERVICE_LABEL}."
        launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
    fi

    log_info "Loading service \${SERVICE_LABEL}."
    if launchctl bootstrap system "$PLIST_PATH" >/dev/null 2>&1; then
        launchctl enable system/\${SERVICE_LABEL} >/dev/null 2>&1 || true
        launchctl kickstart -k system/\${SERVICE_LABEL} >/dev/null 2>&1 || true
    log_success "Service \${SERVICE_LABEL} started."
    else
        launchctl load "$PLIST_PATH" >/dev/null 2>&1 || die "Failed to load LaunchDaemon."
        log_warn "Service loaded via legacy launchctl load; verify status manually."
    fi
}

print_next_steps() {
    echo
    log_success "cert-ctrl installation complete."
    echo "Next steps:" >&2
    echo "  - Check status: sudo launchctl print system/\${SERVICE_LABEL}" >&2
    echo "  - View logs: tail -f \${LOG_DIR}/certctrl.log" >&2
    echo "  - Stop service: sudo launchctl bootout system \${PLIST_PATH}" >&2
    echo "  - Start service: sudo launchctl bootstrap system \${PLIST_PATH}" >&2
}

main() {
    log_info "Starting cert-ctrl macOS installation..."
    check_dependencies
    local arch
    arch=$(detect_arch)
    local version
    version=$(resolve_version)
    maybe_skip_install "$version"
    local archive
    archive=$(download_archive "$version" "$arch")
    install_binary "$archive"
    prepare_directories
    write_launchd_plist
    reload_service
    rm -f "$archive" "$archive.sha256" 2>/dev/null || true
    if [[ -n "$ARCHIVE_TMPDIR" ]]; then
        rm -rf "$ARCHIVE_TMPDIR"
    fi
    print_next_steps
}

main "$@"
`;
