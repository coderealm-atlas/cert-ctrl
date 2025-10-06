#!/bin/bash
# update.sh - Update script for cert-ctrl
# This script handles in-place updates of cert-ctrl binary

set -euo pipefail

# Configuration
BACKUP_DIR="${HOME}/.cert-ctrl/backups"
CONFIG_FILE="${HOME}/.cert-ctrl/config.json"
CURRENT_BINARY=""
VERSION=""
FORCE=false
DRY_RUN=false
VERBOSE=false
ROLLBACK=false
BACKUP_COUNT=5

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_verbose() { [ "$VERBOSE" = "true" ] && echo -e "${BLUE}[VERBOSE]${NC} $1"; }

# Find current cert-ctrl binary
find_current_binary() {
    if command -v cert-ctrl &> /dev/null; then
        CURRENT_BINARY=$(command -v cert-ctrl)
        log_verbose "Found cert-ctrl at: $CURRENT_BINARY"
    else
        log_error "cert-ctrl not found in PATH"
        exit 1
    fi
}

# Get current version
get_current_version() {
    if [ -f "$CURRENT_BINARY" ]; then
        local version=$("$CURRENT_BINARY" --version 2>/dev/null | head -n1 || echo "unknown")
        echo "$version"
    else
        echo "unknown"
    fi
}

# Check for updates
check_updates() {
    log_info "Checking for updates..."
    
    local current_version=$(get_current_version)
    log_verbose "Current version: $current_version"
    
    # Get latest version from GitHub API
    local latest_url="https://api.github.com/repos/coderealm-atlas/cert-ctrl/releases/latest"
    local latest_version=""
    
    if command -v jq &> /dev/null; then
        latest_version=$(curl -fsSL "$latest_url" | jq -r '.tag_name')
    else
        latest_version=$(curl -fsSL "$latest_url" | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
    fi
    
    if [ -z "$latest_version" ] || [ "$latest_version" = "null" ]; then
        log_error "Failed to fetch latest version"
        exit 1
    fi
    
    log_verbose "Latest version: $latest_version"
    
    if [ "$current_version" = "$latest_version" ]; then
        log_success "cert-ctrl is already up to date ($current_version)"
        exit 0
    else
        log_info "Update available: $current_version → $latest_version"
        VERSION="$latest_version"
    fi
}

# Create backup
create_backup() {
    local current_version=$(get_current_version)
    mkdir -p "$BACKUP_DIR"
    
    local backup_file="$BACKUP_DIR/cert-ctrl-$current_version-$(date +%Y%m%d-%H%M%S)"
    
    log_info "Creating backup..."
    if cp "$CURRENT_BINARY" "$backup_file"; then
        log_success "Backup created: $backup_file"
        
        # Cleanup old backups (keep only latest BACKUP_COUNT)
        find "$BACKUP_DIR" -name "cert-ctrl-*" -type f | sort -r | tail -n +$((BACKUP_COUNT + 1)) | xargs rm -f
        
        echo "$backup_file"
    else
        log_error "Failed to create backup"
        exit 1
    fi
}

# Download new version
download_update() {
    local version="$1"
    local platform_arch=$(detect_platform)
    local download_url="https://github.com/coderealm-atlas/cert-ctrl/releases/download/${version}/cert-ctrl-${platform_arch}.tar.gz"
    local temp_file=$(mktemp)
    
    log_info "Downloading cert-ctrl $version..."
    log_verbose "Download URL: $download_url"
    
    if curl -fsSL "$download_url" -o "$temp_file"; then
        echo "$temp_file"
    else
        log_error "Failed to download update"
        rm -f "$temp_file"
        exit 1
    fi
}

# Verify downloaded binary
verify_binary() {
    local temp_file="$1"
    
    # Extract and verify
    local extract_dir=$(mktemp -d)
    if tar -xzf "$temp_file" -C "$extract_dir"; then
        local binary_path=""
        if [ -f "$extract_dir/cert-ctrl" ]; then
            binary_path="$extract_dir/cert-ctrl"
        elif [ -f "$extract_dir/bin/cert-ctrl" ]; then
            binary_path="$extract_dir/bin/cert-ctrl"
        fi
        
        if [ -n "$binary_path" ] && [ -x "$binary_path" ]; then
            # Test if binary works
            if "$binary_path" --version &>/dev/null; then
                echo "$binary_path"
                return 0
            fi
        fi
    fi
    
    rm -rf "$extract_dir"
    return 1
}

# Apply update
apply_update() {
    local new_binary="$1"
    local backup_file="$2"
    
    log_info "Applying update..."
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN: Would replace $CURRENT_BINARY with $new_binary"
        return 0
    fi
    
    # Check if we have write permission
    if [ ! -w "$CURRENT_BINARY" ]; then
        log_error "No write permission for $CURRENT_BINARY"
        log_error "Try running with sudo or contact your administrator"
        return 1
    fi
    
    # Replace binary
    if cp "$new_binary" "$CURRENT_BINARY"; then
        chmod +x "$CURRENT_BINARY"
        log_success "Update applied successfully"
        
        # Verify new installation
        local new_version=$("$CURRENT_BINARY" --version 2>/dev/null | head -n1 || echo "unknown")
        log_success "Updated to version: $new_version"
        
        return 0
    else
        log_error "Failed to apply update"
        
        # Attempt rollback
        if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
            log_warning "Attempting rollback..."
            if cp "$backup_file" "$CURRENT_BINARY"; then
                log_warning "Rollback successful"
            else
                log_error "Rollback failed - manual intervention required"
            fi
        fi
        
        return 1
    fi
}

# Rollback to previous version
rollback_version() {
    log_info "Looking for backup versions..."
    
    if [ ! -d "$BACKUP_DIR" ]; then
        log_error "No backup directory found"
        exit 1
    fi
    
    local latest_backup=$(find "$BACKUP_DIR" -name "cert-ctrl-*" -type f | sort -r | head -n1)
    
    if [ -z "$latest_backup" ]; then
        log_error "No backup versions found"
        exit 1
    fi
    
    log_info "Rolling back to: $(basename "$latest_backup")"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN: Would rollback to $latest_backup"
        return 0
    fi
    
    if cp "$latest_backup" "$CURRENT_BINARY"; then
        chmod +x "$CURRENT_BINARY"
        local version=$("$CURRENT_BINARY" --version 2>/dev/null | head -n1 || echo "unknown")
        log_success "Rollback successful to version: $version"
    else
        log_error "Rollback failed"
        exit 1
    fi
}

# Platform detection (same as install script)
detect_platform() {
    local platform=""
    local arch=""
    
    case "$(uname -s)" in
        Linux*)     platform="linux" ;;
        Darwin*)    platform="macos" ;;
        *)          log_error "Unsupported platform: $(uname -s)"; exit 1 ;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64)   arch="x64" ;;
        aarch64|arm64)  arch="arm64" ;;
        armv7l)         arch="arm" ;;
        *)              log_error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    
    echo "${platform}-${arch}"
}

# Show help
show_help() {
    cat << EOF
cert-ctrl update script

Usage: $0 [OPTIONS]

Options:
    --version VERSION       Update to specific version
    --check                 Check for updates without installing
    --force                 Force update even if already up to date
    --dry-run              Show what would be done without applying changes
    --rollback             Rollback to previous version
    --verbose              Enable verbose output
    --help                 Show this help message

Examples:
    # Check and apply available updates
    $0

    # Check for updates only
    $0 --check

    # Update to specific version
    $0 --version v1.2.3

    # Dry run update
    $0 --dry-run

    # Rollback to previous version
    $0 --rollback

EOF
}

# Main function
main() {
    log_info "cert-ctrl update utility"
    
    # Find current binary
    find_current_binary
    
    if [ "$ROLLBACK" = "true" ]; then
        rollback_version
        exit 0
    fi
    
    # Check for updates
    check_updates
    
    if [ -z "$VERSION" ]; then
        log_success "No updates available"
        exit 0
    fi
    
    # Download update
    local temp_file=$(download_update "$VERSION")
    local backup_file=""
    
    # Verify binary
    log_info "Verifying downloaded binary..."
    local new_binary=$(verify_binary "$temp_file")
    
    if [ -z "$new_binary" ]; then
        log_error "Binary verification failed"
        rm -f "$temp_file"
        exit 1
    fi
    
    log_success "Binary verification passed"
    
    # Create backup
    backup_file=$(create_backup)
    
    # Apply update
    if apply_update "$new_binary" "$backup_file"; then
        log_success "Update completed successfully"
    else
        log_error "Update failed"
        exit 1
    fi
    
    # Cleanup
    rm -f "$temp_file"
    rm -rf "$(dirname "$new_binary")"
}

# Parse arguments
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --rollback)
            ROLLBACK=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Run main function
if [ "$CHECK_ONLY" = "true" ]; then
    check_updates
else
    main
fi