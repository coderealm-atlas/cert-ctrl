#!/bin/bash
# install.sh - Universal installer for cert-ctrl
# Usage: curl -fsSL https://install.cert-ctrl.com/install.sh | bash
# Or: sudo curl -fsSL https://install.cert-ctrl.com/install.sh | sudo bash -s -- --version=v1.0.0

set -euo pipefail

# Configuration
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"
FORCE="${FORCE:-false}"
USER_INSTALL="${USER_INSTALL:-false}"
VERBOSE="${VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1"
    fi
}

# Platform detection
detect_platform() {
    local platform=""
    local arch=""
    
    case "$(uname -s)" in
        Linux*)     platform="linux" ;;
        Darwin*)    platform="macos" ;;
        CYGWIN*|MINGW*|MSYS*) 
            log_error "Windows detected. Please use the PowerShell installer instead:"
            log_error "iwr -useb https://install.cert-ctrl.com/install.ps1 | iex"
            exit 1
            ;;
        *)          
            log_error "Unsupported platform: $(uname -s)"
            exit 1 
            ;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64)   arch="x64" ;;
        aarch64|arm64)  arch="arm64" ;;
        armv7l)         arch="arm" ;;
        *)              
            log_error "Unsupported architecture: $(uname -m)"
            exit 1 
            ;;
    esac
    
    echo "${platform}-${arch}"
}

# Check dependencies
check_dependencies() {
    local deps=("curl" "tar")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "Required dependency '$dep' is not installed."
            log_error "Please install $dep and try again."
            exit 1
        fi
    done
    
    log_verbose "All dependencies are available"
}

# Check if running as root when needed
check_permissions() {
    if [ "$USER_INSTALL" = "false" ] && [ ! -w "$INSTALL_DIR" ]; then
        if [ "$EUID" -ne 0 ]; then
            log_error "Installation requires root privileges."
            exit 1
        fi
    fi
}

# Resolve version
resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        log_info "Resolving latest version..."
        local latest_url="https://api.github.com/repos/coderealm-atlas/cert-ctrl/releases/latest"
        
        if command -v jq &> /dev/null; then
            VERSION=$(curl -fsSL "$latest_url" | jq -r '.tag_name')
        else
            # Fallback without jq
            VERSION=$(curl -fsSL "$latest_url" | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
        fi
        
        if [ -z "$VERSION" ] || [ "$VERSION" = "null" ]; then
            log_error "Failed to resolve latest version"
            exit 1
        fi
        
        log_verbose "Resolved latest version: $VERSION"
    fi
}

# Download and verify
download_binary() {
    local platform_arch="$1"
    local download_url="https://github.com/coderealm-atlas/cert-ctrl/releases/download/${VERSION}/cert-ctrl-${platform_arch}.tar.gz"
    local temp_file=$(mktemp)
    local sig_url="${download_url}.sig"
    local sig_file="${temp_file}.sig"
    
    log_info "Downloading cert-ctrl ${VERSION} for ${platform_arch}..."
    log_verbose "Download URL: $download_url"
    
    # Download binary
    if ! curl -fsSL "$download_url" -o "$temp_file"; then
        log_error "Failed to download cert-ctrl from $download_url"
        rm -f "$temp_file"
        exit 1
    fi
    
    # Download signature if available
    if curl -fsSL "$sig_url" -o "$sig_file" 2>/dev/null; then
        log_verbose "Downloaded signature file"
        
        # Verify signature if gpg is available
        if command -v gpg &> /dev/null; then
            log_info "Verifying signature..."
            if gpg --verify "$sig_file" "$temp_file" 2>/dev/null; then
                log_success "Signature verification passed"
            else
                log_warning "Signature verification failed or key not available"
                log_warning "Proceeding without verification (not recommended for production)"
            fi
        else
            log_warning "GPG not available for signature verification"
        fi
        
        rm -f "$sig_file"
    else
        log_verbose "No signature file available"
    fi
    
    echo "$temp_file"
}

# Install binary
install_binary() {
    local temp_file="$1"
    local platform_arch="$2"
    
    # Set install directory for user install
    if [ "$USER_INSTALL" = "true" ]; then
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        log_verbose "Using user install directory: $INSTALL_DIR"
    fi
    
    log_info "Installing to $INSTALL_DIR..."
    
    # Extract
    local extract_dir=$(mktemp -d)
    if ! tar -xzf "$temp_file" -C "$extract_dir"; then
        log_error "Failed to extract downloaded file"
        rm -rf "$extract_dir"
        exit 1
    fi
    
    # Find the binary (handle different archive structures)
    local binary_path=""
    if [ -f "$extract_dir/cert-ctrl" ]; then
        binary_path="$extract_dir/cert-ctrl"
    elif [ -f "$extract_dir/bin/cert-ctrl" ]; then
        binary_path="$extract_dir/bin/cert-ctrl"
    else
        log_error "cert-ctrl binary not found in downloaded archive"
        rm -rf "$extract_dir"
        exit 1
    fi
    
    # Make executable
    chmod +x "$binary_path"
    
    # Check if binary already exists
    if [ -f "$INSTALL_DIR/cert-ctrl" ] && [ "$FORCE" = "false" ]; then
        log_warning "cert-ctrl is already installed at $INSTALL_DIR/cert-ctrl"
        read -p "Do you want to overwrite it? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installation cancelled"
            rm -rf "$extract_dir"
            exit 0
        fi
    fi
    
    # Install
    if ! cp "$binary_path" "$INSTALL_DIR/cert-ctrl"; then
        log_error "Failed to install cert-ctrl to $INSTALL_DIR"
        rm -rf "$extract_dir"
        exit 1
    fi
    
    # Cleanup
    rm -rf "$extract_dir"
    
    log_success "cert-ctrl installed successfully to $INSTALL_DIR/cert-ctrl"
}

# Setup PATH
setup_path() {
    if [ "$USER_INSTALL" = "true" ]; then
        local shell_rc=""
        
        # Detect shell and set appropriate rc file
        case "$SHELL" in
            */bash)  shell_rc="$HOME/.bashrc" ;;
            */zsh)   shell_rc="$HOME/.zshrc" ;;
            */fish)  shell_rc="$HOME/.config/fish/config.fish" ;;
            *)       shell_rc="$HOME/.profile" ;;
        esac
        
        # Check if PATH already includes install directory
        if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
            log_info "Adding $INSTALL_DIR to PATH in $shell_rc"
            
            if [[ "$shell_rc" == *"fish"* ]]; then
                echo "set -gx PATH $INSTALL_DIR \$PATH" >> "$shell_rc"
            else
                echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$shell_rc"
            fi
            
            log_warning "Please restart your shell or run: source $shell_rc"
        fi
    fi
}

# Verify installation
verify_installation() {
    local binary_path="$INSTALL_DIR/cert-ctrl"
    
    if [ ! -f "$binary_path" ]; then
        log_error "Installation verification failed: binary not found at $binary_path"
        exit 1
    fi
    
    if [ ! -x "$binary_path" ]; then
        log_error "Installation verification failed: binary is not executable"
        exit 1
    fi
    
    # Test if binary runs
    log_info "Verifying installation..."
    if "$binary_path" --version &>/dev/null; then
        local installed_version=$("$binary_path" --version 2>/dev/null | head -n1 || echo "unknown")
        log_success "Installation verified! Installed version: $installed_version"
    else
        log_warning "Binary installed but version check failed"
        log_warning "This might be normal if this is the first run"
    fi

    check_runtime_dependencies "$binary_path"
}

# Show completion message
show_completion() {
    echo
    log_success "cert-ctrl installation completed!"
    echo
    echo "Next steps:"
    if [ "$USER_INSTALL" = "true" ] && [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo "  1. Restart your shell or run: source ~/.bashrc (or equivalent)"
        echo "  2. Run: cert-ctrl --help"
    else
        echo "  1. Run: cert-ctrl --help"
    fi
    echo
    echo "Documentation: https://github.com/coderealm-atlas/cert-ctrl/blob/main/README.md"
    echo "Report issues: https://github.com/coderealm-atlas/cert-ctrl/issues"
    echo
}

# Show help
show_help() {
    cat << EOF
cert-ctrl installer

Usage: $0 [OPTIONS]

Options:
    --version VERSION       Install specific version (default: latest)
    --install-dir DIR      Custom installation directory
    --force                Overwrite existing installation
    --verbose              Enable verbose output
    --help                 Show this help message

Examples:
    # Install latest version to /usr/local/bin (requires sudo)
    $0

    # Install specific version
    sudo $0 --version v1.2.3

    # Install to custom directory
    $0 --install-dir /opt/cert-ctrl

Environment variables:
    INSTALL_DIR            Installation directory
    VERSION                Version to install
    FORCE                  Force overwrite (true/false)
    USER_INSTALL           User installation (true/false)
    VERBOSE                Verbose output (true/false)

EOF
}

# Main installation function
main() {
    log_info "Starting cert-ctrl installation..."
    
    # Check dependencies
    check_dependencies
    
    # Detect platform
    local platform_arch=$(detect_platform)
    log_verbose "Detected platform: $platform_arch"
    
    # Resolve version
    resolve_version
    
    # Check permissions
    check_permissions
    
    # Download
    local temp_file=$(download_binary "$platform_arch")
    
    # Install
    install_binary "$temp_file" "$platform_arch"
    
    # Cleanup
    rm -f "$temp_file"
    
    # Setup PATH
    setup_path
    
    # Verify
    verify_installation
    
    # Show completion
    show_completion
}

check_runtime_dependencies() {
    local binary_path="$1"

    if [ -z "$binary_path" ] || [ ! -x "$binary_path" ]; then
        return 0
    fi

    if ! command -v ldd &>/dev/null; then
        log_verbose "Skipping runtime dependency check (ldd not available)"
        return 0
    fi

    local missing
    missing=$(ldd "$binary_path" 2>&1 | awk '/not found/ {print $0}')
    if [ -n "$missing" ]; then
        log_warning "Detected missing runtime dependencies:"
        printf '%s\n' "$missing"
        log_warning "Please install the packages that supply the libraries above before running cert-ctrl."
    else
        log_verbose "All required shared libraries are available"
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            if [ -z "${2:-}" ]; then
                log_error "Version parameter requires a value"
                exit 1
            fi
            VERSION="$2"
            shift 2
            ;;
        --install-dir)
            if [ -z "${2:-}" ]; then
                log_error "Install directory parameter requires a value"
                exit 1
            fi
            INSTALL_DIR="$2"
            shift 2
            ;;
        --force)
            FORCE="true"
            shift
            ;;
        --verbose)
            VERBOSE="true"
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            log_error "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main installation
main