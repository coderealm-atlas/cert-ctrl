#!/bin/bash
# package.sh - Package creation script for cert-ctrl
# Creates distribution packages for different platforms and package managers

set -euo pipefail

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
DIST_DIR="$PROJECT_ROOT/dist"
VERSION=""
PLATFORMS=()
PACKAGE_TYPES=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Get version from git or CMake
get_version() {
    if [ -n "$VERSION" ]; then
        echo "$VERSION"
        return
    fi
    
    # Try git describe first
    if git describe --tags --exact-match HEAD 2>/dev/null; then
        return
    fi
    
    # Try git describe with long format
    if git describe --tags --long --dirty --match "v*" 2>/dev/null; then
        return
    fi
    
    # Fallback to git rev-parse
    local short_sha=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    echo "v0.0.0-dev-$short_sha"
}

# Detect platform
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

# Build binary for platform
build_binary() {
    local platform="$1"
    local build_type="${2:-Release}"
    
    log_info "Building binary for $platform ($build_type)..."
    
    local preset=""
    case "$platform" in
        linux-*)
            preset="release"
            ;;
        macos-*)
            preset="release"  # Assuming similar preset exists
            ;;
        windows-*)
            preset="windows-release"
            ;;
        *)
            log_error "Unknown platform: $platform"
            return 1
            ;;
    esac
    
    # Configure and build
    cmake --preset "$preset"
    cmake --build --preset "$preset"
    
    # Find the built binary
    local binary_path=""
    case "$platform" in
        windows-*)
            binary_path="$BUILD_DIR/windows-release/cert_ctrl.exe"
            ;;
        *)
            binary_path="$BUILD_DIR/release/cert_ctrl"
            ;;
    esac
    
    if [ ! -f "$binary_path" ]; then
        log_error "Built binary not found at: $binary_path"
        return 1
    fi
    
    echo "$binary_path"
}

# Create tarball package
create_tarball() {
    local platform="$1"
    local binary_path="$2"
    local version="$3"
    
    log_info "Creating tarball for $platform..."
    
    local package_dir="$DIST_DIR/cert-ctrl-$version-$platform"
    local tarball_name="cert-ctrl-$version-$platform.tar.gz"
    
    mkdir -p "$package_dir"
    
    # Copy binary
    case "$platform" in
        windows-*)
            cp "$binary_path" "$package_dir/cert-ctrl.exe"
            ;;
        *)
            cp "$binary_path" "$package_dir/cert-ctrl"
            chmod +x "$package_dir/cert-ctrl"
            ;;
    esac
    
    # Copy documentation
    [ -f "$PROJECT_ROOT/README.md" ] && cp "$PROJECT_ROOT/README.md" "$package_dir/"
    [ -f "$PROJECT_ROOT/LICENSE" ] && cp "$PROJECT_ROOT/LICENSE" "$package_dir/"
    [ -f "$PROJECT_ROOT/CHANGELOG.md" ] && cp "$PROJECT_ROOT/CHANGELOG.md" "$package_dir/"
    
    # Copy config templates
    if [ -d "$PROJECT_ROOT/config_dir" ]; then
        mkdir -p "$package_dir/config"
        cp "$PROJECT_ROOT/config_dir"/*.tpl "$package_dir/config/" 2>/dev/null || true
    fi
    
    # Create install script
    case "$platform" in
        windows-*)
            cat > "$package_dir/install.bat" << 'EOF'
@echo off
echo Installing cert-ctrl...
copy cert-ctrl.exe "%LOCALAPPDATA%\Programs\CertCtrl\cert-ctrl.exe"
echo Installation complete!
echo Add %LOCALAPPDATA%\Programs\CertCtrl to your PATH
pause
EOF
            ;;
        *)
            cat > "$package_dir/install.sh" << 'EOF'
#!/bin/bash
echo "Installing cert-ctrl..."
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"
cp cert-ctrl "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/cert-ctrl"
echo "Installation complete!"
echo "Make sure $INSTALL_DIR is in your PATH"
EOF
            chmod +x "$package_dir/install.sh"
            ;;
    esac
    
    # Create tarball
    (cd "$DIST_DIR" && tar -czf "$tarball_name" "$(basename "$package_dir")")
    
    # Cleanup temp directory
    rm -rf "$package_dir"
    
    log_success "Created: $DIST_DIR/$tarball_name"
}

# Create ZIP package (mainly for Windows)
create_zip() {
    local platform="$1"
    local binary_path="$2"
    local version="$3"
    
    log_info "Creating ZIP package for $platform..."
    
    local package_dir="$DIST_DIR/cert-ctrl-$version-$platform"
    local zip_name="cert-ctrl-$version-$platform.zip"
    
    mkdir -p "$package_dir"
    
    # Copy files (similar to tarball)
    cp "$binary_path" "$package_dir/cert-ctrl.exe"
    [ -f "$PROJECT_ROOT/README.md" ] && cp "$PROJECT_ROOT/README.md" "$package_dir/"
    [ -f "$PROJECT_ROOT/LICENSE" ] && cp "$PROJECT_ROOT/LICENSE" "$package_dir/"
    
    # Create ZIP
    if command -v zip &> /dev/null; then
        (cd "$DIST_DIR" && zip -r "$zip_name" "$(basename "$package_dir")")
    else
        log_warning "zip command not available, skipping ZIP creation"
        return 1
    fi
    
    # Cleanup
    rm -rf "$package_dir"
    
    log_success "Created: $DIST_DIR/$zip_name"
}

# Create DEB package
create_deb() {
    local platform="$1"
    local binary_path="$2"
    local version="$3"
    
    if ! command -v dpkg-deb &> /dev/null; then
        log_warning "dpkg-deb not available, skipping DEB package creation"
        return 1
    fi
    
    log_info "Creating DEB package for $platform..."
    
    # Clean version for DEB (remove v prefix)
    local deb_version="${version#v}"
    local package_dir="$DIST_DIR/cert-ctrl-$deb_version-$platform-deb"
    local deb_name="cert-ctrl_${deb_version}_amd64.deb"
    
    # Create package structure
    mkdir -p "$package_dir/DEBIAN"
    mkdir -p "$package_dir/usr/bin"
    mkdir -p "$package_dir/usr/share/doc/cert-ctrl"
    
    # Copy binary
    cp "$binary_path" "$package_dir/usr/bin/cert-ctrl"
    chmod +x "$package_dir/usr/bin/cert-ctrl"
    
    # Copy documentation
    [ -f "$PROJECT_ROOT/README.md" ] && cp "$PROJECT_ROOT/README.md" "$package_dir/usr/share/doc/cert-ctrl/"
    [ -f "$PROJECT_ROOT/LICENSE" ] && cp "$PROJECT_ROOT/LICENSE" "$package_dir/usr/share/doc/cert-ctrl/"
    
    # Create control file
    cat > "$package_dir/DEBIAN/control" << EOF
Package: cert-ctrl
Version: $deb_version
Section: utils
Priority: optional
Architecture: amd64
Maintainer: CertCtrl Team <info@cert-ctrl.com>
Description: Certificate control and management utility
 A comprehensive tool for certificate management, validation, and control
 operations. Supports various certificate formats and provides automated
 certificate lifecycle management capabilities.
Homepage: https://github.com/coderealm-atlas/cert-ctrl
EOF
    
    # Create postinst script
    cat > "$package_dir/DEBIAN/postinst" << 'EOF'
#!/bin/bash
echo "cert-ctrl installed successfully!"
echo "Run 'cert-ctrl --help' to get started."
EOF
    chmod +x "$package_dir/DEBIAN/postinst"
    
    # Build DEB package
    dpkg-deb --build "$package_dir" "$DIST_DIR/$deb_name"
    
    # Cleanup
    rm -rf "$package_dir"
    
    log_success "Created: $DIST_DIR/$deb_name"
}

# Create RPM package
create_rpm() {
    local platform="$1"
    local binary_path="$2"
    local version="$3"
    
    if ! command -v rpmbuild &> /dev/null; then
        log_warning "rpmbuild not available, skipping RPM package creation"
        return 1
    fi
    
    log_info "Creating RPM package for $platform..."
    
    # Clean version for RPM
    local rpm_version="${version#v}"
    local rpm_dir="$DIST_DIR/rpm"
    local spec_file="$rpm_dir/cert-ctrl.spec"
    
    # Create RPM build directories
    mkdir -p "$rpm_dir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    
    # Copy source
    cp "$binary_path" "$rpm_dir/SOURCES/cert-ctrl"
    
    # Create spec file
    cat > "$spec_file" << EOF
Name:           cert-ctrl
Version:        $rpm_version
Release:        1%{?dist}
Summary:        Certificate control and management utility
License:        MIT
URL:            https://github.com/coderealm-atlas/cert-ctrl
Source0:        cert-ctrl

%description
A comprehensive tool for certificate management, validation, and control
operations. Supports various certificate formats and provides automated
certificate lifecycle management capabilities.

%prep
# No prep needed for binary package

%build
# No build needed for binary package

%install
mkdir -p %{buildroot}%{_bindir}
cp %{SOURCE0} %{buildroot}%{_bindir}/cert-ctrl
chmod +x %{buildroot}%{_bindir}/cert-ctrl

%files
%{_bindir}/cert-ctrl

%changelog
* $(date +'%a %b %d %Y') CertCtrl Team <info@cert-ctrl.com> - $rpm_version-1
- Release $rpm_version
EOF
    
    # Build RPM
    rpmbuild --define "_topdir $rpm_dir" -bb "$spec_file"
    
    # Move RPM to dist directory
    find "$rpm_dir/RPMS" -name "*.rpm" -exec mv {} "$DIST_DIR/" \;
    
    # Cleanup
    rm -rf "$rpm_dir"
    
    log_success "Created RPM package in $DIST_DIR"
}

# Sign packages
sign_packages() {
    local version="$1"
    
    if [ -z "${GPG_KEY_ID:-}" ]; then
        log_warning "GPG_KEY_ID not set, skipping package signing"
        return
    fi
    
    log_info "Signing packages with key: $GPG_KEY_ID"
    
    for file in "$DIST_DIR"/cert-ctrl-"$version"-*.{tar.gz,zip,deb,rpm}; do
        if [ -f "$file" ]; then
            gpg --detach-sign --armor --default-key "$GPG_KEY_ID" "$file"
            log_success "Signed: $(basename "$file")"
        fi
    done
}

# Show help
show_help() {
    cat << EOF
cert-ctrl package creation script

Usage: $0 [OPTIONS]

Options:
    --version VERSION       Package version (default: auto-detect from git)
    --platform PLATFORM    Target platform (e.g., linux-x64, windows-x64)
    --all-platforms        Package for all supported platforms
    --type TYPE            Package type (tarball, zip, deb, rpm, all)
    --build-type TYPE      Build type (Release, Debug) [default: Release]
    --output-dir DIR       Output directory [default: ./dist]
    --sign                 Sign packages with GPG (requires GPG_KEY_ID env var)
    --help                 Show this help message

Examples:
    # Package current platform
    $0

    # Package for specific platform
    $0 --platform linux-x64 --type deb

    # Package for all platforms
    $0 --all-platforms --type all

    # Package with specific version
    $0 --version v1.2.3 --all-platforms

Environment variables:
    GPG_KEY_ID             GPG key ID for signing packages

EOF
}

# Main function
main() {
    local build_type="Release"
    local sign=false
    local all_platforms=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --platform)
                PLATFORMS+=("$2")
                shift 2
                ;;
            --all-platforms)
                all_platforms=true
                shift
                ;;
            --type)
                PACKAGE_TYPES+=("$2")
                shift 2
                ;;
            --build-type)
                build_type="$2"
                shift 2
                ;;
            --output-dir)
                DIST_DIR="$2"
                shift 2
                ;;
            --sign)
                sign=true
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
    
    # Set defaults
    if [ "$all_platforms" = true ]; then
        PLATFORMS=("linux-x64" "linux-arm64" "macos-x64" "macos-arm64" "windows-x64")
    elif [ ${#PLATFORMS[@]} -eq 0 ]; then
        PLATFORMS=("$(detect_platform)")
    fi
    
    if [ ${#PACKAGE_TYPES[@]} -eq 0 ]; then
        PACKAGE_TYPES=("tarball")
    fi
    
    # Get version
    local version=$(get_version)
    log_info "Packaging version: $version"
    
    # Create output directory
    mkdir -p "$DIST_DIR"
    
    # Package for each platform
    for platform in "${PLATFORMS[@]}"; do
        log_info "Processing platform: $platform"
        
        # Build binary
        local binary_path=$(build_binary "$platform" "$build_type")
        
        # Create packages
        for package_type in "${PACKAGE_TYPES[@]}"; do
            case "$package_type" in
                tarball|all)
                    create_tarball "$platform" "$binary_path" "$version"
                    ;;
                zip|all)
                    if [[ "$platform" == windows-* ]]; then
                        create_zip "$platform" "$binary_path" "$version"
                    fi
                    ;;
                deb|all)
                    if [[ "$platform" == linux-* ]]; then
                        create_deb "$platform" "$binary_path" "$version"
                    fi
                    ;;
                rpm|all)
                    if [[ "$platform" == linux-* ]]; then
                        create_rpm "$platform" "$binary_path" "$version"
                    fi
                    ;;
                *)
                    log_warning "Unknown package type: $package_type"
                    ;;
            esac
        done
    done
    
    # Sign packages if requested
    if [ "$sign" = true ]; then
        sign_packages "$version"
    fi
    
    log_success "Packaging completed! Output directory: $DIST_DIR"
    ls -la "$DIST_DIR"
}

# Run main function
main "$@"