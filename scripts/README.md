# Installation and Deployment Scripts

This directory contains scripts for installing, updating, and packaging the cert-ctrl application across different platforms.

## Directory Structure

```
scripts/
├── install/          # Installation scripts
│   ├── install.sh    # Unix/Linux/macOS installer
│   └── install.ps1   # Windows PowerShell installer
├── update/           # Update scripts
│   ├── update.sh     # Unix/Linux/macOS updater
│   └── update.ps1    # Windows PowerShell updater
├── package/          # Package creation scripts
│   └── package.sh    # Multi-platform package builder
└── README.md         # This file
```

## Installation Scripts

### Unix/Linux/macOS Installation (`install.sh`)

**One-line installation:**
```bash
curl -fsSL https://install.cert-ctrl.com/install.sh | bash
```

**With options:**
```bash
# Specific version
curl -fsSL https://install.cert-ctrl.com/install.sh | bash -s -- --version v1.2.3

# Custom directory
curl -fsSL https://install.cert-ctrl.com/install.sh | bash -s -- --install-dir /opt/cert-ctrl
```

**Features:**
- ✅ Automatic platform detection (Linux, macOS)
- ✅ Architecture detection (x64, ARM64, ARM)
- ✅ Version resolution (latest or specific)
- ✅ Signature verification (when available)
- ✅ User or system-wide installation
- ✅ PATH setup and shell integration
- ✅ Colored output and verbose logging
- ✅ Error handling and rollback

### Windows Installation (`install.ps1`)

**One-line installation:**
```powershell
iwr -useb https://install.cert-ctrl.com/install.ps1 | iex
```

**With options:**
```powershell
# User installation (no Administrator required)
iwr -useb https://install.cert-ctrl.com/install.ps1 | iex; Install-CertCtrl -UserInstall

# Specific version
iwr -useb https://install.cert-ctrl.com/install.ps1 | iex; Install-CertCtrl -Version "v1.2.3"

# Custom path
iwr -useb https://install.cert-ctrl.com/install.ps1 | iex; Install-CertCtrl -InstallPath "C:\Tools\CertCtrl"
```

**Features:**
- ✅ PowerShell 5.0+ compatibility
- ✅ Administrator privilege detection
- ✅ Automatic PATH management
- ✅ User or system-wide installation
- ✅ Error handling and cleanup
- ✅ Colored console output

## Update Scripts

### Unix/Linux/macOS Update (`update.sh`)

**Basic usage:**
```bash
# Check and apply updates
cert-ctrl-update

# Or using the script directly
./scripts/update/update.sh
```

**Advanced usage:**
```bash
# Check for updates only
./scripts/update/update.sh --check

# Update to specific version
./scripts/update/update.sh --version v1.2.3

# Dry run (show what would be done)
./scripts/update/update.sh --dry-run

# Rollback to previous version
./scripts/update/update.sh --rollback
```

**Features:**
- ✅ In-place binary updates
- ✅ Automatic backup creation
- ✅ Signature verification
- ✅ Rollback capability
- ✅ Version checking via GitHub API
- ✅ Dry run mode
- ✅ Verbose logging

### Windows Update (`update.ps1`)

**Basic usage:**
```powershell
# Check and apply updates
.\scripts\update\update.ps1

# Check for updates only
.\scripts\update\update.ps1 -Check

# Update to specific version
.\scripts\update\update.ps1 -Version "v1.2.3"

# Rollback to previous version
.\scripts\update\update.ps1 -Rollback
```

**Features:**
- ✅ PowerShell-native implementation
- ✅ Binary backup and restore
- ✅ Permission checking
- ✅ Error handling and rollback
- ✅ Version management

## Package Creation (`package.sh`)

**Basic usage:**
```bash
# Package for current platform
./scripts/package/package.sh

# Package for all platforms
./scripts/package/package.sh --all-platforms

# Create specific package types
./scripts/package/package.sh --type deb --platform linux-x64

# Package with signing
GPG_KEY_ID=your-key-id ./scripts/package/package.sh --sign --all-platforms
```

**Supported package types:**
- `tarball` - Cross-platform tar.gz archives
- `zip` - Windows ZIP archives
- `deb` - Debian/Ubuntu packages
- `rpm` - RedHat/CentOS/Fedora packages

**Features:**
- ✅ Multi-platform builds
- ✅ Multiple package formats
- ✅ GPG signing support
- ✅ Automatic version detection
- ✅ Binary verification
- ✅ Documentation inclusion

## Environment Variables

### Installation Scripts
- `INSTALL_DIR` - Custom installation directory
- `VERSION` - Specific version to install
- `FORCE` - Force overwrite existing installation
- `USER_INSTALL` - Install to user directory
- `VERBOSE` - Enable verbose output

### Package Creation
- `GPG_KEY_ID` - GPG key ID for package signing
- `BUILD_TYPE` - CMake build type (Release, Debug)

## Security Features

### Download Security
- ✅ HTTPS-only downloads
- ✅ Checksum verification
- ✅ GPG signature verification (when available)
- ✅ Binary execution testing

### Installation Security
- ✅ Privilege checking
- ✅ Permission validation
- ✅ Backup creation
- ✅ Rollback capability

## Integration Examples

### CI/CD Pipeline Integration

**GitHub Actions:**
```yaml
- name: Install cert-ctrl
  run: |
    sudo curl -fsSL https://install.cert-ctrl.com/install.sh | sudo bash

- name: Update cert-ctrl
  run: |
    if command -v cert-ctrl &> /dev/null; then
      ./scripts/update/update.sh --check
    fi
```

**Docker Integration:**
```dockerfile
FROM ubuntu:22.04
RUN curl -fsSL https://install.cert-ctrl.com/install.sh | bash
COPY . /app
WORKDIR /app
CMD ["cert-ctrl"]
```

### Package Manager Integration

**Homebrew Formula:**
```ruby
class CertCtrl < Formula
  desc "Certificate control and management utility"
  homepage "https://github.com/coderealm-atlas/cert-ctrl"
  url "https://github.com/coderealm-atlas/cert-ctrl/releases/download/v1.0.0/cert-ctrl-v1.0.0-macos-x64.tar.gz"
  sha256 "..."
  
  def install
    bin.install "cert-ctrl"
  end
end
```

**Chocolatey Package:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>cert-ctrl</id>
    <version>1.0.0</version>
    <title>CertCtrl</title>
    <authors>CertCtrl Team</authors>
    <description>Certificate control and management utility</description>
  </metadata>
  <files>
    <file src="cert-ctrl.exe" target="tools" />
  </files>
</package>
```

## Troubleshooting

### Common Issues

**Permission Denied:**
```bash
# Linux/macOS: Use user installation
sudo curl -fsSL https://install.cert-ctrl.com/install.sh | sudo bash

# Windows: Run PowerShell as Administrator
```

**Network Issues:**
```bash
# Check proxy settings
echo $HTTP_PROXY $HTTPS_PROXY

# Manual download
wget https://github.com/coderealm-atlas/cert-ctrl/releases/latest/download/cert-ctrl-linux-x64.tar.gz
```

**Version Issues:**
```bash
# Check current version
cert-ctrl --version

# Force reinstall
./scripts/install/install.sh --force

# Rollback
./scripts/update/update.sh --rollback
```

### Debug Mode

Enable verbose output for troubleshooting:

```bash
# Installation
curl -fsSL https://install.cert-ctrl.com/install.sh | bash -s -- --verbose

# Updates
./scripts/update/update.sh --verbose
```

## Development

### Testing Scripts Locally

```bash
# Test installation script
VERSION=v1.0.0 INSTALL_DIR=/tmp/cert-ctrl-test ./scripts/install/install.sh

# Test update script
./scripts/update/update.sh --dry-run --verbose

# Test package creation
./scripts/package/package.sh --platform linux-x64 --type tarball
```

### Contributing

When modifying scripts:

1. **Test on multiple platforms**
2. **Maintain backward compatibility**
3. **Update documentation**
4. **Add error handling**
5. **Follow shell scripting best practices**

### Script Dependencies

**Linux/macOS:**
- `curl` - For downloading files
- `tar` - For extracting archives
- `jq` - For JSON parsing (optional, has fallback)
- `gpg` - For signature verification (optional)

**Windows:**
- PowerShell 5.0+
- .NET Framework 4.5+

---

For more information, see the [Deployment Strategy](../docs/DEPLOYMENT_STRATEGY.md) document.