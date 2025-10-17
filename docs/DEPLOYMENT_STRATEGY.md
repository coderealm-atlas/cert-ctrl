# Certificate Control Application Deployment Strategy

## Overview

This document outlines deployment strategies for the `cert_ctrl` application, covering installation methods, version notification systems, and update mechanisms for both Linux and Windows platforms.

## Table of Contents

1. [Deployment Methods](#deployment-methods)
2. [Version Notification](#version-notification)
3. [Update Mechanisms](#update-mechanisms)
4. [Security Considerations](#security-considerations)
5. [Runtime Architecture](#runtime-architecture)
6. [Implementation Examples](#implementation-examples)

---

## 1. Deployment Methods

### 1.1 One-Line Installation Scripts

#### Linux/macOS (curl | bash pattern)
```bash
# Quick install
curl -fsSL https://install.cert-ctrl.com/install.sh | bash

# With options
curl -fsSL https://install.cert-ctrl.com/install.sh | bash -s -- --version=latest --install-dir=/usr/local/bin
```

#### Windows (PowerShell)
```powershell
# Quick install
iwr -useb https://install.cert-ctrl.com/install.ps1 | iex

# With options
iwr -useb https://install.cert-ctrl.com/install.ps1 | iex; Install-CertCtrl -Version "latest" -InstallPath "C:\Program Files\CertCtrl"
```

### 1.2 Package Manager Integration

#### Linux Package Managers
```bash
# APT (Debian/Ubuntu)
curl -fsSL https://repo.cert-ctrl.com/gpg.key | sudo apt-key add -
echo "deb https://repo.cert-ctrl.com/apt stable main" | sudo tee /etc/apt/sources.list.d/cert-ctrl.list
sudo apt update && sudo apt install cert-ctrl

# YUM/DNF (RedHat/CentOS/Fedora)
sudo rpm --import https://repo.cert-ctrl.com/rpm.key
sudo yum-config-manager --add-repo https://repo.cert-ctrl.com/rpm/cert-ctrl.repo
sudo yum install cert-ctrl

# Snap
sudo snap install cert-ctrl

# Homebrew (macOS)
brew tap cert-ctrl/tap
brew install cert-ctrl
```

#### Windows Package Managers
```powershell
# Chocolatey
choco install cert-ctrl

# Scoop
scoop bucket add cert-ctrl https://github.com/cert-ctrl/scoop-bucket
scoop install cert-ctrl

# winget
winget install CertCtrl.CertCtrl
```

### 1.3 Direct Binary Download

#### GitHub Releases
```bash
# Linux
wget https://github.com/cert-ctrl/cert-ctrl/releases/latest/download/cert-ctrl-linux-x64.tar.gz
tar -xzf cert-ctrl-linux-x64.tar.gz
sudo mv cert-ctrl /usr/local/bin/

# Windows
# Download from: https://github.com/cert-ctrl/cert-ctrl/releases/latest/download/cert-ctrl-windows-x64.zip
```

### 1.4 Container Deployment

#### Docker
```bash
# Run directly
docker run --rm -v $(pwd):/workspace cert-ctrl/cert-ctrl:latest [commands]

# Docker Compose
version: '3.8'
services:
  cert-ctrl:
    image: cert-ctrl/cert-ctrl:latest
    volumes:
      - ./config:/app/config
      - ./certs:/app/certs
    environment:
      - CERT_CTRL_CONFIG=/app/config/cert-ctrl.json
```

#### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-ctrl
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cert-ctrl
  template:
    metadata:
      labels:
        app: cert-ctrl
    spec:
      containers:
      - name: cert-ctrl
        image: cert-ctrl/cert-ctrl:latest
        volumeMounts:
        - name: config
          mountPath: /app/config
```

---

## 2. Version Notification

### 2.1 Built-in Update Checker

#### Automatic Check on Startup
```cpp
// Example implementation in C++
class UpdateChecker {
public:
    struct VersionInfo {
        std::string latest_version;
        std::string download_url;
        std::string changelog_url;
        bool security_update;
    };
    
    std::optional<VersionInfo> checkForUpdates() {
        // HTTP request to version API
        auto response = httpClient.get("https://api.cert-ctrl.com/v1/version/check", {
            {"current_version", getCurrentVersion()},
            {"platform", getPlatform()},
            {"arch", getArchitecture()}
        });
        
        if (response.newer_version_available) {
            return VersionInfo{
                .latest_version = response.latest_version,
                .download_url = response.download_url,
                .changelog_url = response.changelog_url,
                .security_update = response.security_update
            };
        }
        return std::nullopt;
    }
};
```

#### Command Line Check
```bash
# Check for updates
cert-ctrl --check-updates

# Output example:
# A new version is available: v2.1.0 (current: v2.0.5)
# Security update available - update recommended
# Download: https://github.com/cert-ctrl/cert-ctrl/releases/tag/v2.1.0
# Update: cert-ctrl --update
```

### 2.2 Version API Endpoints

#### REST API Structure
```json
// GET https://api.cert-ctrl.com/v1/version/check?current=v2.0.5&platform=linux&arch=x64
{
  "current_version": "v2.0.5",
  "latest_version": "v2.1.0",
  "newer_version_available": true,
  "security_update": true,
  "download_urls": {
    "linux-x64": "https://github.com/cert-ctrl/cert-ctrl/releases/download/v2.1.0/cert-ctrl-linux-x64.tar.gz",
    "windows-x64": "https://github.com/cert-ctrl/cert-ctrl/releases/download/v2.1.0/cert-ctrl-windows-x64.zip",
    "macos-x64": "https://github.com/cert-ctrl/cert-ctrl/releases/download/v2.1.0/cert-ctrl-macos-x64.tar.gz"
  },
  "changelog_url": "https://github.com/cert-ctrl/cert-ctrl/releases/tag/v2.1.0",
  "minimum_supported_version": "v1.5.0",
  "deprecation_warnings": []
}
```

### 2.3 Notification Channels

#### System Notifications
- **Linux**: Desktop notifications via libnotify
- **Windows**: Toast notifications via WinRT API
- **macOS**: Native notification center

#### Configuration File
```json
{
  "update_settings": {
    "auto_check": true,
    "check_interval_hours": 24,
    "notify_security_updates": true,
    "notify_feature_updates": false,
    "notification_method": "desktop",
    "update_channel": "stable"  // stable, beta, nightly
  }
}
```

---

## 3. Update Mechanisms

### 3.1 In-Place Updates

#### Self-Updating Binary
```cpp
class SelfUpdater {
private:
    std::string current_binary_path;
    std::string temp_directory;
    
public:
    UpdateResult performUpdate(const std::string& download_url) {
        // 1. Download new binary to temp location
        auto temp_binary = downloadBinary(download_url);
        
        // 2. Verify signature/checksum
        if (!verifyBinary(temp_binary)) {
            return UpdateResult::VERIFICATION_FAILED;
        }
        
        // 3. Replace current binary (platform-specific)
        #ifdef _WIN32
            return replaceWindowsBinary(temp_binary);
        #else
            return replaceUnixBinary(temp_binary);
        #endif
    }
    
private:
    UpdateResult replaceWindowsBinary(const std::string& new_binary) {
        // Windows: Use MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT
        // Or spawn updater process that waits for main process to exit
    }
    
    UpdateResult replaceUnixBinary(const std::string& new_binary) {
        // Unix: Atomic rename, then exec new binary
    }
};
```

#### Update Command
```bash
# Perform update
cert-ctrl --update

# Update to specific version
cert-ctrl --update --version=v2.1.0

# Update with backup
cert-ctrl --update --backup

# Dry run (download and verify only)
cert-ctrl --update --dry-run
```

### 3.2 Package Manager Updates

#### Automatic Updates via Package Managers
```bash
# APT auto-update setup
echo 'Unattended-Upgrade::Allowed-Origins:: "cert-ctrl:stable";' >> /etc/apt/apt.conf.d/50unattended-upgrades

# YUM/DNF automatic updates
dnf install dnf-automatic
systemctl enable --now dnf-automatic-install.timer
```

### 3.3 Container Updates

#### Docker Update Strategy
```bash
# Update script for Docker deployment
#!/bin/bash
# update-cert-ctrl.sh

CURRENT_VERSION=$(docker inspect cert-ctrl/cert-ctrl:current --format='{{.Config.Labels.version}}')
LATEST_VERSION=$(curl -s https://api.cert-ctrl.com/v1/version/latest | jq -r '.version')

if [ "$CURRENT_VERSION" != "$LATEST_VERSION" ]; then
    echo "Updating from $CURRENT_VERSION to $LATEST_VERSION"
    docker pull cert-ctrl/cert-ctrl:$LATEST_VERSION
    docker tag cert-ctrl/cert-ctrl:$LATEST_VERSION cert-ctrl/cert-ctrl:current
    docker-compose restart cert-ctrl
fi
```

### 3.4 Update Verification

#### Signature Verification
```cpp
class UpdateVerifier {
public:
    bool verifyUpdate(const std::string& binary_path, const std::string& signature_path) {
        // 1. Verify digital signature
        if (!verifyDigitalSignature(binary_path, signature_path)) {
            return false;
        }
        
        // 2. Verify checksum
        auto expected_hash = getExpectedHash();
        auto actual_hash = calculateSHA256(binary_path);
        
        return expected_hash == actual_hash;
    }
    
private:
    bool verifyDigitalSignature(const std::string& file, const std::string& sig) {
        // OpenSSL signature verification
        // Verify against embedded public key
    }
};
```

---

## 4. Security Considerations

### 4.1 Download Security

#### HTTPS Only
- All downloads must use HTTPS
- Certificate pinning for critical endpoints
- Fallback mirrors with signature verification

#### Signature Verification
```bash
# Download with signature verification
curl -fsSL https://releases.cert-ctrl.com/v2.1.0/cert-ctrl-linux-x64.tar.gz -o cert-ctrl.tar.gz
curl -fsSL https://releases.cert-ctrl.com/v2.1.0/cert-ctrl-linux-x64.tar.gz.sig -o cert-ctrl.tar.gz.sig

# Verify signature
gpg --verify cert-ctrl.tar.gz.sig cert-ctrl.tar.gz
```

### 4.2 Installation Security

#### Privilege Requirements
- **Linux**: Root for system-wide installation, user for local installation
- **Windows**: Administrator for Program Files, user for AppData

#### System Installation
```bash
# Install system-wide (requires root)
sudo curl -fsSL https://install.cert-ctrl.com/install.sh | sudo bash
```

### 4.3 Update Security

#### Rollback Mechanism
```cpp
class UpdateRollback {
public:
    void createBackup() {
        auto backup_path = getBackupPath();
        std::filesystem::copy_file(getCurrentBinaryPath(), backup_path);
        saveBackupMetadata();
    }
    
    bool rollback() {
        auto backup_path = getBackupPath();
        if (std::filesystem::exists(backup_path)) {
            return std::filesystem::copy_file(backup_path, getCurrentBinaryPath());
        }
        return false;
    }
};
```

---

## 5. Runtime Architecture

### 5.1 Motivation and Reference Model

Tailscale separates its functionality into two personas:

- **`tailscaled`** — a privileged daemon that maintains device state, manages WireGuard tunnels, and persists configuration.
- **`tailscale`** — an unprivileged CLI used by operators to interrogate or instruct the daemon over an authenticated control channel.

Following the same pattern, `cert-ctrl` should ship with distinct entry points for its background work and its interactive tooling. Borrowing this approach gives us:

- A hardened surface area for privileged operations (certificate provisioning, key management, secure storage writes).
- A lightweight user-experience layer that can run without elevated privileges but still leverage the daemon via IPC.

### 5.2 Executable Layout

| Role             | Suggested Binary Name | Runs As                | Responsibilities |
| ---------------- | --------------------- | ---------------------- | ---------------- |
| Long-running service | `certctrld` (Linux/macOS) / `CertCtrlService.exe` (Windows) | `root` or a locked-down system account |
| | | | - Boot-time startup via `systemd`/Windows Service Manager  
| | | | - Watches config/runtime directories, applies policy when `auto_apply_config` is enabled  
| | | | - Owns device enrollment, certificate issuance, token refresh, and telemetry flush  
| Operator CLI    | `certctrl`            | invoking user (non-root) | - Sends requests to the daemon over UDS/Named Pipe  
| | | | - Presents status, log tails, and one-shot operations (login, updates poll)  
| | | | - Falls back gracefully when the daemon is unavailable, offering actionable guidance |

### 5.3 Single Binary vs. Multi-Binary Delivery

Both binaries can originate from the same build artifact, enabling a BusyBox-style multi-call pattern:

- Install a single ELF/PE and create symlinks (`certctrld` ➝ `certctrl`, `certctrl` ➝ `certctrl`).
- At startup we derive the active persona from `argv[0]`, with override flags (`--daemon`, `--cli`) for clarity.
- On Windows we ship the same executable twice under different filenames to keep the SCM metadata straightforward.

This affords shared code reuse while still giving package maintainers explicit file names for service definitions.

### 5.4 Privilege and Service Management

- **Linux/macOS**: Ship `certctrld.service` units that run as `root` (or a dedicated system user with membership in required groups). Ensure runtime directories (`/var/lib/certctrl`, `/var/log/certctrl`) are owned by that account. Harden with `ProtectSystem=strict`, `PrivateTmp=yes`, and tight `CapabilityBoundingSet` rules.
- **Windows**: Register `CertCtrlService.exe` with the Service Control Manager under the `LocalSystem` account by default, with an opt-in path to run under a managed service account.
- **IPC Channel**: Use a Unix Domain Socket (Linux/macOS) or Named Pipe (Windows) under the daemon-owned runtime directory. Gate access via filesystem ACLs so only intended operators (e.g., `certctrl` group) can reach it.
- **CLI Authentication**: Require the CLI to present device tokens stored in `runtime_dir/state`. Optionally layer mutual TLS or per-user API keys when the daemon is exposed off-box.

### 5.5 Packaging Implications

- Include both entry point names in every distribution artifact, even if they map back to the same binary, so scripts and docs remain explicit.
- Update install scripts to create/manage the service unit (enable + start) and drop a `certctrl` convenience wrapper into `/usr/local/bin` or `%ProgramFiles%\CertCtrl`.
- Document manual workflows (copy binary, register service, run CLI) for air-gapped deployments.
- Ensure auto-update logic differentiates between daemon restarts (which require coordination) and CLI updates (which can often be transparent).

## 6. Implementation Examples

### 5.1 Installation Script (install.sh)

```bash
#!/bin/bash
# install.sh - Universal installer for cert-ctrl

set -euo pipefail

# Configuration
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"
FORCE="${FORCE:-false}"
USER_INSTALL="${USER_INSTALL:-false}"

# Platform detection
detect_platform() {
    local platform=""
    local arch=""
    
    case "$(uname -s)" in
        Linux*)     platform="linux" ;;
        Darwin*)    platform="macos" ;;
        CYGWIN*|MINGW*|MSYS*) platform="windows" ;;
        *)          echo "Unsupported platform: $(uname -s)" >&2; exit 1 ;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64)   arch="x64" ;;
        aarch64|arm64)  arch="arm64" ;;
        *)              echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac
    
    echo "${platform}-${arch}"
}

# Download and install
main() {
    local platform_arch=$(detect_platform)
    
    if [ "$USER_INSTALL" = "true" ]; then
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
    fi
    
    echo "Installing cert-ctrl ${VERSION} for ${platform_arch} to ${INSTALL_DIR}"
    
    # Download
    local download_url="https://github.com/cert-ctrl/cert-ctrl/releases/download/${VERSION}/cert-ctrl-${platform_arch}.tar.gz"
    local temp_file=$(mktemp)
    
    curl -fsSL "$download_url" -o "$temp_file"
    
    # Extract and install
    tar -xzf "$temp_file" -C /tmp
    chmod +x /tmp/cert-ctrl
    
    if [ -w "$INSTALL_DIR" ] || [ "$USER_INSTALL" = "true" ]; then
        mv /tmp/cert-ctrl "$INSTALL_DIR/"
    else
        sudo mv /tmp/cert-ctrl "$INSTALL_DIR/"
    fi
    
    echo "cert-ctrl installed successfully!"
    echo "Run 'cert-ctrl --help' to get started."
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --force)
            FORCE="true"
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

main
```

### 5.2 PowerShell Installation Script (install.ps1)

```powershell
# install.ps1 - Windows installer for cert-ctrl

param(
    [string]$Version = "latest",
    [string]$InstallPath = "$env:ProgramFiles\CertCtrl",
    [switch]$UserInstall,
    [switch]$Force
)

function Get-Platform {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
    return "windows-$arch"
}

function Install-CertCtrl {
    param(
        [string]$Version,
        [string]$InstallPath,
        [bool]$UserInstall
    )
    
    if ($UserInstall) {
        $InstallPath = "$env:LOCALAPPDATA\Programs\CertCtrl"
    }
    
    $platform = Get-Platform
    Write-Host "Installing cert-ctrl $Version for $platform to $InstallPath"
    
    # Create install directory
    if (!(Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }
    
    # Download
    $downloadUrl = "https://github.com/cert-ctrl/cert-ctrl/releases/download/$Version/cert-ctrl-$platform.zip"
    $tempFile = [System.IO.Path]::GetTempFileName() + ".zip"
    
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
        
        # Extract
        Expand-Archive -Path $tempFile -DestinationPath $InstallPath -Force
        
        # Add to PATH if not already there
        $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        if ($currentPath -notlike "*$InstallPath*") {
            [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$InstallPath", "User")
            Write-Host "Added $InstallPath to PATH"
        }
        
        Write-Host "cert-ctrl installed successfully!"
        Write-Host "Restart your terminal and run 'cert-ctrl --help' to get started."
        
    } finally {
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
    }
}

Install-CertCtrl -Version $Version -InstallPath $InstallPath -UserInstall $UserInstall
```

---

## 6. Configuration Management

### 6.1 Configuration Deployment

#### Default Configuration
```json
{
  "deployment": {
    "update_check_url": "https://api.cert-ctrl.com/v1/version/check",
    "download_base_url": "https://releases.cert-ctrl.com",
    "auto_update": false,
    "update_channel": "stable",
    "backup_on_update": true,
    "rollback_timeout_minutes": 30
  },
  "installation": {
    "verify_signatures": true,
    "public_key_url": "https://keys.cert-ctrl.com/release.pub",
    "allow_downgrades": false,
    "max_download_retries": 3
  }
}
```

### 6.2 Environment-Specific Deployments

#### Production
- Stable channel only
- Signature verification required
- Automatic backups
- Staged rollouts

#### Development
- Beta/nightly channels available
- Optional signature verification
- Faster update cycles
- A/B testing support

---

## 7. Monitoring and Analytics

### 7.1 Update Metrics

#### Tracking Update Success
```cpp
class UpdateMetrics {
public:
    void recordUpdateAttempt(const std::string& from_version, const std::string& to_version) {
        // Send anonymous usage data
        json payload = {
            {"event", "update_attempt"},
            {"from_version", from_version},
            {"to_version", to_version},
            {"platform", getPlatform()},
            {"timestamp", getCurrentTimestamp()}
        };
        
        // Send to analytics endpoint (opt-in only)
        if (isAnalyticsEnabled()) {
            sendAnalytics(payload);
        }
    }
};
```

### 7.2 Deployment Health

#### Health Checks
- Update success/failure rates
- Download completion rates
- Rollback frequency
- Platform-specific issues

---

This deployment strategy provides multiple installation methods, secure update mechanisms, and comprehensive monitoring for the cert-ctrl application across all major platforms.