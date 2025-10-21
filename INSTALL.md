# cert-ctrl Installation Guide

This guide provides comprehensive installation instructions for the cert-ctrl certificate management agent across different platforms.

## Quick Installation

### Automated Installer

#### Linux & WSL

For most Linux distributions (including WSL), use the unified shell installer:

```bash
curl -fsSL https://install.lets-script.com/install.sh | sudo bash
```

or

```bash
curl -fsSL https://install.lets-script.com/install.sh -o install.sh
# Review the script first
cat install.sh
# Then run with sudo
sudo bash install.sh
```

This will automatically:
- Detect your Linux distribution and architecture
- Download the latest release
- Install to `/usr/local/bin` (requires root)
- Set up the systemd service when supported
- Verify the installation

#### macOS

macOS uses a dedicated installer script that configures launchd and mac-specific paths:

```bash
curl -fsSL https://install.lets-script.com/install-macos.sh | sudo bash
```

or, to review first:

```bash
curl -fsSL https://install.lets-script.com/install-macos.sh -o install-macos.sh
# Inspect the script before execution
cat install-macos.sh
sudo bash install-macos.sh
```

The macOS installer:
- Detects Apple Silicon vs Intel automatically
- Installs to `/usr/local/bin` (creates the directory when needed)
- Generates the launchd plist and loads the daemon
- Writes defaults under `/Library/Application Support/certctrl`
- Performs basic verification after setup

#### Windows (PowerShell)

For Windows users, use PowerShell with the Windows installer script:

```powershell
irm https://install.lets-script.com/install.ps1 | iex
```

Or download and run manually for better security:
```powershell
Invoke-WebRequest -Uri "https://install.lets-script.com/install.ps1" -OutFile "install.ps1"
# Review the script content before running
Get-Content install.ps1
# Then run it
.\install.ps1
```

This will automatically:
- Download the Windows release
- Install to `C:\Program Files\cert-ctrl\` (system-wide) or `%USERPROFILE%\.local\bin` (user-only)
- Create configuration directory in `%APPDATA%\cert-ctrl\`
- Set up Windows service
- Configure Windows Defender exclusions if needed

### Platform Detection

The installer automatically detects:
- **Operating System**: Linux, macOS, Windows
- **Architecture**: x64 (Intel/AMD), ARM64, ARM32

## Installation Options

### Linux & WSL

#### System-wide Installation (Default)

```bash
# Install for all users (requires sudo/root)
curl -fsSL https://install.lets-script.com/install.sh | bash
```

#### Custom Installation Directory

```bash
# Install to custom directory
curl -fsSL https://install.lets-script.com/install.sh | bash -s -- --install-dir /opt/cert-ctrl/bin
```

#### Service Installation

```bash
# Install binary and systemd service
curl -fsSL https://install.lets-script.com/install.sh | bash -s -- --service

# Install binary only, skip service
curl -fsSL https://install.lets-script.com/install.sh | bash -s -- --no-service
```

### macOS

The macOS installer script exposes similar toggles via long options. Some common examples:

```bash
# Install for all users (requires sudo)
curl -fsSL https://install.lets-script.com/install-macos.sh | bash

# Install to a custom directory
curl -fsSL https://install.lets-script.com/install-macos.sh | bash -s -- --install-dir /usr/local/cert-ctrl

# Skip launchd registration
curl -fsSL https://install.lets-script.com/install-macos.sh | bash -s -- --no-service
```

### Windows

#### System-wide Installation (Default)

```powershell
# Install for all users (requires Administrator privileges)
irm https://install.lets-script.com/install.ps1 | iex
```

#### User Installation

```powershell
# Install for current user only
#### Custom Installation Directory

```powershell
# Install to custom directory
$installDir = "C:\Tools\cert-ctrl"
irm https://install.lets-script.com/install.ps1 | iex -ArgumentList "--install-dir", $installDir
```

#### Service Installation Options

```powershell
# Install binary and Windows service
irm https://install.lets-script.com/install.ps1 | iex -ArgumentList "--service"

# Install binary only, skip service
irm https://install.lets-script.com/install.ps1 | iex -ArgumentList "--no-service"
```

## Alternative Installation Methods

### Manual Installation from GitHub Releases

This is currently the most reliable method as we haven't published to package repositories yet.

#### For Unix-like Systems (Linux, macOS)

```bash
# Download latest release directly
VERSION="latest"  # or specific version like "v0.1.0"
ARCH="x64"        # or "arm64" for ARM systems
OS="linux"        # or "macos" for macOS

# Download and install
curl -fsSL "https://github.com/coderealm-atlas/cert-ctrl/releases/download/${VERSION}/cert-ctrl-${OS}-${ARCH}.tar.gz" -o cert-ctrl.tar.gz
tar -xzf cert-ctrl.tar.gz
sudo mv cert-ctrl /usr/local/bin/
sudo chmod +x /usr/local/bin/cert-ctrl

# Verify installation
cert-ctrl --version
```

#### For Windows

```powershell
# Download latest release directly
$VERSION = "latest"  # or specific version like "v0.1.0"
$ARCH = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }

$InstallDir = "$env:ProgramFiles\cert-ctrl"
New-Item -ItemType Directory -Force -Path $InstallDir

$DownloadUrl = "https://github.com/coderealm-atlas/cert-ctrl/releases/download/$VERSION/cert-ctrl-windows-$ARCH.zip"
Invoke-WebRequest -Uri $DownloadUrl -OutFile "$env:TEMP\cert-ctrl.zip"
Expand-Archive -Path "$env:TEMP\cert-ctrl.zip" -DestinationPath $InstallDir -Force

# Add to PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($CurrentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$CurrentPath;$InstallDir", "Machine")
}

# Verify installation
cert-ctrl --version
```

### Package Managers (Future Support)

*Note: Package manager support is planned but not yet available. Use GitHub releases or automated installers above.*

The following package managers are planned for future releases:

- **Homebrew** (macOS/Linux) - Coming soon
- **APT** (Debian/Ubuntu) - Coming soon  
- **YUM/DNF** (RedHat/CentOS/Fedora) - Coming soon
- **Chocolatey** (Windows) - Coming soon
- **Scoop** (Windows) - Coming soon
- **winget** (Windows) - Coming soon

## Platform-Specific Instructions

### Linux

#### Prerequisites
- **Required**: `curl`, `tar`, `gzip`, `sha256sum` (or `shasum -a 256` on macOS)
- **Optional**: `systemctl` (for service management)

#### Installation
```bash
# Standard installation with service
curl -fsSL https://install.lets-script.com/install.sh | bash -s -- --service

# Verify installation
cert-ctrl --version
sudo systemctl status certctrl
```

#### Service Management
```bash
# Enable and start service
sudo systemctl enable --now certctrl

# Check service status
sudo systemctl status certctrl

# View logs
sudo journalctl -u certctrl -f

# Stop service
sudo systemctl stop certctrl

# Disable service
sudo systemctl disable certctrl
```

#### Configuration
Default configuration locations:
- System: `/etc/certctrl/`
- User: `~/.config/certctrl/`

### macOS

#### Prerequisites
- **Required**: `curl`, `tar`, `gzip`, `shasum` (bundled) or `sha256sum` (`brew install coreutils`)
- **Optional**: Homebrew (for dependencies)

#### Installation
```bash
# Fetch installer (requires root for system service)
curl -fsSL https://install.lets-script.com/install-macos.sh -o install-macos.sh
sudo bash install-macos.sh

# Verify installation
cert-ctrl --version
```

#### Running as Service (launchd)
```bash
# The macOS installer registers a LaunchDaemon automatically.
# Useful launchctl commands:
sudo launchctl print system/com.coderealm.certctrl
sudo launchctl kickstart -k system/com.coderealm.certctrl
sudo launchctl bootout system /Library/LaunchDaemons/com.coderealm.certctrl.plist
```

#### Configuration
Default configuration location: `/Library/Application Support/certctrl`

### Windows

#### Prerequisites
- **Required**: PowerShell 5.0+, Windows 10/Server 2016+
- **Optional**: Windows Terminal (for better experience)

#### Installation
```powershell
# Download and run installer
Invoke-WebRequest -Uri "https://install.lets-script.com/install.ps1" -OutFile "$env:TEMP\install-cert-ctrl.ps1"
PowerShell -ExecutionPolicy Bypass -File "$env:TEMP\install-cert-ctrl.ps1"

# Or one-line installation
iwr https://install.lets-script.com/install.ps1 | iex
```

#### Alternative: Manual Installation
```powershell
# Download latest release
$version = "latest"  # or specific version like "v0.1.0"
$arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
$url = "https://github.com/coderealm-atlas/cert-ctrl/releases/download/$version/cert-ctrl-windows-$arch.zip"

# Download and extract
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\cert-ctrl.zip"
Expand-Archive -Path "$env:TEMP\cert-ctrl.zip" -DestinationPath "$env:TEMP\cert-ctrl"

# Copy to Program Files
Copy-Item "$env:TEMP\cert-ctrl\cert-ctrl.exe" -Destination "$env:ProgramFiles\cert-ctrl\"

# Add to PATH
$path = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($path -notlike "*$env:ProgramFiles\cert-ctrl*") {
    [Environment]::SetEnvironmentVariable("PATH", "$path;$env:ProgramFiles\cert-ctrl", "Machine")
}
```

#### Running as Windows Service
```powershell
# Install as Windows service (requires administrative privileges)
cert-ctrl install-service

# Start the service
Start-Service "cert-ctrl"

# Check service status
Get-Service "cert-ctrl"

# Set to start automatically
Set-Service "cert-ctrl" -StartupType Automatic
```

#### Configuration
Default configuration location: `%ProgramData%\cert-ctrl\`

## Manual Installation from GitHub Releases

### Unix-like Systems (Linux, macOS)

#### Download and Install

```bash
# Set version and architecture
VERSION="latest"  # or specific version like "v0.1.0"
ARCH="x64"        # or "arm64" for ARM systems
OS="linux"        # or "macos" for macOS

# Download binary
curl -fsSL "https://github.com/coderealm-atlas/cert-ctrl/releases/download/${VERSION}/cert-ctrl-${OS}-${ARCH}.tar.gz" -o cert-ctrl.tar.gz

# Verify checksum (optional but recommended)
curl -fsSL "https://github.com/coderealm-atlas/cert-ctrl/releases/download/${VERSION}/cert-ctrl-${OS}-${ARCH}.tar.gz.sha256" | sha256sum -c
# macOS alternative:
# curl ... | shasum -a 256 -c

# Extract
tar -xzf cert-ctrl.tar.gz

# Install system-wide (requires sudo)
sudo cp cert-ctrl /usr/local/bin/
sudo chmod +x /usr/local/bin/cert-ctrl

# Or install for current user only
mkdir -p ~/.local/bin
cp cert-ctrl ~/.local/bin/
chmod +x ~/.local/bin/cert-ctrl

# Add to PATH if not already (user installation)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify installation
cert-ctrl --version
```

#### Create systemd Service (Linux)

```bash
# Create service file
sudo tee /etc/systemd/system/certctrl.service > /dev/null << EOF
[Unit]
Description=Certificate Control Agent
After=network.target

[Service]
Type=simple
User=certctrl
Group=certctrl
ExecStart=/usr/local/bin/cert-ctrl daemon
Restart=always
RestartSec=5
Environment=CERTCTRL_CONFIG_DIR=/etc/certctrl

[Install]
WantedBy=multi-user.target
EOF

# Create user and directories
sudo useradd -r -s /bin/false certctrl
sudo mkdir -p /etc/certctrl
sudo chown certctrl:certctrl /etc/certctrl

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable --now certctrl
```

### Windows Manual Installation

#### Download and Install

```powershell
# Set version and architecture
$VERSION = "latest"  # or specific version like "v0.1.0"
$ARCH = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }

# Create installation directory
$InstallDir = "$env:ProgramFiles\cert-ctrl"
New-Item -ItemType Directory -Force -Path $InstallDir

# Download binary
$DownloadUrl = "https://github.com/coderealm-atlas/cert-ctrl/releases/download/$VERSION/cert-ctrl-windows-$ARCH.zip"
$TempFile = "$env:TEMP\cert-ctrl.zip"
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempFile

# Verify checksum (optional but recommended)
$ChecksumUrl = "https://github.com/coderealm-atlas/cert-ctrl/releases/download/$VERSION/cert-ctrl-windows-$ARCH.zip.sha256"
$ExpectedChecksum = (Invoke-WebRequest -Uri $ChecksumUrl).Content.Trim()
$ActualChecksum = (Get-FileHash -Path $TempFile -Algorithm SHA256).Hash
if ($ActualChecksum -ne $ExpectedChecksum) {
    throw "Checksum verification failed!"
}

# Extract and install
Expand-Archive -Path $TempFile -DestinationPath $env:TEMP -Force
Copy-Item "$env:TEMP\cert-ctrl.exe" -Destination "$InstallDir\cert-ctrl.exe" -Force

# Add to system PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($CurrentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$CurrentPath;$InstallDir", "Machine")
    # Update current session PATH
    $env:PATH += ";$InstallDir"
}

# Create configuration directory
$ConfigDir = "$env:ProgramData\cert-ctrl"
New-Item -ItemType Directory -Force -Path $ConfigDir

# Verify installation
& "$InstallDir\cert-ctrl.exe" --version

# Cleanup
Remove-Item $TempFile -Force
Remove-Item "$env:TEMP\cert-ctrl.exe" -Force -ErrorAction SilentlyContinue
```

#### Install as Windows Service

```powershell
# Run as Administrator to install service
cert-ctrl install-service

# Configure service to start automatically
Set-Service -Name "cert-ctrl" -StartupType Automatic

# Start the service
Start-Service -Name "cert-ctrl"

# Verify service status
Get-Service -Name "cert-ctrl"
```

## Advanced Installation Options

### Specific Version Installation

```bash
# Install specific version
curl -fsSL https://install.lets-script.com/install.sh | bash -s -- --version v0.1.0
```

### Non-interactive Installation

```bash
# Automated installation for scripts
curl -fsSL https://install.lets-script.com/install.sh | bash -s -- --non-interactive --force
```

### Verification and Checksums

```bash
# The installer automatically verifies checksums when available
# Manual verification:
curl -fsSL "https://github.com/coderealm-atlas/cert-ctrl/releases/download/v0.1.0/cert-ctrl-linux-x64.tar.gz.sha256"
# Linux: sha256sum cert-ctrl-linux-x64.tar.gz
# macOS: shasum -a 256 cert-ctrl-macos-x64.tar.gz
```

### Corporate/Proxy Environments

```bash
# Set proxy for installation
export http_proxy="http://proxy.company.com:8080"
export https_proxy="https://proxy.company.com:8080"
curl -fsSL https://install.lets-script.com/install.sh | bash
```

## Configuration

### Initial Setup

After installation, cert-ctrl requires configuration:

1. **Create configuration directory**:
   ```bash
   # Linux/macOS
   mkdir -p ~/.config/certctrl
   
   # Windows
   mkdir %APPDATA%\certctrl
   ```

2. **Create basic configuration**:
   ```bash
   # Copy example configuration
   cert-ctrl init-config
   ```

3. **Edit configuration**:
   ```bash
   # Linux/macOS
   nano ~/.config/certctrl/application.json
   
   # Windows
   notepad %APPDATA%\certctrl\application.json
   ```

### Key Configuration Files

- `application.json` - Main application configuration
- `ioc_config.json` - Dependency injection configuration  
- `log_config.json` - Logging configuration
- `httpclient_config.json` - HTTP client settings

### Environment Variables

cert-ctrl recognizes these environment variables:

- `CERTCTRL_CONFIG_DIR` - Override configuration directory
- `CERTCTRL_LOG_LEVEL` - Set log level (debug, info, warn, error)
- `CERTCTRL_SERVER_URL` - Certificate server URL
- `CERTCTRL_DEVICE_ID` - Device identifier

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Fix: Use sudo for system installation
curl -fsSL https://install.lets-script.com/install.sh | sudo bash

# System-wide installation requires root
sudo curl -fsSL https://install.lets-script.com/install.sh | sudo bash
```

#### Command Not Found
```bash
# Add to PATH manually
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### Service Won't Start
```bash
# Check service logs
sudo journalctl -u certctrl -n 50

# Check configuration
cert-ctrl --config-check

# Check permissions
ls -la /etc/certctrl/
```

#### Network Issues
```bash
# Test connectivity
cert-ctrl test-connection

# Check proxy settings
echo $http_proxy $https_proxy

# Verify DNS resolution
nslookup install.lets-script.com
```

### Getting Help

1. **Check logs**:
   ```bash
   # Linux
   sudo journalctl -u certctrl -f
   
   # macOS
   tail -f ~/Library/Logs/certctrl.log
   
   # Windows
   Get-EventLog -LogName Application -Source "cert-ctrl"
   ```

2. **Verify installation**:
   ```bash
   cert-ctrl --version
   cert-ctrl --config-check
   cert-ctrl doctor
   ```

3. **Documentation**: Visit [our documentation site](https://docs.lets-script.com)
4. **Support**: Create an issue at [GitHub Issues](https://github.com/coderealm-atlas/cert-ctrl/issues)

## Uninstallation

### Remove Binary
```bash
# System installation
sudo rm -f /usr/local/bin/cert-ctrl

# User installation  
rm -f ~/.local/bin/cert-ctrl
```

### Remove Service (Linux)
```bash
sudo systemctl stop certctrl
sudo systemctl disable certctrl
sudo rm -f /etc/systemd/system/certctrl.service
sudo systemctl daemon-reload
```

### Remove Configuration
```bash
# Linux/macOS
rm -rf ~/.config/certctrl
sudo rm -rf /etc/certctrl

# Windows
rmdir /s %APPDATA%\certctrl
rmdir /s %ProgramData%\certctrl
```

## Building from Source

If you prefer to build from source:

```bash
# Clone repository
git clone https://github.com/coderealm-atlas/cert-ctrl.git
cd cert-ctrl

# Build with CMake
cmake --preset=release
cmake --build --preset=release

# Install locally
sudo cp build/release/cert_ctrl /usr/local/bin/cert-ctrl
```

For detailed build instructions, see [BUILD.md](BUILD.md).

---

## Security Considerations

- cert-ctrl requires network access to communicate with certificate servers
- Configuration files may contain sensitive information - secure appropriately
- Run with minimal required privileges
- Regularly update to the latest version for security patches
- Verify checksums when downloading manually

For security questions, contact security@lets-script.com.