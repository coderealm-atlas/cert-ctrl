# install.ps1 - Windows PowerShell installer for cert-ctrl
# Usage: iwr -useb https://install.cert-ctrl.com/install.ps1 | iex
# Or: iwr -useb https://install.cert-ctrl.com/install.ps1 | iex; Install-CertCtrl -Version "v1.0.0" -UserInstall

param(
    [string]$Version = "latest",
    [string]$InstallPath = "$env:ProgramFiles\CertCtrl",
    [switch]$UserInstall,
    [switch]$Force,
    [switch]$Verbose,
    [switch]$Help
)

# Global variables
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue" # Disable progress bar for Invoke-WebRequest

# Color functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    $colorMap = @{
        "Red" = [System.ConsoleColor]::Red
        "Green" = [System.ConsoleColor]::Green
        "Yellow" = [System.ConsoleColor]::Yellow
        "Blue" = [System.ConsoleColor]::Blue
        "White" = [System.ConsoleColor]::White
    }
    
    Write-Host $Message -ForegroundColor $colorMap[$Color]
}

function Write-Info {
    param([string]$Message)
    Write-ColorOutput "[INFO] $Message" "Blue"
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput "[SUCCESS] $Message" "Green"
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput "[WARNING] $Message" "Yellow"
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput "[ERROR] $Message" "Red"
}

function Write-Verbose {
    param([string]$Message)
    if ($Verbose) {
        Write-ColorOutput "[VERBOSE] $Message" "Blue"
    }
}

# Platform detection
function Get-Platform {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
    return "windows-$arch"
}

# Check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check dependencies
function Test-Dependencies {
    $dependencies = @("Expand-Archive")
    
    foreach ($dep in $dependencies) {
        if (!(Get-Command $dep -ErrorAction SilentlyContinue)) {
            Write-Error "Required command '$dep' is not available."
            Write-Error "Please ensure you're running PowerShell 5.0 or later."
            exit 1
        }
    }
    
    Write-Verbose "All dependencies are available"
}

# Check permissions
function Test-Permissions {
    param(
        [string]$Path,
        [bool]$IsUserInstall
    )
    
    if (-not $IsUserInstall) {
        if (-not (Test-Administrator)) {
            Write-Error "Installation to $Path requires administrator privileges."
            Write-Error "Please run PowerShell as Administrator or use -UserInstall switch."
            exit 1
        }
    }
}

# Resolve version
function Resolve-Version {
    param([string]$Version)
    
    if ($Version -eq "latest") {
        Write-Info "Resolving latest version..."
        
        try {
            $latestUrl = "https://api.github.com/repos/coderealm-atlas/cert-ctrl/releases/latest"
            $response = Invoke-RestMethod -Uri $latestUrl -UseBasicParsing
            $resolvedVersion = $response.tag_name
            
            if ([string]::IsNullOrEmpty($resolvedVersion)) {
                throw "Failed to resolve latest version"
            }
            
            Write-Verbose "Resolved latest version: $resolvedVersion"
            return $resolvedVersion
        }
        catch {
            Write-Error "Failed to resolve latest version: $($_.Exception.Message)"
            exit 1
        }
    }
    
    return $Version
}

# Download binary
function Get-Binary {
    param(
        [string]$Version,
        [string]$Platform
    )
    
    $downloadUrl = "https://github.com/coderealm-atlas/cert-ctrl/releases/download/$Version/cert-ctrl-$Platform.zip"
    $tempFile = [System.IO.Path]::GetTempFileName() + ".zip"
    
    Write-Info "Downloading cert-ctrl $Version for $Platform..."
    Write-Verbose "Download URL: $downloadUrl"
    
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
        Write-Verbose "Downloaded to: $tempFile"
        
        # TODO: Add signature verification when available
        # $sigUrl = "$downloadUrl.sig"
        # $sigFile = "$tempFile.sig"
        # try {
        #     Invoke-WebRequest -Uri $sigUrl -OutFile $sigFile -UseBasicParsing
        #     Write-Verbose "Downloaded signature file"
        #     # Verify signature here
        # } catch {
        #     Write-Warning "No signature file available"
        # }
        
        return $tempFile
    }
    catch {
        Write-Error "Failed to download cert-ctrl: $($_.Exception.Message)"
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
        exit 1
    }
}

# Install binary
function Install-Binary {
    param(
        [string]$TempFile,
        [string]$InstallPath,
        [bool]$IsUserInstall,
        [bool]$Force
    )
    
    # Set install path for user install
    if ($IsUserInstall) {
        $InstallPath = "$env:LOCALAPPDATA\Programs\CertCtrl"
        Write-Verbose "Using user install path: $InstallPath"
    }
    
    Write-Info "Installing to $InstallPath..."
    
    # Create install directory
    if (!(Test-Path $InstallPath)) {
        try {
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
            Write-Verbose "Created install directory: $InstallPath"
        }
        catch {
            Write-Error "Failed to create install directory: $($_.Exception.Message)"
            exit 1
        }
    }
    
    # Check if binary already exists
    $binaryPath = Join-Path $InstallPath "cert-ctrl.exe"
    if ((Test-Path $binaryPath) -and (-not $Force)) {
        Write-Warning "cert-ctrl is already installed at $binaryPath"
        $choice = Read-Host "Do you want to overwrite it? [y/N]"
        if ($choice -notmatch '^[Yy]$') {
            Write-Info "Installation cancelled"
            return
        }
    }
    
    # Extract archive
    try {
        $extractPath = [System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid().ToString()
        New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
        
        Expand-Archive -Path $TempFile -DestinationPath $extractPath -Force
        Write-Verbose "Extracted to: $extractPath"
        
        # Find the binary (handle different archive structures)
        $sourceBinary = $null
        $possiblePaths = @(
            (Join-Path $extractPath "cert-ctrl.exe"),
            (Join-Path $extractPath "bin\cert-ctrl.exe"),
            (Join-Path $extractPath "cert-ctrl\cert-ctrl.exe")
        )
        
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $sourceBinary = $path
                break
            }
        }
        
        if (-not $sourceBinary) {
            throw "cert-ctrl.exe not found in downloaded archive"
        }
        
        # Copy binary to install location
        Copy-Item $sourceBinary $binaryPath -Force
        Write-Verbose "Copied binary to: $binaryPath"
        
        # Cleanup extraction directory
        Remove-Item $extractPath -Recurse -Force
        
        Write-Success "cert-ctrl installed successfully to $binaryPath"
        return $binaryPath
    }
    catch {
        Write-Error "Failed to install cert-ctrl: $($_.Exception.Message)"
        if (Test-Path $extractPath) {
            Remove-Item $extractPath -Recurse -Force
        }
        exit 1
    }
}

# Setup PATH
function Set-Path {
    param(
        [string]$InstallPath,
        [bool]$IsUserInstall
    )
    
    $target = if ($IsUserInstall) { "User" } else { "Machine" }
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", $target)
    
    if ($currentPath -notlike "*$InstallPath*") {
        Write-Info "Adding $InstallPath to PATH ($target)"
        
        try {
            $newPath = "$currentPath;$InstallPath"
            [Environment]::SetEnvironmentVariable("PATH", $newPath, $target)
            
            # Update current session PATH
            $env:PATH = "$env:PATH;$InstallPath"
            
            Write-Success "Added $InstallPath to PATH"
            Write-Warning "You may need to restart your PowerShell session for PATH changes to take effect"
        }
        catch {
            Write-Warning "Failed to update PATH: $($_.Exception.Message)"
            Write-Warning "You may need to manually add $InstallPath to your PATH"
        }
    }
    else {
        Write-Verbose "$InstallPath is already in PATH"
    }
}

# Verify installation
function Test-Installation {
    param([string]$BinaryPath)
    
    if (!(Test-Path $BinaryPath)) {
        Write-Error "Installation verification failed: binary not found at $BinaryPath"
        exit 1
    }
    
    Write-Info "Verifying installation..."
    
    try {
        $versionOutput = & $BinaryPath --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Installation verified! Version: $($versionOutput | Select-Object -First 1)"
        }
        else {
            Write-Warning "Binary installed but version check failed"
            Write-Warning "This might be normal if this is the first run"
        }
    }
    catch {
        Write-Warning "Could not verify installation: $($_.Exception.Message)"
    }
}

# Show completion message
function Show-Completion {
    param([bool]$IsUserInstall)
    
    Write-Host ""
    Write-Success "cert-ctrl installation completed!"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor White
    
    if ($IsUserInstall) {
        Write-Host "  1. Restart PowerShell or open a new terminal"
        Write-Host "  2. Run: cert-ctrl --help"
    }
    else {
        Write-Host "  1. Run: cert-ctrl --help"
    }
    
    Write-Host ""
    Write-Host "Documentation: " -NoNewline -ForegroundColor White
    Write-Host "https://github.com/coderealm-atlas/cert-ctrl/blob/main/README.md" -ForegroundColor Blue
    Write-Host "Report issues: " -NoNewline -ForegroundColor White
    Write-Host "https://github.com/coderealm-atlas/cert-ctrl/issues" -ForegroundColor Blue
    Write-Host ""
}

# Show help
function Show-Help {
    $helpText = @"
cert-ctrl PowerShell installer

SYNTAX
    Install-CertCtrl [[-Version] <string>] [[-InstallPath] <string>] [-UserInstall] [-Force] [-Verbose] [-Help]

PARAMETERS
    -Version <string>
        Install specific version (default: latest)
        
    -InstallPath <string>
        Custom installation directory (default: $env:ProgramFiles\CertCtrl)
        
    -UserInstall
        Install to user directory ($env:LOCALAPPDATA\Programs\CertCtrl)
        
    -Force
        Overwrite existing installation without prompting
        
    -Verbose
        Enable verbose output
        
    -Help
        Show this help message

EXAMPLES
    # Install latest version to Program Files (requires Administrator)
    Install-CertCtrl

    # Install to user directory (no Administrator required)
    Install-CertCtrl -UserInstall

    # Install specific version
    Install-CertCtrl -Version "v1.2.3" -UserInstall

    # Install to custom directory
    Install-CertCtrl -InstallPath "C:\Tools\CertCtrl"

    # One-liner installation
    iwr -useb https://install.cert-ctrl.com/install.ps1 | iex

"@
    
    Write-Host $helpText
}

# Main installation function
function Install-CertCtrl {
    param(
        [string]$Version = "latest",
        [string]$InstallPath = "$env:ProgramFiles\CertCtrl",
        [switch]$UserInstall,
        [switch]$Force,
        [switch]$Verbose,
        [switch]$Help
    )
    
    if ($Help) {
        Show-Help
        return
    }
    
    Write-Info "Starting cert-ctrl installation..."
    
    # Check dependencies
    Test-Dependencies
    
    # Detect platform
    $platform = Get-Platform
    Write-Verbose "Detected platform: $platform"
    
    # Resolve version
    $resolvedVersion = Resolve-Version $Version
    Write-Verbose "Installing version: $resolvedVersion"
    
    # Check permissions
    Test-Permissions $InstallPath $UserInstall.IsPresent
    
    # Download
    $tempFile = Get-Binary $resolvedVersion $platform
    
    try {
        # Install
        $binaryPath = Install-Binary $tempFile $InstallPath $UserInstall.IsPresent $Force.IsPresent
        
        # Setup PATH
        $installDir = Split-Path $binaryPath -Parent
        Set-Path $installDir $UserInstall.IsPresent
        
        # Verify
        Test-Installation $binaryPath
        
        # Show completion
        Show-Completion $UserInstall.IsPresent
    }
    finally {
        # Cleanup
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
    }
}

# If script is run directly (not dot-sourced), call the main function
if ($MyInvocation.InvocationName -ne '.') {
    Install-CertCtrl -Version $Version -InstallPath $InstallPath -UserInstall:$UserInstall -Force:$Force -Verbose:$Verbose -Help:$Help
}