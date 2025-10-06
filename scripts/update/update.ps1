# update.ps1 - Windows PowerShell update script for cert-ctrl
# This script handles in-place updates of cert-ctrl binary on Windows

param(
    [string]$Version,
    [switch]$Check,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Rollback,
    [switch]$Verbose,
    [switch]$Help
)

# Configuration
$BackupDir = "$env:LOCALAPPDATA\CertCtrl\Backups"
$ConfigFile = "$env:LOCALAPPDATA\CertCtrl\config.json"
$CurrentBinary = ""
$BackupCount = 5

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Logging functions
function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Blue }
function Write-Success { param([string]$Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }
function Write-Verbose { param([string]$Message) if ($Verbose) { Write-Host "[VERBOSE] $Message" -ForegroundColor Blue } }

# Find current cert-ctrl binary
function Find-CurrentBinary {
    try {
        $binary = Get-Command cert-ctrl -ErrorAction SilentlyContinue
        if ($binary) {
            $script:CurrentBinary = $binary.Source
            Write-Verbose "Found cert-ctrl at: $CurrentBinary"
        }
        else {
            Write-Error "cert-ctrl not found in PATH"
            exit 1
        }
    }
    catch {
        Write-Error "Failed to locate cert-ctrl binary: $($_.Exception.Message)"
        exit 1
    }
}

# Get current version
function Get-CurrentVersion {
    try {
        if (Test-Path $CurrentBinary) {
            $versionOutput = & $CurrentBinary --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                return ($versionOutput | Select-Object -First 1)
            }
        }
        return "unknown"
    }
    catch {
        return "unknown"
    }
}

# Check for updates
function Test-Updates {
    Write-Info "Checking for updates..."
    
    $currentVersion = Get-CurrentVersion
    Write-Verbose "Current version: $currentVersion"
    
    try {
        $latestUrl = "https://api.github.com/repos/coderealm-atlas/cert-ctrl/releases/latest"
        $response = Invoke-RestMethod -Uri $latestUrl -UseBasicParsing
        $latestVersion = $response.tag_name
        
        if ([string]::IsNullOrEmpty($latestVersion)) {
            throw "Failed to fetch latest version"
        }
        
        Write-Verbose "Latest version: $latestVersion"
        
        if ($currentVersion -eq $latestVersion) {
            Write-Success "cert-ctrl is already up to date ($currentVersion)"
            return $null
        }
        else {
            Write-Info "Update available: $currentVersion → $latestVersion"
            return $latestVersion
        }
    }
    catch {
        Write-Error "Failed to check for updates: $($_.Exception.Message)"
        exit 1
    }
}

# Create backup
function New-Backup {
    $currentVersion = Get-CurrentVersion
    
    if (!(Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupFile = Join-Path $BackupDir "cert-ctrl-$currentVersion-$timestamp.exe"
    
    Write-Info "Creating backup..."
    
    try {
        Copy-Item $CurrentBinary $backupFile -Force
        Write-Success "Backup created: $backupFile"
        
        # Cleanup old backups
        $backups = Get-ChildItem $BackupDir -Name "cert-ctrl-*.exe" | Sort-Object -Descending
        if ($backups.Count -gt $BackupCount) {
            $toDelete = $backups | Select-Object -Skip $BackupCount
            foreach ($backup in $toDelete) {
                Remove-Item (Join-Path $BackupDir $backup) -Force
                Write-Verbose "Removed old backup: $backup"
            }
        }
        
        return $backupFile
    }
    catch {
        Write-Error "Failed to create backup: $($_.Exception.Message)"
        exit 1
    }
}

# Download new version
function Get-Update {
    param([string]$Version)
    
    $platform = Get-Platform
    $downloadUrl = "https://github.com/coderealm-atlas/cert-ctrl/releases/download/$Version/cert-ctrl-$platform.zip"
    $tempFile = [System.IO.Path]::GetTempFileName() + ".zip"
    
    Write-Info "Downloading cert-ctrl $Version..."
    Write-Verbose "Download URL: $downloadUrl"
    
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
        return $tempFile
    }
    catch {
        Write-Error "Failed to download update: $($_.Exception.Message)"
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
        exit 1
    }
}

# Verify downloaded binary
function Test-Binary {
    param([string]$TempFile)
    
    Write-Info "Verifying downloaded binary..."
    
    try {
        $extractPath = Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
        
        Expand-Archive -Path $TempFile -DestinationPath $extractPath -Force
        
        # Find the binary
        $binaryPath = $null
        $possiblePaths = @(
            (Join-Path $extractPath "cert-ctrl.exe"),
            (Join-Path $extractPath "bin\cert-ctrl.exe"),
            (Join-Path $extractPath "cert-ctrl\cert-ctrl.exe")
        )
        
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $binaryPath = $path
                break
            }
        }
        
        if (-not $binaryPath) {
            throw "cert-ctrl.exe not found in downloaded archive"
        }
        
        # Test if binary works
        try {
            $testOutput = & $binaryPath --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Binary verification passed"
                return $binaryPath
            }
            else {
                throw "Binary version check failed"
            }
        }
        catch {
            throw "Binary execution test failed: $($_.Exception.Message)"
        }
    }
    catch {
        Write-Error "Binary verification failed: $($_.Exception.Message)"
        if (Test-Path $extractPath) {
            Remove-Item $extractPath -Recurse -Force
        }
        return $null
    }
}

# Apply update
function Set-Update {
    param(
        [string]$NewBinary,
        [string]$BackupFile
    )
    
    Write-Info "Applying update..."
    
    if ($DryRun) {
        Write-Info "DRY RUN: Would replace $CurrentBinary with $NewBinary"
        return $true
    }
    
    try {
        # Check if we can write to the current binary
        $testWrite = $false
        try {
            $fileStream = [System.IO.File]::OpenWrite($CurrentBinary)
            $fileStream.Close()
            $testWrite = $true
        }
        catch {
            $testWrite = $false
        }
        
        if (-not $testWrite) {
            Write-Error "No write permission for $CurrentBinary"
            Write-Error "Try running PowerShell as Administrator"
            return $false
        }
        
        # Replace binary
        Copy-Item $NewBinary $CurrentBinary -Force
        Write-Success "Update applied successfully"
        
        # Verify new installation
        $newVersion = Get-CurrentVersion
        Write-Success "Updated to version: $newVersion"
        
        return $true
    }
    catch {
        Write-Error "Failed to apply update: $($_.Exception.Message)"
        
        # Attempt rollback
        if ($BackupFile -and (Test-Path $BackupFile)) {
            Write-Warning "Attempting rollback..."
            try {
                Copy-Item $BackupFile $CurrentBinary -Force
                Write-Warning "Rollback successful"
            }
            catch {
                Write-Error "Rollback failed - manual intervention required"
            }
        }
        
        return $false
    }
}

# Rollback to previous version
function Restore-PreviousVersion {
    Write-Info "Looking for backup versions..."
    
    if (!(Test-Path $BackupDir)) {
        Write-Error "No backup directory found"
        exit 1
    }
    
    $latestBackup = Get-ChildItem $BackupDir -Name "cert-ctrl-*.exe" | Sort-Object -Descending | Select-Object -First 1
    
    if (-not $latestBackup) {
        Write-Error "No backup versions found"
        exit 1
    }
    
    $backupPath = Join-Path $BackupDir $latestBackup
    Write-Info "Rolling back to: $latestBackup"
    
    if ($DryRun) {
        Write-Info "DRY RUN: Would rollback to $backupPath"
        return
    }
    
    try {
        Copy-Item $backupPath $CurrentBinary -Force
        $version = Get-CurrentVersion
        Write-Success "Rollback successful to version: $version"
    }
    catch {
        Write-Error "Rollback failed: $($_.Exception.Message)"
        exit 1
    }
}

# Platform detection
function Get-Platform {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
    return "windows-$arch"
}

# Show help
function Show-Help {
    $helpText = @"
cert-ctrl PowerShell update script

SYNTAX
    .\update.ps1 [[-Version] <string>] [-Check] [-Force] [-DryRun] [-Rollback] [-Verbose] [-Help]

PARAMETERS
    -Version <string>
        Update to specific version
        
    -Check
        Check for updates without installing
        
    -Force
        Force update even if already up to date
        
    -DryRun
        Show what would be done without applying changes
        
    -Rollback
        Rollback to previous version
        
    -Verbose
        Enable verbose output
        
    -Help
        Show this help message

EXAMPLES
    # Check and apply available updates
    .\update.ps1

    # Check for updates only
    .\update.ps1 -Check

    # Update to specific version
    .\update.ps1 -Version "v1.2.3"

    # Dry run update
    .\update.ps1 -DryRun

    # Rollback to previous version
    .\update.ps1 -Rollback

"@
    
    Write-Host $helpText
}

# Main function
function Main {
    Write-Info "cert-ctrl update utility"
    
    # Find current binary
    Find-CurrentBinary
    
    if ($Rollback) {
        Restore-PreviousVersion
        return
    }
    
    # Check for updates
    $latestVersion = Test-Updates
    
    if (-not $latestVersion) {
        return
    }
    
    if ($Check) {
        return
    }
    
    # Use provided version or latest
    $targetVersion = if ($Version) { $Version } else { $latestVersion }
    
    # Download update
    $tempFile = Get-Update $targetVersion
    
    try {
        # Verify binary
        $newBinary = Test-Binary $tempFile
        
        if (-not $newBinary) {
            exit 1
        }
        
        # Create backup
        $backupFile = New-Backup
        
        # Apply update
        if (Set-Update $newBinary $backupFile) {
            Write-Success "Update completed successfully"
        }
        else {
            Write-Error "Update failed"
            exit 1
        }
    }
    finally {
        # Cleanup
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
        if ($newBinary -and (Test-Path (Split-Path $newBinary -Parent))) {
            Remove-Item (Split-Path $newBinary -Parent) -Recurse -Force
        }
    }
}

# Execute based on parameters
if ($Help) {
    Show-Help
}
else {
    Main
}