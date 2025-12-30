# cert-ctrl self-hosted installer
$Version = $env:VERSION
if ([string]::IsNullOrEmpty($Version)) { $Version = "{{VERSION}}" }
$BaseUrl = "{{BASE_URL}}"

$InstallDir = $env:INSTALL_DIR
if ([string]::IsNullOrEmpty($InstallDir)) { $InstallDir = "$env:ProgramFiles\cert-ctrl" }

$Arch = "x64"
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $Arch = "arm64" }

$ArchiveName = "cert-ctrl-windows-$Arch.zip"
$DownloadUrl = "$BaseUrl/releases/proxy/$Version/$ArchiveName"
$ChecksumUrl = "$DownloadUrl.sha256"

$TempRoot = Join-Path $env:TEMP ("cert-ctrl-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempRoot -Force | Out-Null
$ArchivePath = Join-Path $TempRoot $ArchiveName

Write-Host "Downloading $DownloadUrl"
Invoke-WebRequest -Uri $DownloadUrl -OutFile $ArchivePath -UseBasicParsing

try {
  $ChecksumPath = "$ArchivePath.sha256"
  Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing
  if (Get-Command certutil.exe -ErrorAction SilentlyContinue) {
    $hashLine = (Get-Content $ChecksumPath | Select-Object -First 1).Split(' ')[0]
    $localHash = (certutil.exe -hashfile $ArchivePath SHA256 | Select-Object -Skip 1 -First 1).Trim()
    if ($hashLine -and $localHash -and ($hashLine -ne $localHash)) {
      Write-Error "Checksum verification failed"
      exit 1
    }
  }
} catch {
  Write-Host "Checksum not available; skipping verification."
}

Expand-Archive -Path $ArchivePath -DestinationPath $TempRoot -Force
$ExePath = Join-Path $TempRoot "cert-ctrl.exe"
if (-not (Test-Path $ExePath)) {
  Write-Error "cert-ctrl.exe not found in archive"
  exit 1
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $ExePath (Join-Path $InstallDir "cert-ctrl.exe") -Force

Write-Host "Installed cert-ctrl to $InstallDir\cert-ctrl.exe"
