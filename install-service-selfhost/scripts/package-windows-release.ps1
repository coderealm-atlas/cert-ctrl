param(
  [string]$ReleaseVersion,
  [string]$InstallPrefix,
  [string]$AssetName,
  [string]$ArchiveExt,
  [string]$BinaryBasename,
  [string]$StagingRoot
)

$ErrorActionPreference = "Stop"

if (-not $ReleaseVersion -or -not $InstallPrefix -or -not $AssetName -or -not $ArchiveExt -or -not $BinaryBasename -or -not $StagingRoot) {
  throw "Missing required parameters."
}

$releaseDir = Join-Path $StagingRoot $ReleaseVersion
$tmpDir = Join-Path $StagingRoot (".tmp\$AssetName")
$archivePath = Join-Path $releaseDir "$AssetName$ArchiveExt"

if (-not (Test-Path $releaseDir)) { New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null }
if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null }

$candidates = @(
  (Join-Path $InstallPrefix "bin\$BinaryBasename.exe"),
  (Join-Path $InstallPrefix "bin\cert_ctrl.exe"),
  (Join-Path $InstallPrefix "$BinaryBasename.exe"),
  (Join-Path $InstallPrefix "cert_ctrl.exe")
)

$binaryPath = $null
foreach ($candidate in $candidates) {
  if (Test-Path $candidate) { $binaryPath = $candidate; break }
}

if (-not $binaryPath) {
  throw "Unable to locate cert-ctrl binary under $InstallPrefix"
}

$stagedBinary = Join-Path $tmpDir "$BinaryBasename.exe"
Copy-Item $binaryPath $stagedBinary -Force

if (Test-Path $archivePath) { Remove-Item $archivePath -Force }
Compress-Archive -Path $stagedBinary -DestinationPath $archivePath -Force

$hash = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLower()
$shaLine = $hash + "  " + [System.IO.Path]::GetFileName($archivePath)
$shaPath = "$archivePath.sha256"
$shaLine | Out-File -FilePath $shaPath -Encoding ascii
