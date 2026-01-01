param(
  [string]$RepoPath,
  [string]$BuildTarget
)

$ErrorActionPreference = "Stop"

if (-not $RepoPath) {
  $RepoPath = $env:INSTALL_SERVICE_REPO_PATH
}
if (-not $RepoPath) {
  $RepoPath = (Get-Location).Path
}
Set-Location $RepoPath

if (-not $BuildTarget) {
  $BuildTarget = $env:BUILD_TARGET
}
if (-not $BuildTarget) {
  $BuildTarget = "cert_ctrl"
}

$forceBuild = $env:INSTALL_SERVICE_FORCE_BUILD
$stampFile = "build\\w64\\.install-service-build.stamp"

function Normalize-Lf {
  param([string]$Value)
  return ($Value -replace "`r`n", "`n")
}

function Get-GitStatus {
  $gitHead = (git rev-parse HEAD 2>$null).Trim()
  $gitDirty = $false
  git diff --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) { $gitDirty = $true }
  git diff --cached --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) { $gitDirty = $true }
  $submoduleStatus = (git submodule status 2>$null) | Out-String
  $submoduleDirty = $false
  foreach ($line in ($submoduleStatus -split "`n")) {
    if ($line -match '^[\-\+U]') { $submoduleDirty = $true; break }
  }
  return @{
    Head = $gitHead
    Dirty = $gitDirty
    Submodules = $submoduleStatus.TrimEnd()
    SubmoduleDirty = $submoduleDirty
  }
}
if (Test-Path "build\\w64\\CMakeCache.txt") {
  $hasCache = $true
} else {
  $hasCache = $false
}
if ($forceBuild -and ($forceBuild -eq "1" -or $forceBuild -eq "true" -or $forceBuild -eq "True")) {
  Remove-Item -Recurse -Force "build\\w64" -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force "install\\selfhost-windows" -ErrorAction SilentlyContinue
  $cmakeFresh = "--fresh"
} else {
  $cmakeFresh = $null
}

function Import-VsEnv {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
  if (-not (Test-Path $vswhere)) { return }
  $vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
  if (-not $vsInstall) { return }
  $vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
  if (-not (Test-Path $vcvars)) { return }
  $envBlock = cmd /c "`"$vcvars`" >nul && set"
  foreach ($line in $envBlock) {
    if ($line -match '^(?<name>[^=]+)=(?<val>.*)$') {
      [Environment]::SetEnvironmentVariable($matches.name, $matches.val)
    }
  }
}

Import-VsEnv
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
  throw "MSVC toolchain not available (cl.exe not found)."
}

$gitStatus = Get-GitStatus
$binaryName = $BuildTarget
if (-not $binaryName.ToLower().EndsWith(".exe")) {
  $binaryName = "${binaryName}.exe"
}
$binaryPath = Join-Path "install\\selfhost-windows\\bin" $binaryName
if (-not $forceBuild -and -not $gitStatus.Dirty -and -not $gitStatus.SubmoduleDirty -and (Test-Path $stampFile) -and (Test-Path $binaryPath)) {
  $stampContent = "git_head=$($gitStatus.Head)`nsubmodules=$($gitStatus.Submodules)`n"
  $existing = Normalize-Lf (Get-Content $stampFile -Raw)
  $expected = Normalize-Lf $stampContent
  if ($existing -eq $expected) {
    Write-Host "No source changes detected; skipping build."
    exit 0
  }
}

git submodule sync --recursive
git submodule update --init --recursive

if (-not (Test-Path "external\vcpkg\scripts\buildsystems\vcpkg.cmake")) {
  throw "vcpkg_missing"
}

if (-not $hasCache -or $cmakeFresh) {
  if ($cmakeFresh) {
    cmake --preset w64 $cmakeFresh
  } else {
    cmake --preset w64
  }
}
cmake --build --preset w64 --target $BuildTarget
cmake --install build\w64 --config Release --prefix install\selfhost-windows

$gitStatus = Get-GitStatus
$stampContent = "git_head=$($gitStatus.Head)`nsubmodules=$($gitStatus.Submodules)`n"
Set-Content -NoNewline -Path $stampFile -Value $stampContent
