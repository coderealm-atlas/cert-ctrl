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
$reconfigCmake = $env:INSTALL_SERVICE_RECONFIG_CMAKE
$stampFile = "build\\w64\\.install-service-build.stamp"
$installPrefix = "install\\selfhost-windows"

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

function Set-GitProxyOverride {
  $proxy = $env:HTTPS_PROXY
  if (-not $proxy) { $proxy = $env:HTTP_PROXY }
  if (-not $proxy) { return }

  # Git config has precedence over HTTP_PROXY. Export command-scope config so
  # nested Git processes started by vcpkg cannot inherit a stale global proxy.
  $env:GIT_CONFIG_COUNT = "2"
  $env:GIT_CONFIG_KEY_0 = "http.proxy"
  $env:GIT_CONFIG_VALUE_0 = $proxy
  $env:GIT_CONFIG_KEY_1 = "https.proxy"
  $env:GIT_CONFIG_VALUE_1 = $proxy
}

function Sync-GitSubmodules {
  git submodule sync --recursive | ForEach-Object { Write-Host $_ }
  if ($LASTEXITCODE -ne 0) {
    throw "git submodule sync failed with exit code $LASTEXITCODE"
  }

  $proxy = $env:HTTPS_PROXY
  if (-not $proxy) { $proxy = $env:HTTP_PROXY }
  $gitProxyArgs = @()
  if ($proxy) {
    $gitProxyArgs = @("-c", "http.proxy=$proxy", "-c", "https.proxy=$proxy")
  }

  & git @gitProxyArgs submodule update --init --recursive --checkout --depth 1 |
    ForEach-Object { Write-Host $_ }
  if ($LASTEXITCODE -ne 0) {
    throw "git submodule update failed with exit code $LASTEXITCODE"
  }

  $status = Get-GitStatus
  if ($status.SubmoduleDirty) {
    throw "git submodules remain out of sync with the parent repository: $($status.Submodules)"
  }
  return $status
}

function Write-BuildInfo {
  param(
    [string]$InstallPrefix,
    [string]$BuildTarget,
    $GitStatus
  )

  $describe = $null
  try {
    $describe = (git describe --tags --long --dirty --abbrev=8 --match "v[0-9]*.[0-9]*.[0-9]*" --exclude "*-*" 2>$null).Trim()
  } catch { }
  if (-not $describe) {
    try { $describe = (git describe --tags --long --dirty --abbrev=8 2>$null).Trim() } catch { }
  }

  $info = [ordered]@{
    git_head        = $GitStatus.Head
    git_describe    = $describe
    git_dirty       = [bool]$GitStatus.Dirty
    submodule_dirty = [bool]$GitStatus.SubmoduleDirty
    build_target    = $BuildTarget
    platform        = "windows"
    timestamp_utc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  }

  if (-not (Test-Path $InstallPrefix)) {
    New-Item -ItemType Directory -Path $InstallPrefix -Force | Out-Null
  }
  $outPath = Join-Path $InstallPrefix "build-info.json"
  ($info | ConvertTo-Json -Depth 4) | Out-File -FilePath $outPath -Encoding utf8
}
# Note: Always run the CMake configure step before building (unless we early-exit
# due to an unchanged stamp). This avoids stale configure-time metadata such as
# version.h (git describe) when the repo updates.
if ($forceBuild -and ($forceBuild -eq "1" -or $forceBuild -eq "true" -or $forceBuild -eq "True")) {
  Remove-Item -Recurse -Force "build\\w64" -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force $installPrefix -ErrorAction SilentlyContinue
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

Set-GitProxyOverride
$gitStatus = Sync-GitSubmodules
$binaryName = $BuildTarget
if (-not $binaryName.ToLower().EndsWith(".exe")) {
  $binaryName = "${binaryName}.exe"
}
$binaryPath = Join-Path "$installPrefix\\bin" $binaryName
if (-not $forceBuild -and -not $gitStatus.Dirty -and -not $gitStatus.SubmoduleDirty -and (Test-Path $stampFile) -and (Test-Path $binaryPath)) {
  $stampContent = "git_head=$($gitStatus.Head)`nsubmodules=$($gitStatus.Submodules)`n"
  $existing = Normalize-Lf (Get-Content $stampFile -Raw)
  $expected = Normalize-Lf $stampContent
  if ($existing -eq $expected) {
    if (-not $reconfigCmake -or ($reconfigCmake -ne "1" -and $reconfigCmake -ne "true" -and $reconfigCmake -ne "True")) {
      Write-Host "No source changes detected; skipping build."
      Write-BuildInfo -InstallPrefix $installPrefix -BuildTarget $BuildTarget -GitStatus $gitStatus
      exit 0
    }
  }
}

if (-not (Test-Path "external\vcpkg\scripts\buildsystems\vcpkg.cmake")) {
  throw "vcpkg_missing"
}

if ($cmakeFresh) {
  cmake --preset w64 $cmakeFresh
} else {
  cmake --preset w64
}
cmake --build --preset w64 --target $BuildTarget
cmake --install build\w64 --config Release --prefix $installPrefix

$gitStatus = Get-GitStatus
$stampContent = "git_head=$($gitStatus.Head)`nsubmodules=$($gitStatus.Submodules)`n"
Set-Content -NoNewline -Path $stampFile -Value $stampContent

Write-BuildInfo -InstallPrefix $installPrefix -BuildTarget $BuildTarget -GitStatus $gitStatus
