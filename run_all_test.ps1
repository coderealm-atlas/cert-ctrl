#!/usr/bin/env pwsh
# run_all_test.ps1 - PowerShell wrapper to configure, build, and run the full CTest suite.

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8

$ArgumentList = @($args)

$ErrorActionPreference = 'Stop'

function Show-Usage {
    @"
Usage: .\run_all_test.ps1 [options]

Options:
  --preset <name>     CMake configure/build preset to use (default: debug)
  --jobs <n>          Override parallelism passed to CTest (CTEST_PARALLEL_LEVEL)
  --skip-configure    Skip the cmake --preset <name> configure step
  --skip-build        Skip the cmake --build step (requires artifacts already built)
  -h, --help          Show this help message

Examples:
    pwsh -NoProfile -File .\run_all_test.ps1 -- --preset release-compat --jobs 8
"@
}

function Get-CMakePresetsData {
    param(
        [Parameter(Mandatory)] [string] $SourceDir
    )

    $configurePresets = @()
    $buildPresets = @()

    foreach ($fileName in @('CMakePresets.json', 'CMakeUserPresets.json')) {
        $fullPath = Join-Path -Path $SourceDir -ChildPath $fileName
        if (Test-Path -Path $fullPath -PathType Leaf) {
            $json = Get-Content -Path $fullPath -Raw | ConvertFrom-Json
            if ($null -ne $json.configurePresets) {
                $configurePresets += $json.configurePresets
            }
            if ($null -ne $json.buildPresets) {
                $buildPresets += $json.buildPresets
            }
        }
    }

    [PSCustomObject]@{
        Configure = $configurePresets
        Build      = $buildPresets
    }
}

function Resolve-PresetBinaryDir {
    param(
        [Parameter(Mandatory)] [string] $SourceDir,
        [string] $BinaryDirValue,
        [string] $PresetName
    )

    if ([string]::IsNullOrWhiteSpace($BinaryDirValue)) {
        $fallback = Join-Path -Path $SourceDir -ChildPath (Join-Path 'build' $PresetName)
        return [System.IO.Path]::GetFullPath($fallback)
    }

    $resolved = $BinaryDirValue.Replace('${sourceDir}', $SourceDir)
    $resolved = [regex]::Replace($resolved, '\$env\{([^}]+)\}', {
        param($matches)
        $envValue = [Environment]::GetEnvironmentVariable($matches.Groups[1].Value)
        if ([string]::IsNullOrEmpty($envValue)) { return '' }
        return $envValue
    })

    return [System.IO.Path]::GetFullPath($resolved)
}

$isWindows = $false
try {
    $isWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
} catch {
    $isWindows = $false
}

function Ensure-VsBuildToolsOnPath {
    if (-not $isWindows) { return }

    if (Get-Command dumpbin -ErrorAction SilentlyContinue) {
        return
    }

    $vswhere = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -Path $vswhere -PathType Leaf)) {
        Write-Warning "Could not find vswhere.exe; dumpbin not added to PATH."
        return
    }

    $installationPath = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installationPath)) {
        Write-Warning "vswhere.exe did not return a Visual Studio installation path; dumpbin not added to PATH."
        return
    }

    $vcToolsRoot = Join-Path -Path $installationPath -ChildPath 'VC\Tools\MSVC'
    if (-not (Test-Path -Path $vcToolsRoot -PathType Container)) {
        Write-Warning "VS installation at '$installationPath' does not contain VC tools; dumpbin not added to PATH."
        return
    }

    $latestToolset = Get-ChildItem -Path $vcToolsRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $latestToolset) {
        Write-Warning "Unable to locate a VC toolset version under '$vcToolsRoot'."
        return
    }

    $binHostPath = Join-Path -Path $latestToolset.FullName -ChildPath 'bin\Hostx64\x64'
    if (-not (Test-Path -Path (Join-Path -Path $binHostPath -ChildPath 'dumpbin.exe') -PathType Leaf)) {
        Write-Warning "dumpbin.exe not found under '$binHostPath'."
        return
    }

    if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $binHostPath })) {
        $env:PATH = "$binHostPath;" + $env:PATH
        Write-Host "[run_all_test] Added Visual Studio tools to PATH: $binHostPath"
    }
}

$scriptDir = Split-Path -Path $PSCommandPath -Parent
$projectRoot = $scriptDir
$preset = 'windows-debug'
$jobs = $null
$configureFirst = $true
$buildFirst = $true

for ($i = 0; $i -lt $ArgumentList.Length; $i++) {
    if ($ArgumentList[$i] -eq '--') {
        continue
    }
    switch ($ArgumentList[$i]) {
        '--preset' {
            if ($i + 1 -ge $ArgumentList.Length) {
                throw "Missing value for --preset option."
            }
            $preset = $ArgumentList[$i + 1]
            $i++
        }
        '--jobs' {
            if ($i + 1 -ge $ArgumentList.Length) {
                throw "Missing value for --jobs option."
            }
            $jobsValue = $ArgumentList[$i + 1]
            try {
                $jobs = [int]$jobsValue
            } catch {
                throw "Invalid value for --jobs option: '$jobsValue'. Expected an integer."
            }
            if ($jobs -le 0) {
                throw "Invalid value for --jobs option: '$jobsValue'. Expected a positive integer."
            }
            $i++
        }
        '--skip-configure' {
            $configureFirst = $false
        }
        '--skip-build' {
            $buildFirst = $false
        }
        '-h' { Write-Host (Show-Usage); exit 0 }
        '--help' { Write-Host (Show-Usage); exit 0 }
        default {
            throw "Unknown option: $($ArgumentList[$i])`n$(Show-Usage)"
        }
    }
}

$presetFile = Join-Path -Path $projectRoot -ChildPath 'CMakePresets.json'
if (-not (Test-Path -Path $presetFile -PathType Leaf)) {
    throw "Error: CMakePresets.json not found in project root ($projectRoot)."
}

$presetsData = Get-CMakePresetsData -SourceDir $projectRoot
$buildPresetEntry = $presetsData.Build | Where-Object { $_.name -eq $preset } | Select-Object -First 1
$configurePresetName = if ($buildPresetEntry) { $buildPresetEntry.configurePreset } else { $preset }
$configurePresetEntry = $presetsData.Configure | Where-Object { $_.name -eq $configurePresetName } | Select-Object -First 1

if (-not $configurePresetEntry) {
    throw "Error: Preset '$preset' not found in CMake preset files."
}

$binaryDir = Resolve-PresetBinaryDir -SourceDir $projectRoot -BinaryDirValue $configurePresetEntry.binaryDir -PresetName $configurePresetName
$buildConfiguration = $null
if ($buildPresetEntry -and $buildPresetEntry.PSObject.Properties.Name -contains 'configuration') {
    $buildConfiguration = [string]$buildPresetEntry.configuration
}
elseif ($configurePresetEntry.cacheVariables -and $configurePresetEntry.cacheVariables.PSObject.Properties.Name -contains 'CMAKE_BUILD_TYPE') {
    $buildConfiguration = [string]$configurePresetEntry.cacheVariables.CMAKE_BUILD_TYPE
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw 'Error: cmake is not installed or not in PATH.'
}

if (-not (Get-Command ctest -ErrorAction SilentlyContinue)) {
    throw 'Error: ctest is not installed or not in PATH.'
}

Ensure-VsBuildToolsOnPath

if ($configureFirst) {
    Write-Host "[run_all_test] Configuring with preset '$preset'..."
    & cmake --preset $preset
    if ($LASTEXITCODE -ne 0) {
        throw "cmake configure step failed with exit code $LASTEXITCODE."
    }
}

if ($buildFirst) {
    Write-Host "[run_all_test] Building with preset '$preset'..."
    & cmake --build --preset $preset
    if ($LASTEXITCODE -ne 0) {
        throw "cmake build step failed with exit code $LASTEXITCODE."
    }
}

$originalCTestOutput = $env:CTEST_OUTPUT_ON_FAILURE
$originalCTestParallel = $env:CTEST_PARALLEL_LEVEL
$modifiedParallel = $false

try {
    $env:CTEST_OUTPUT_ON_FAILURE = '1'
    if ($null -ne $jobs) {
        $env:CTEST_PARALLEL_LEVEL = $jobs.ToString()
        $modifiedParallel = $true
    }

    Write-Host "[run_all_test] Running tests (preset: '$preset')..."
    $cacheFile = Join-Path -Path $binaryDir -ChildPath 'CMakeCache.txt'
    $generator = $null
    if (Test-Path -Path $cacheFile -PathType Leaf) {
        foreach ($line in Get-Content -Path $cacheFile) {
            if (-not $generator -and $line -like 'CMAKE_GENERATOR*') {
                $generator = ($line -split '=', 2)[1]
            }
            if ((-not $buildConfiguration -or [string]::IsNullOrWhiteSpace($buildConfiguration)) -and $line -like 'CMAKE_BUILD_TYPE*') {
                $buildConfiguration = ($line -split '=', 2)[1]
            }
        }
    }

    $isMultiConfig = $false
    if ($generator -and ($generator -match 'Visual Studio' -or $generator -match 'Xcode' -or $generator -match 'Multi-Config')) {
        $isMultiConfig = $true
    }

    if ($isMultiConfig -and [string]::IsNullOrWhiteSpace($buildConfiguration)) {
        $buildConfiguration = 'Debug'
    }

    $ctestArgs = @('--test-dir', $binaryDir, '--output-on-failure')
    if ($isMultiConfig -and -not [string]::IsNullOrWhiteSpace($buildConfiguration)) {
        $ctestArgs += @('-C', $buildConfiguration)
    }

    & ctest @ctestArgs
    if ($LASTEXITCODE -ne 0) {
        throw "CTest execution failed with exit code $LASTEXITCODE."
    }

    Write-Host "[run_all_test] All tests completed successfully."
}
finally {
    if ($null -eq $originalCTestOutput) {
        Remove-Item Env:CTEST_OUTPUT_ON_FAILURE -ErrorAction SilentlyContinue
    } else {
        $env:CTEST_OUTPUT_ON_FAILURE = $originalCTestOutput
    }

    if ($modifiedParallel) {
        if ($null -eq $originalCTestParallel) {
            Remove-Item Env:CTEST_PARALLEL_LEVEL -ErrorAction SilentlyContinue
        } else {
            $env:CTEST_PARALLEL_LEVEL = $originalCTestParallel
        }
    }
}
