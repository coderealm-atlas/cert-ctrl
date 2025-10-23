#!/usr/bin/env pwsh
# run_all_test.ps1 - PowerShell wrapper to configure, build, and run the full CTest suite.

[CmdletBinding()]
param()

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
"@
}

$scriptDir = Split-Path -LiteralPath $MyInvocation.MyCommand.Path -Parent
$projectRoot = $scriptDir
$preset = 'debug'
$jobs = $null
$configureFirst = $true
$buildFirst = $true

for ($i = 0; $i -lt $args.Length; $i++) {
    switch ($args[$i]) {
        '--preset' {
            if ($i + 1 -ge $args.Length) {
                throw "Missing value for --preset option."
            }
            $preset = $args[$i + 1]
            $i++
        }
        '--jobs' {
            if ($i + 1 -ge $args.Length) {
                throw "Missing value for --jobs option."
            }
            $jobsValue = $args[$i + 1]
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
            throw "Unknown option: $($args[$i])`n$(Show-Usage)"
        }
    }
}

$presetFile = Join-Path -Path $projectRoot -ChildPath 'CMakePresets.json'
if (-not (Test-Path -Path $presetFile -PathType Leaf)) {
    throw "Error: CMakePresets.json not found in project root ($projectRoot)."
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw 'Error: cmake is not installed or not in PATH.'
}

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
    & cmake --build --preset $preset --target test
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
