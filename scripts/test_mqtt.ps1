# Copyright (C) 2026 Eclipse ThreadX contributors
#
# SPDX-License-Identifier: MIT
#
# Test script for the MQTT Win64/VS 2022 regression test suite.
# AI Disclosure: portions of this file were generated with Copilot (Claude Sonnet 4.6).
# Author: Frédéric Desbiens
#
# Usage:
#   .\test_mqtt.ps1 [-Arch win64] [-Configuration all|<name>] [-BuildDir <path>]
#                   [-TestRegex <regex>] [-RerunFailedOnly] [-Clean]

[CmdletBinding()]
param(
    [ValidateSet('win64', 'win32')]
    [string]$Arch = 'win64',

    [AllowNull()]
    [object]$Configuration = 'all',

    [int]$Parallel = [Math]::Max(1, [Environment]::ProcessorCount),

    [int]$RepeatFailCount = 1,

    [int]$TestTimeoutSeconds = 60,

    [switch]$CollectFailureDiagnostics = $true,

    [string]$TestRegex,

    [switch]$RerunFailedOnly,

    [string]$BuildDir,

    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'nx_windows_common.ps1')

$repoRoot = Split-Path -Parent $PSScriptRoot
$settings = Get-PortSettings -SelectedArch $Arch

if (-not $BuildDir) {
    $BuildDir = Join-Path $repoRoot "build\tests\$Arch\mqtt"
}

$validConfigurations = @(
    'default_build_coverage',
    'secure_build_coverage',
    'require_secure_build',
    'queue_depth_build',
    'cloud_default_build_coverage',
    'cloud_secure_build_coverage',
    'cloud_require_secure_build',
    'cloud_queue_depth_build',
    'websocket_secure_build'
)
$selectedConfigurations = Resolve-Configurations -ValidConfigurations $validConfigurations `
                                                 -RequestedConfigurations $Configuration
Write-Host "Selected configurations: $($selectedConfigurations -join ', ')"

Enter-VisualStudioDevShell -VsArch $settings.VsArch
if ($Parallel -ne 1) {
    Write-Warning "The Win64 ThreadX simulator pins all threads to a single core for deterministic scheduling. Running multiple test processes in parallel causes timer starvation. Forcing -Parallel 1."
    $Parallel = 1
}

$failedConfigurations = @()

foreach ($currentConfiguration in $selectedConfigurations) {
    $currentBuildDirName = Get-ShortConfigName -ConfigurationName $currentConfiguration
    $currentBuildDir = Join-Path $BuildDir $currentBuildDirName
    $currentTestingTemporaryDir = Join-Path $currentBuildDir 'Testing\Temporary'

    try {
        if ($Clean) {
            $currentTestingDir = Join-Path $currentBuildDir 'Testing'
            Remove-CtestTestingDirectory -Path $currentTestingDir
        }

        if (-not (Test-Path -LiteralPath $currentBuildDir)) {
            throw "Build directory does not exist for $Arch / mqtt / ${currentConfiguration}: $currentBuildDir"
        }

        Remove-NinjaLock -Path $currentBuildDir
        if (Test-Path -LiteralPath $currentTestingTemporaryDir) {
            Remove-Item -LiteralPath (Join-Path $currentTestingTemporaryDir 'LastTest.log') -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $currentTestingTemporaryDir 'LastTestsFailed.log') -Force -ErrorAction SilentlyContinue
        }

        Write-Host "Testing $Arch / mqtt / $currentConfiguration"
        $ctestArguments = @(
            '--test-dir', $currentBuildDir,
            '--output-on-failure',
            '--timeout', $TestTimeoutSeconds.ToString(),
            '-j', $Parallel.ToString()
        )

        if ($RepeatFailCount -gt 1) {
            $ctestArguments += @('--repeat', "until-pass:$RepeatFailCount")
        }

        if ($TestRegex) {
            $ctestArguments += @('-R', $TestRegex)
        }

        if ($RerunFailedOnly) {
            $ctestArguments += '--rerun-failed'
        }

        Invoke-NativeCommand -FilePath 'ctest' -Arguments $ctestArguments
    }
    catch {
        if ($CollectFailureDiagnostics -and (Test-Path -LiteralPath $currentBuildDir)) {
            try {
                Invoke-CtestFailureDiagnostics -BuildDir $currentBuildDir -TestingTemporaryDir $currentTestingTemporaryDir `
                    -TimeoutSeconds $TestTimeoutSeconds
            }
            catch {
                Write-Warning "Failure diagnostics collection failed for ${currentConfiguration}: $($_.Exception.Message)"
            }
        }

        $failedConfigurations += @{
            Configuration = $currentConfiguration
            Message = $_.Exception.Message
        }

        Write-Warning "Configuration failed: $currentConfiguration"
    }
}

if ($failedConfigurations.Count -gt 0) {
    Write-Host ''
    Write-Host 'Configuration failure summary:'
    foreach ($failedConfiguration in $failedConfigurations) {
        Write-Host "- $($failedConfiguration.Configuration): $($failedConfiguration.Message)"
    }

    throw "One or more configurations failed: $($failedConfigurations.Configuration -join ', ')"
}
