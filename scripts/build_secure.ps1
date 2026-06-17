# Copyright (C) 2026 Eclipse ThreadX contributors
#
# SPDX-License-Identifier: MIT
#
# Build script for the NX Secure Win64/VS 2022 regression test suite.
# AI Disclosure: portions of this file were generated with Copilot (Claude Sonnet 4.6).
# Author: Frédéric Desbiens
#
# Usage:
#   .\build_secure.ps1 [-Arch win64] [-Configuration all|<name>] [-ThreadXDir <path>]
#                      [-BuildDir <path>] [-Clean] [-Parallel <n>]

[CmdletBinding()]
param(
    [ValidateSet('win64')]
    [string]$Arch = 'win64',

    [AllowNull()]
    [object]$Configuration = 'all',

    [int]$Parallel = [Math]::Max(1, [Environment]::ProcessorCount),

    [int]$BuildTimeoutSeconds = 600,

    [string]$BuildDir,

    [string]$ThreadXDir,

    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'nx_windows_common.ps1')

$repoRoot = Split-Path -Parent $PSScriptRoot
$settings = Get-PortSettings -SelectedArch $Arch

function Resolve-AbsolutePath([string]$Path) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

if (-not $BuildDir) {
    $BuildDir = Join-Path $repoRoot "build\tests\$Arch\secure"
}

if (-not $ThreadXDir) {
    $ThreadXDir = Join-Path (Split-Path -Parent $repoRoot) 'threadx-fd'
}

$BuildDir   = Resolve-AbsolutePath $BuildDir
$ThreadXDir = Resolve-AbsolutePath $ThreadXDir

$validConfigurations = @(
    'default_build_coverage',
    'psk_build_coverage',
    'tls_1_0_enable_build',
    'tls_1_1_enable_build',
    'tls_1_3_enable_build_coverage',
    'client_disable_build',
    'server_disable_build',
    'tls_1_3_client_disable_build',
    'tls_1_3_server_disable_build',
    'ecjpake_build',
    'dtls_build_coverage',
    'eal4_build_coverage',
    'sesip_build_coverage',
    'no_ecc_build_coverage',
    'no_renegotiation_build',
    'no_client_renegotiation_build',
    'no_x509_build',
    'hash_clone_build',
    'curve25519_448_build'
)
$selectedConfigurations = Resolve-Configurations -ValidConfigurations $validConfigurations `
                                                 -RequestedConfigurations $Configuration
Write-Host "Selected configurations: $($selectedConfigurations -join ', ')"

Enter-VisualStudioDevShell -VsArch $settings.VsArch

foreach ($currentConfiguration in $selectedConfigurations) {
    $currentBuildDirName = Get-ShortConfigName -ConfigurationName $currentConfiguration
    $currentBuildDir = Join-Path $BuildDir $currentBuildDirName

    if ($Clean) {
        Remove-BuildDirectory -Path $currentBuildDir -RepoRoot $repoRoot
    }

    Remove-NinjaLock -Path $currentBuildDir

    Write-Host "Configuring $Arch / nx_secure / $currentConfiguration"
    Invoke-NativeCommand -FilePath 'cmake' -Arguments @(
        '-S', (Join-Path $repoRoot 'test\cmake\nx_secure'),
        '-B', $currentBuildDir,
        '-G', 'Ninja',
        '-DCMAKE_C_COMPILER_FORCED=TRUE',
        '-DCMAKE_C_COMPILER_WORKS=TRUE',
        '-DCMAKE_C_ABI_COMPILED=TRUE',
        '-DCMAKE_ASM_COMPILER_FORCED=TRUE',
        '-DCMAKE_ASM_COMPILER_WORKS=TRUE',
        "-DCMAKE_BUILD_TYPE=$currentConfiguration",
        "-DTHREADX_ARCH=$($settings.NetXArch)",
        "-DTHREADX_TOOLCHAIN=$($settings.NetXToolchain)",
        "-DTHREADX_SOURCE_DIR=$ThreadXDir"
    )

    Write-Host "Building $Arch / nx_secure / $currentConfiguration"
    Invoke-CMakeBuild -BuildDir $currentBuildDir -Parallel $Parallel -TimeoutSeconds $BuildTimeoutSeconds
}
