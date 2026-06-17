# Copyright (C) 2026 Eclipse ThreadX contributors
#
# SPDX-License-Identifier: MIT
#
# Build script for the NetX Duo 64-bit Win64/VS 2022 regression test suite.
# AI Disclosure: portions of this file were generated with Copilot (Claude Sonnet 4.6).
# Author: Frédéric Desbiens
#
# Usage:
#   .\build_nxd64.ps1 [-Arch win64] [-Configuration all|<name>] [-ThreadXDir <path>]
#                     [-FilexDir <path>] [-BuildDir <path>] [-Clean] [-Parallel <n>]

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

    [string]$FilexDir,

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
    $BuildDir = Join-Path $repoRoot "build\tests\$Arch\nxd64"
}

if (-not $ThreadXDir) {
    $ThreadXDir = Join-Path (Split-Path -Parent $repoRoot) 'threadx-fd'
}

if (-not $FilexDir) {
    $FilexDir = Join-Path (Split-Path -Parent $repoRoot) 'filex-fd'
}

$BuildDir   = Resolve-AbsolutePath $BuildDir
$ThreadXDir = Resolve-AbsolutePath $ThreadXDir
$FilexDir   = Resolve-AbsolutePath $FilexDir

$validConfigurations = @('default_build_coverage')
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

    Write-Host "Configuring $Arch / netxduo64 / $currentConfiguration"
    Invoke-NativeCommand -FilePath 'cmake' -Arguments @(
        '-S', (Join-Path $repoRoot 'test\cmake\netxduo64'),
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
        "-DTHREADX_SOURCE_DIR=$ThreadXDir",
        "-DFILEX_SOURCE_DIR=$FilexDir"
    )

    Write-Host "Building $Arch / netxduo64 / $currentConfiguration"
    Invoke-CMakeBuild -BuildDir $currentBuildDir -Parallel $Parallel -TimeoutSeconds $BuildTimeoutSeconds
}
