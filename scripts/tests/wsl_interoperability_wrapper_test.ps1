# Copyright (c) 2026 Eclipse ThreadX contributors
#
# SPDX-License-Identifier: MIT
# Portions of this file were generated with AI assistance.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$wrapper = Join-Path (Split-Path -Parent $PSScriptRoot) 'run_interoperability_wsl.ps1'

function Assert-Contains {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Output,

        [Parameter(Mandatory = $true)]
        [string]$Expected
    )

    if ($Output -notcontains $Expected) {
        throw "Expected output was not found: $Expected"
    }
}

$allOutput = @(& $wrapper -Suite all -Operation test -Configuration all `
    -Distribution Ubuntu-24.04 -LinuxRepositoryRoot /home/test/netxduo -DryRun)
Assert-Contains -Output $allOutput -Expected 'WSL_DISTRIBUTION=Ubuntu-24.04'
Assert-Contains -Output $allOutput -Expected 'LINUX_REPOSITORY_ROOT=/home/test/netxduo'
Assert-Contains -Output $allOutput -Expected 'RUN=mqtt_interoperability test all'
Assert-Contains -Output $allOutput -Expected 'RUN=nx_secure_interoperability test all'

$checkOutput = @(& $wrapper -Suite all -Operation test -Configuration all `
    -Distribution Ubuntu-24.04 -LinuxRepositoryRoot /home/test/netxduo -CheckOnly -DryRun)
Assert-Contains -Output $checkOutput -Expected 'CHECK_ONLY=true'

$profileOutput = @(& $wrapper -Suite secure -Operation build `
    -Configuration psk_build_coverage,tls_1_3_enable_build_coverage `
    -LinuxRepositoryRoot /home/test/netxduo -DryRun)
Assert-Contains -Output $profileOutput `
    -Expected 'RUN=nx_secure_interoperability build psk_build_coverage tls_1_3_enable_build_coverage'

$invalidCombinationRejected = $false
try {
    & $wrapper -Suite mqtt -Operation test -Configuration all,queue_depth_build `
        -LinuxRepositoryRoot /home/test/netxduo -DryRun | Out-Null
}
catch {
    $invalidCombinationRejected = $true
}

if (-not $invalidCombinationRejected) {
    throw 'The wrapper accepted all combined with a named configuration.'
}

$invalidDistributionRejected = $false
try {
    & $wrapper -Suite mqtt -Operation test -Configuration all `
        -Distribution '../invalid' -LinuxRepositoryRoot /home/test/netxduo -DryRun | Out-Null
}
catch {
    $invalidDistributionRejected = $true
}

if (-not $invalidDistributionRejected) {
    throw 'The wrapper accepted an invalid WSL distribution name.'
}

Write-Output 'WSL interoperability wrapper tests passed.'
