# Copyright (C) 2026 Eclipse ThreadX contributors
#
# SPDX-License-Identifier: MIT
#
# Shared helpers for the NetX Duo Win64 build and test scripts.
# AI Disclosure: portions of this file were generated with Copilot (Claude Sonnet 4.6).
# Author: Frédéric Desbiens

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter()]
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Get-CommandPathIfAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName
    )

    $command = Get-Command $CommandName -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        return $null
    }

    return $command.Source
}

function Get-PortSettings {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelectedArch
    )

    switch ($SelectedArch) {
        'win64' {
            return @{
                NetXArch      = 'win64'
                NetXToolchain = 'vs_2022'
                VsArch        = 'amd64'
            }
        }
        default {
            throw "Unsupported architecture: $SelectedArch"
        }
    }
}

function Get-RegressionConfigurations {
    return @(
        'default_build_coverage',
        'v4_build',
        'v6_build'
    )
}

# Maps a CMake build-type name to a short filesystem-safe directory name.
# Covers all suites; falls back to the sanitized config name for unknowns.
function Get-ShortConfigName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigurationName
    )

    $knownNames = @{
        'default_build_coverage'        = 'dbc'
        'v4_build'                      = 'v4'
        'v6_build'                      = 'v6'
        'v6_full_build'                 = 'vf'
        'psk_build_coverage'            = 'psk'
        'tls_1_0_enable_build'          = 't10'
        'tls_1_1_enable_build'          = 't11'
        'tls_1_3_enable_build_coverage' = 't13'
        'client_disable_build'          = 'cld'
        'server_disable_build'          = 'svd'
        'tls_1_3_client_disable_build'  = 't3cd'
        'tls_1_3_server_disable_build'  = 't3sd'
        'ecjpake_build'                 = 'ejp'
        'dtls_build_coverage'           = 'dtls'
        'eal4_build_coverage'           = 'eal4'
        'sesip_build_coverage'          = 'ses'
        'no_ecc_build_coverage'         = 'necc'
        'no_renegotiation_build'        = 'nrn'
        'no_client_renegotiation_build' = 'ncr'
        'no_x509_build'                 = 'nx5'
        'hash_clone_build'              = 'hcl'
        'curve25519_448_build'          = 'c25'
        'secure_build_coverage'         = 'sec'
        'require_secure_build'          = 'req'
        'queue_depth_build'             = 'qd'
        'cloud_default_build_coverage'  = 'cldbc'
        'cloud_secure_build_coverage'   = 'clsec'
        'cloud_require_secure_build'    = 'clreq'
        'cloud_queue_depth_build'       = 'clqd'
        'websocket_secure_build'        = 'wssec'
        'gptp_slave_build'              = 'gpts'
        'gptp_master_build'             = 'gptm'
        'no_tls_build_coverage'         = 'ntls'
        'digest_authenticate_build'     = 'dauth'
        'fips_build_coverage'           = 'fips'
        'standalone_build'              = 'sa'
    }

    if ($knownNames.ContainsKey($ConfigurationName)) {
        return $knownNames[$ConfigurationName]
    }

    return $ConfigurationName -replace '[^a-zA-Z0-9_-]', '_'
}

# Generic configuration resolver. $ValidConfigurations is the full list for the suite.
function Resolve-Configurations {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ValidConfigurations,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object]$RequestedConfigurations = 'all'
    )

    $resolvedConfigurations = @()

    if ($null -eq $RequestedConfigurations) {
        $resolvedConfigurations = @('all')
    }
    elseif ($RequestedConfigurations -is [System.Array]) {
        foreach ($requestedConfiguration in $RequestedConfigurations) {
            if ($null -ne $requestedConfiguration) {
                $resolvedConfigurations += [string]$requestedConfiguration
            }
        }
    }
    else {
        $resolvedConfigurations = @([string]$RequestedConfigurations)
    }

    $normalizedConfigurations = @()
    foreach ($requestedConfiguration in $resolvedConfigurations) {
        foreach ($configurationPart in ($requestedConfiguration -split ',')) {
            $trimmedConfiguration = $configurationPart.Trim()
            if ($trimmedConfiguration.Length -gt 0) {
                $normalizedConfigurations += $trimmedConfiguration
            }
        }
    }

    if (($normalizedConfigurations.Count -eq 0) -or ($normalizedConfigurations -contains 'all')) {
        return $ValidConfigurations
    }

    foreach ($normalizedConfiguration in $normalizedConfigurations) {
        if ($ValidConfigurations -notcontains $normalizedConfiguration) {
            throw "Unsupported configuration: $normalizedConfiguration"
        }
    }

    return $normalizedConfigurations
}

function Resolve-RegressionConfigurations {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object]$RequestedConfigurations = 'all'
    )

    return Resolve-Configurations -ValidConfigurations (Get-RegressionConfigurations) `
                                  -RequestedConfigurations $RequestedConfigurations
}

function Get-RegressionBuildDirectoryName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigurationName
    )

    return Get-ShortConfigName -ConfigurationName $ConfigurationName
}

function Enter-VisualStudioDevShell {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VsArch
    )

    $targetArch = switch ($VsArch) {
        'amd64' { 'x64' }
        'x86'   { 'x86' }
        default { $VsArch }
    }

    if ((Get-Command cl -ErrorAction SilentlyContinue) -and ($env:VSCMD_ARG_TGT_ARCH -eq $targetArch)) {
        return
    }

    $vsWherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vsWherePath)) {
        throw "Unable to locate vswhere.exe at $vsWherePath"
    }

    $installationPath = & $vsWherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $installationPath) {
        throw 'Unable to locate a Visual Studio 2022 installation with MSVC build tools.'
    }

    $launchScript = Join-Path $installationPath 'Common7\Tools\Launch-VsDevShell.ps1'
    if (-not (Test-Path -LiteralPath $launchScript)) {
        throw "Unable to locate Launch-VsDevShell.ps1 at $launchScript"
    }

    $env:VSCMD_SKIP_SENDTELEMETRY = '1'
    & $launchScript -VsInstallationPath $installationPath -Arch $VsArch -HostArch amd64 -SkipAutomaticLocation | Out-Null

    if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
        throw 'MSVC compiler environment was not activated successfully.'
    }
}

function Remove-BuildDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $fullRepoRoot = [System.IO.Path]::GetFullPath($RepoRoot)
    $fullPath = [System.IO.Path]::GetFullPath($Path)

    if (-not $fullPath.StartsWith($fullRepoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a directory outside the repository: $fullPath"
    }

    if (Test-Path -LiteralPath $fullPath) {
        try {
            Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop
            return
        } catch {
            Write-Warning "Failed to remove build directory '$fullPath': $($_.Exception.Message)"
        }

        Get-ChildItem -LiteralPath $fullPath -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                if (($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
                    $_.Attributes = ($_.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly))
                }
            } catch {
            }
        }

        try {
            Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Warning "Proceeding with partially cleaned build directory '$fullPath': $($_.Exception.Message)"
        }
    }
}

function Remove-CtestTestingDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        return
    } catch {
        Write-Warning "Failed to remove CTest directory '$Path': $($_.Exception.Message)"
    }

    Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if (($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
                $_.Attributes = ($_.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly))
            }
        } catch {
        }
    }

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Warning "Proceeding with partially cleaned CTest directory '$Path': $($_.Exception.Message)"
    }
}

function Remove-NinjaLock {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $ninjaLockPath = Join-Path $Path '.ninja_lock'
    if (Test-Path -LiteralPath $ninjaLockPath) {
        Remove-Item -LiteralPath $ninjaLockPath -Force
    }
}

function Get-WindowsDebuggerPath {
    $debuggerPath = Get-CommandPathIfAvailable -CommandName 'cdb.exe'
    if ($debuggerPath) {
        return $debuggerPath
    }

    $candidatePaths = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x86\cdb.exe')
    )

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath) {
            return $candidatePath
        }
    }

    return $null
}

function Get-SanitizedFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $safeName = [regex]::Replace($Name, '[<>:"/\\|?*]', '_')
    $safeName = $safeName -replace '\s+', '_'
    return $safeName
}

function Initialize-MinidumpSupport {
    if ($null -ne ('NetXDuo.WindowsMiniDump' -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace NetXDuo
{
    public static class WindowsMiniDump
    {
        [DllImport("Dbghelp.dll", SetLastError = true)]
        private static extern bool MiniDumpWriteDump(
            IntPtr hProcess,
            uint processId,
            IntPtr hFile,
            uint dumpType,
            IntPtr exceptionParam,
            IntPtr userStreamParam,
            IntPtr callbackParam);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint ProcessQueryInformation = 0x0400U;
        private const uint ProcessVmRead = 0x0010U;
        private const uint ProcessDupHandle = 0x0040U;

        public static bool WriteDump(int processId, string dumpPath, uint dumpType, out int errorCode)
        {
            IntPtr processHandle = OpenProcess(ProcessQueryInformation | ProcessVmRead | ProcessDupHandle, false, processId);
            if (processHandle == IntPtr.Zero)
            {
                errorCode = Marshal.GetLastWin32Error();
                return false;
            }

            try
            {
                using (FileStream dumpStream = new FileStream(dumpPath, FileMode.Create, FileAccess.ReadWrite, FileShare.Read))
                {
                    bool success = MiniDumpWriteDump(
                        processHandle,
                        unchecked((uint)processId),
                        dumpStream.SafeFileHandle.DangerousGetHandle(),
                        dumpType,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero);

                    errorCode = success ? 0 : Marshal.GetLastWin32Error();
                    return success;
                }
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }
    }
}
'@
}

function Wait-FileReadable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [int]$TimeoutSeconds = 10
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-Path -LiteralPath $Path)) {
            Start-Sleep -Milliseconds 200
            continue
        }

        try {
            $fileStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $fileStream.Dispose()
            return $true
        }
        catch {
            Start-Sleep -Milliseconds 200
        }
    }

    return $false
}

function Get-CtestTestMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir
    )

    $ctestOutput = & ctest --test-dir $BuildDir --show-only=json-v1
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to enumerate ctest metadata in $BuildDir"
    }

    return (($ctestOutput -join [Environment]::NewLine) | ConvertFrom-Json).tests
}

function Get-CtestFailedTestNames {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestingTemporaryDir
    )

    $lastFailedPath = Join-Path $TestingTemporaryDir 'LastTestsFailed.log'
    if (-not (Test-Path -LiteralPath $lastFailedPath)) {
        return @()
    }

    $failedTestNames = @()
    foreach ($logLine in (Get-Content -LiteralPath $lastFailedPath)) {
        if ([string]::IsNullOrWhiteSpace($logLine)) {
            continue
        }

        if ($logLine -match '^\s*\d+:(?<name>.+)\s*$') {
            $failedTestNames += $Matches['name'].Trim()
        }
        else {
            $failedTestNames += $logLine.Trim()
        }
    }

    return $failedTestNames
}

function Invoke-ProcessDumpCapture {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,

        [Parameter(Mandatory = $true)]
        [string]$DumpPath,

        [Parameter()]
        [int]$TimeoutSeconds = 15
    )

    $outputDirectory = Split-Path -Parent $DumpPath
    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory | Out-Null
    }

    Remove-Item -LiteralPath $DumpPath -Force -ErrorAction SilentlyContinue

    Initialize-MinidumpSupport
    $dumpType = [uint32]0x00001006
    $errorCode = 0
    $dumpCaptured = [NetXDuo.WindowsMiniDump]::WriteDump($ProcessId, $DumpPath, $dumpType, [ref]$errorCode)

    if (-not $dumpCaptured) {
        Write-Warning "MiniDumpWriteDump failed for PID ${ProcessId} with Win32 error $errorCode"
        return $false
    }

    return (Test-Path -LiteralPath $DumpPath)
}

function Invoke-DumpStackAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DumpPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputBasePath,

        [Parameter()]
        [string]$SymbolPath,

        [Parameter()]
        [int]$TimeoutSeconds = 15
    )

    if (-not (Test-Path -LiteralPath $DumpPath)) {
        Write-Warning "Skipping dump analysis because the dump file was not created: $DumpPath"
        return $false
    }

    if (-not (Wait-FileReadable -Path $DumpPath)) {
        Write-Warning "Skipping dump analysis because the dump file is not readable yet: $DumpPath"
        return $false
    }

    $debuggerPath = Get-WindowsDebuggerPath
    if (-not $debuggerPath) {
        Write-Warning 'Skipping dump analysis because cdb.exe is not available.'
        return $false
    }

    $outputDirectory = Split-Path -Parent $OutputBasePath
    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory | Out-Null
    }

    $stdoutPath = "${OutputBasePath}.stdout.txt"
    $stderrPath = "${OutputBasePath}.stderr.txt"
    $commandFilePath = "${OutputBasePath}.commands.txt"
    Set-Content -LiteralPath $commandFilePath -Value @(
        '!runaway 7'
        '~* kb 200'
        'q'
    ) -Encoding Ascii
    $cdbArguments = @(
        '-lines',
        '-z', $DumpPath
    )

    if ($SymbolPath) {
        $cdbArguments += @('-y', $SymbolPath)
    }

    $cdbArguments += @('-cf', $commandFilePath)
    $cdbProcess = Start-Process -FilePath $debuggerPath -ArgumentList $cdbArguments -PassThru -NoNewWindow `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

    try {
        $cdbProcess | Wait-Process -Timeout $TimeoutSeconds -ErrorAction Stop
    }
    catch {
        if (-not $cdbProcess.HasExited) {
            $null = Start-Process -FilePath 'taskkill.exe' -ArgumentList @('/PID', $cdbProcess.Id.ToString(), '/T', '/F') `
                -WindowStyle Hidden -Wait -PassThru
        }
    }

    return $true
}

function Invoke-ProcessWithTimeout {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter()]
        [string[]]$Arguments = @(),

        [Parameter()]
        [int]$TimeoutSeconds = 0,

        [Parameter()]
        [string]$WorkingDirectory,

        [Parameter()]
        [string]$RedirectStandardOutputPath,

        [Parameter()]
        [string]$RedirectStandardErrorPath,

        [Parameter()]
        [scriptblock]$OnTimeout,

        [Parameter()]
        [scriptblock]$PostTimeout
    )

    $argumentList = @()
    foreach ($argument in $Arguments) {
        if ($argument -match '\s|"') {
            $argumentList += '"' + ($argument -replace '"', '\"') + '"'
        }
        else {
            $argumentList += $argument
        }
    }

    $startProcessParameters = @{
        FilePath    = $FilePath
        NoNewWindow = $true
        PassThru    = $true
    }

    if ($argumentList.Count -gt 0) {
        $startProcessParameters['ArgumentList'] = $argumentList
    }

    if ($WorkingDirectory) {
        $startProcessParameters['WorkingDirectory'] = $WorkingDirectory
    }

    if ($RedirectStandardOutputPath) {
        $startProcessParameters['RedirectStandardOutput'] = $RedirectStandardOutputPath
    }

    if ($RedirectStandardErrorPath) {
        $startProcessParameters['RedirectStandardError'] = $RedirectStandardErrorPath
    }

    $process = Start-Process @startProcessParameters
    if ($TimeoutSeconds -le 0) {
        $process | Wait-Process
        $completed = $true
    }
    else {
        try {
            $process | Wait-Process -Timeout $TimeoutSeconds -ErrorAction Stop
            $completed = $true
        }
        catch {
            $completed = $false
        }
    }

    if (-not $completed) {
        if ($null -ne $OnTimeout) {
            & $OnTimeout $process
        }

        $null = Start-Process -FilePath 'taskkill.exe' -ArgumentList @('/PID', $process.Id.ToString(), '/T', '/F') -WindowStyle Hidden -Wait -PassThru

        if ($null -ne $PostTimeout) {
            & $PostTimeout $process
        }

        return @{
            Completed = $false
            ExitCode  = $null
            ProcessId = $process.Id
        }
    }

    $process.Refresh()
    return @{
        Completed = $true
        ExitCode  = $process.ExitCode
        ProcessId = $process.Id
    }
}

function Invoke-CtestFailureDiagnostics {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,

        [Parameter(Mandatory = $true)]
        [string]$TestingTemporaryDir,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $failedTestNames = Get-CtestFailedTestNames -TestingTemporaryDir $TestingTemporaryDir
    if ($failedTestNames.Count -eq 0) {
        Write-Warning "No failed tests were recorded in $TestingTemporaryDir"
        return
    }

    $testMetadataList = Get-CtestTestMetadata -BuildDir $BuildDir
    $testMetadataMap = @{}
    foreach ($testMetadata in $testMetadataList) {
        $testMetadataMap[$testMetadata.name] = $testMetadata
    }

    $diagnosticsRoot = Join-Path $TestingTemporaryDir 'FailureDiagnostics'
    if (-not (Test-Path -LiteralPath $diagnosticsRoot)) {
        New-Item -ItemType Directory -Path $diagnosticsRoot | Out-Null
    }

    foreach ($failedTestName in $failedTestNames) {
        if (-not $testMetadataMap.ContainsKey($failedTestName)) {
            Write-Warning "Unable to locate ctest metadata for failed test: $failedTestName"
            continue
        }

        $testMetadata = $testMetadataMap[$failedTestName]
        if (($null -eq $testMetadata.command) -or ($testMetadata.command.Count -eq 0)) {
            Write-Warning "No executable command was recorded for failed test: $failedTestName"
            continue
        }

        $testArguments = @()
        if ($testMetadata.command.Count -gt 1) {
            $testArguments = @($testMetadata.command[1..($testMetadata.command.Count - 1)])
        }

        $safeTestName = Get-SanitizedFileName -Name $failedTestName
        $stdoutPath = Join-Path $diagnosticsRoot "${safeTestName}.stdout.txt"
        $stderrPath = Join-Path $diagnosticsRoot "${safeTestName}.stderr.txt"
        $debugOutputBasePath = Join-Path $diagnosticsRoot "${safeTestName}.cdb"
        $workingDirectory = $null
        $symbolDirectory = Split-Path -Parent $testMetadata.command[0]

        if ($null -ne $testMetadata.properties) {
            foreach ($testProperty in $testMetadata.properties) {
                if ($testProperty.name -eq 'WORKING_DIRECTORY') {
                    $workingDirectory = $testProperty.value
                    break
                }
            }
        }

        Write-Warning "Collecting failure diagnostics for $failedTestName"
        $dumpPath = '{0}.{1}.dmp' -f $debugOutputBasePath, ([DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff'))
        $testResult = Invoke-ProcessWithTimeout -FilePath $testMetadata.command[0] -Arguments $testArguments `
            -TimeoutSeconds $TimeoutSeconds -WorkingDirectory $workingDirectory -RedirectStandardOutputPath $stdoutPath `
            -RedirectStandardErrorPath $stderrPath -OnTimeout {
                param($timedOutProcess)
                Invoke-ProcessDumpCapture -ProcessId $timedOutProcess.Id -DumpPath $dumpPath | Out-Null
            } -PostTimeout {
                param($timedOutProcess)
                if (Test-Path -LiteralPath $dumpPath) {
                    Invoke-DumpStackAnalysis -DumpPath $dumpPath -OutputBasePath $debugOutputBasePath -SymbolPath $symbolDirectory | Out-Null
                }
            }

        if (-not $testResult.Completed) {
            Write-Warning "Timeout diagnostics were captured for $failedTestName under $diagnosticsRoot"
            continue
        }

        Write-Warning "Replay finished for $failedTestName with exit code $($testResult.ExitCode). Output was saved under $diagnosticsRoot"
    }
}

function Test-IsNinjaBuildDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir
    )

    return (Test-Path -LiteralPath (Join-Path $BuildDir 'build.ninja'))
}

function Get-NinjaBuildStatements {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir
    )

    $buildNinjaPath = Join-Path $BuildDir 'build.ninja'
    if (-not (Test-Path -LiteralPath $buildNinjaPath)) {
        throw "Unable to locate build.ninja in $BuildDir"
    }

    return Get-Content -LiteralPath $buildNinjaPath
}

function New-NinjaRspFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,

        [Parameter(Mandatory = $true)]
        [string]$RspRelativePath
    )

    $buildStatements = Get-NinjaBuildStatements -BuildDir $BuildDir
    $rspLine = '  RSP_FILE = ' + $RspRelativePath
    $rspIndex = -1

    for ($index = 0; $index -lt $buildStatements.Count; $index++) {
        if ($buildStatements[$index] -eq $rspLine) {
            $rspIndex = $index
            break
        }
    }

    if ($rspIndex -lt 0) {
        throw "Unable to locate RSP_FILE entry for $RspRelativePath in build.ninja."
    }

    $buildIndex = -1
    for ($index = $rspIndex; $index -ge 0; $index--) {
        if ($buildStatements[$index].StartsWith('build ')) {
            $buildIndex = $index
            break
        }
    }

    if ($buildIndex -lt 0) {
        throw "Unable to locate the build statement that owns $RspRelativePath."
    }

    $buildLine = $buildStatements[$buildIndex]
    if ($buildLine -notmatch '^build\s+\S+:\s+\S+\s+(.+)$') {
        throw "Unable to parse build statement for $RspRelativePath."
    }

    $rspContents = ($Matches[1] -split '\s+') -join [Environment]::NewLine
    $rspPath = Join-Path $BuildDir $RspRelativePath
    $rspParent = Split-Path -Parent $rspPath

    if (-not (Test-Path -LiteralPath $rspParent)) {
        New-Item -ItemType Directory -Path $rspParent | Out-Null
    }

    Set-Content -LiteralPath $rspPath -Value $rspContents
}

function Ensure-NinjaRspFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,

        [Parameter(Mandatory = $true)]
        [string]$CommandLine
    )

    $rspMatches = [regex]::Matches($CommandLine, '@(?<path>[^\s"]+\.rsp)')
    foreach ($rspMatch in $rspMatches) {
        $rspRelativePath = $rspMatch.Groups['path'].Value
        $rspPath = Join-Path $BuildDir $rspRelativePath
        if (-not (Test-Path -LiteralPath $rspPath)) {
            New-NinjaRspFile -BuildDir $BuildDir -RspRelativePath $rspRelativePath
        }
    }
}

function Get-PendingNinjaCommands {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir
    )

    $commandLines = & ninja -C $BuildDir -t commands
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to enumerate pending Ninja commands in $BuildDir"
    }

    return $commandLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
}

function Invoke-NinjaFallbackBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir
    )

    $pendingCommands = Get-PendingNinjaCommands -BuildDir $BuildDir
    if ($pendingCommands.Count -eq 0) {
        return
    }

    Push-Location $BuildDir
    try {
        foreach ($pendingCommand in $pendingCommands) {
            Ensure-NinjaRspFiles -BuildDir $BuildDir -CommandLine $pendingCommand

            $commandToRun = $pendingCommand -replace '\s/showIncludes(?=\s|$)', ''

            if ($commandToRun -match '^[^ ]*cmd(?:\.exe)?\s+/C\s+"(?<inner>.*)"\s*$') {
                & cmd.exe /C $Matches['inner']
            }
            else {
                & cmd.exe /C $commandToRun
            }

            if ($LASTEXITCODE -ne 0) {
                throw "Fallback Ninja command failed with exit code ${LASTEXITCODE}: $pendingCommand"
            }
        }
    }
    finally {
        Pop-Location
    }
}

function Invoke-CMakeBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,

        [Parameter(Mandatory = $true)]
        [int]$Parallel,

        [Parameter()]
        [int]$TimeoutSeconds = 0
    )

    Remove-NinjaLock -Path $BuildDir
    $isNinjaBuild = Test-IsNinjaBuildDirectory -BuildDir $BuildDir

    if ($TimeoutSeconds -le 0) {
        if ($isNinjaBuild) {
            Invoke-NativeCommand -FilePath 'ninja' -Arguments @(
                '-C', $BuildDir,
                '-j', $Parallel.ToString()
            )
        }
        else {
            Invoke-NativeCommand -FilePath 'cmake' -Arguments @(
                '--build', $BuildDir,
                '--parallel', $Parallel.ToString()
            )
        }
        return
    }

    if ($isNinjaBuild) {
        $buildToolName = 'Ninja'
        $buildResult = Invoke-ProcessWithTimeout -FilePath 'ninja' -Arguments @(
            '-C', $BuildDir,
            '-j', $Parallel.ToString()
        ) -TimeoutSeconds $TimeoutSeconds
    }
    else {
        $buildToolName = 'CMake'
        $buildResult = Invoke-ProcessWithTimeout -FilePath 'cmake' -Arguments @(
            '--build', $BuildDir,
            '--parallel', $Parallel.ToString()
        ) -TimeoutSeconds $TimeoutSeconds
    }

    if ($buildResult.Completed -and ($buildResult.ExitCode -eq 0)) {
        return
    }

    if (-not $isNinjaBuild) {
        if (-not $buildResult.Completed) {
            throw "$buildToolName build timed out after $TimeoutSeconds seconds in $BuildDir"
        }

        throw "$buildToolName build failed with exit code $($buildResult.ExitCode) in $BuildDir"
    }

    if ($buildResult.Completed) {
        throw "$buildToolName build failed with exit code $($buildResult.ExitCode) in $BuildDir"
    }

    Write-Warning "$buildToolName build timed out after $TimeoutSeconds seconds in $BuildDir. Replaying pending Ninja commands from PowerShell."

    Remove-NinjaLock -Path $BuildDir
    Invoke-NinjaFallbackBuild -BuildDir $BuildDir
}
