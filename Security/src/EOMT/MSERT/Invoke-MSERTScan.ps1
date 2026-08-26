# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Confirm-Signature is loaded via Shared/ScriptUpdateFunctions/Confirm-Signature.ps1
# through the Test-ScriptVersion → Invoke-ScriptUpdate dot-source chain.

<#
.SYNOPSIS
    Downloads and runs the Microsoft Safety Scanner (MSERT) to detect known threats.

.DESCRIPTION
    This function automates the Microsoft Safety Scanner workflow:
    - Validates prerequisites (KB4474419 on Server 2008 R2)
    - Waits for any running mrt/msert processes to complete
    - Checks for sufficient disk space (>= 300 MB)
    - Downloads the appropriate msert.exe (32-bit or 64-bit)
    - Verifies the downloaded binary's digital signature
    - Runs a quick or full scan
    - Parses the scan log for detected threats

.PARAMETER RunFullScan
    Runs a full scan instead of a quick scan. Full scans can take hours or days.

.PARAMETER DoNotRemediate
    Passes the /N flag to MSERT so threats are detected but not removed.

.PARAMETER DoNotRunMSERT
    Skips the scan entirely. The function returns immediately with ScanCompleted = $false.

.PARAMETER WorkingDir
    Directory where msert.exe will be downloaded. Defaults to $env:TEMP.

.OUTPUTS
    PSCustomObject with properties:
        ScanCompleted   [bool]   - Whether the scan ran to completion.
        ThreatsDetected [bool]   - Whether MSERT reported any threats.
        ScanMode        [string] - "Quick Scan", "Full Scan", or "Skipped".
        LogPath         [string] - Path to the msert.log file, or empty string.

.EXAMPLE
    Invoke-MSERTScan -RunFullScan -Verbose

.EXAMPLE
    Invoke-MSERTScan -DoNotRemediate -WorkingDir "C:\Temp"
#>
function Invoke-MSERTScan {
    [CmdletBinding()]
    param(
        [switch]$RunFullScan,
        [switch]$DoNotRemediate,
        [switch]$DoNotRunMSERT,
        [string]$WorkingDir = $env:TEMP
    )

    $msertLogPath = Join-Path -Path $env:SystemRoot -ChildPath "debug\msert.log"
    $msertLogArchivePath = Join-Path -Path $env:SystemRoot -ChildPath "debug\msert.old.log"

    # Helper to build the result object returned from every exit path.
    function Get-ScanResult {
        param(
            [bool]$ScanCompleted = $false,
            [bool]$ThreatsDetected = $false,
            [string]$ScanMode = "Skipped",
            [string]$LogPath = ""
        )
        [PSCustomObject]@{
            ScanCompleted   = $ScanCompleted
            ThreatsDetected = $ThreatsDetected
            ScanMode        = $ScanMode
            LogPath         = $LogPath
        }
    }

    # --- Early exit when scan is explicitly skipped ---
    if ($DoNotRunMSERT) {
        Write-Verbose "Skipping MSERT scan (-DoNotRunMSERT) on $env:COMPUTERNAME"
        return (Get-ScanResult)
    }

    # --- Prerequisite: KB4474419 on Server 2008 R2 ---
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 1) {
        $hotfix = Get-HotFix -Id KB4474419 -ErrorAction SilentlyContinue
        if (-not $hotfix) {
            Write-Warning "KB4474419 is missing on Server 2008 R2 – MSERT cannot run."
            return (Get-ScanResult)
        }
    }

    # --- Wait for any existing mrt / msert process ---
    $processToWaitFor = @("mrt", "msert")
    :checkForRunningCleaner while ($true) {
        foreach ($procName in $processToWaitFor) {
            $existingProc = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($existingProc) {
                $pIds = ($existingProc.Id -join ",")
                Write-Verbose "Found $procName already running (PID: $pIds). Waiting 60 seconds..."
                Start-Sleep -Seconds 60
                continue checkForRunningCleaner
            }
        }
        break
    }

    # --- Check free disk space (>= 300 MB) ---
    $workingDrive = (Get-Item -Path $WorkingDir -ErrorAction SilentlyContinue)
    if ($null -eq $workingDrive) {
        Write-Warning "Working directory '$WorkingDir' does not exist."
        return (Get-ScanResult)
    }

    $freeBytes = $workingDrive.PSDrive.Free
    $requiredBytes = 314572800  # 300 MB
    if ($freeBytes -lt $requiredBytes) {
        $driveRoot = $workingDrive.PSDrive.Root
        Write-Warning ("Insufficient disk space on $driveRoot. " +
            "At least 300 MB is required (available: $([math]::Round($freeBytes / 1MB, 0)) MB).")
        return (Get-ScanResult)
    }

    # --- Download msert.exe ---
    if ([System.Environment]::Is64BitOperatingSystem) {
        $msertUrl = "https://go.microsoft.com/fwlink/?LinkId=212732"
    } else {
        $msertUrl = "https://go.microsoft.com/fwlink/?LinkId=212733"
    }

    $msertExe = Join-Path -Path $WorkingDir -ChildPath "msert.exe"
    Write-Verbose "Downloading Microsoft Safety Scanner to $msertExe"

    try {
        $response = Invoke-WebRequest -Uri $msertUrl -UseBasicParsing
        [IO.File]::WriteAllBytes($msertExe, $response.Content)
        Write-Verbose "MSERT download complete on $env:COMPUTERNAME"
    } catch {
        Write-Warning "MSERT download failed: $_"
        return (Get-ScanResult)
    }

    # --- Verify digital signature ---
    if (-not (Confirm-Signature -File $msertExe)) {
        Write-Warning "The file at $msertExe does not appear to be signed as expected. Aborting scan."
        return (Get-ScanResult)
    }

    # --- Determine scan mode ---
    $scanMode = if ($RunFullScan) { "Full Scan" } else { "Quick Scan" }
    if ($DoNotRemediate) {
        $scanMode += " (No Remediation)"
    }

    # --- Archive previous log ---
    if (Test-Path -Path $msertLogPath) {
        Get-Content -Path $msertLogPath | Out-File -FilePath $msertLogArchivePath -Append
        Remove-Item -Path $msertLogPath -Force
    }

    # --- Build arguments ---
    $msertArguments = if ($RunFullScan) { "/F /Q" } else { "/Q" }
    if ($DoNotRemediate) {
        $msertArguments += " /N"
    }

    # --- Run the scan ---
    Write-Verbose "Running Microsoft Safety Scanner – Mode: $scanMode on $env:COMPUTERNAME"
    if ($RunFullScan) {
        Write-Warning "A full scan can take hours or days to complete."
    } else {
        Write-Verbose "Quick scan will take several minutes to complete, please wait..."
    }

    Start-Process -FilePath $msertExe -ArgumentList $msertArguments -Wait

    # --- Parse results ---
    $threatsDetected = $false

    if (Test-Path -Path $msertLogPath) {
        $logMatches = Select-String -Path $msertLogPath -Pattern "Threat Detected"
        if ($logMatches) {
            $threatsDetected = $true
            Write-Warning "THREATS DETECTED on $env:COMPUTERNAME! Review '$msertLogPath' immediately."
            if (-not $RunFullScan) {
                Write-Warning "We strongly recommend re-running with -RunFullScan."
            }
        } else {
            Write-Verbose "Microsoft Safety Scanner complete on $env:COMPUTERNAME – no known threats detected."
        }
    } else {
        Write-Warning "Expected scanner log not found at $msertLogPath."
        return (Get-ScanResult -ScanMode $scanMode)
    }

    $scanResult = @{
        ScanCompleted   = $true
        ThreatsDetected = $threatsDetected
        ScanMode        = $scanMode
        LogPath         = $msertLogPath
    }
    return (Get-ScanResult @scanResult)
}
