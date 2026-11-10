# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Resolve a safe local filesystem path, or return null.

.DESCRIPTION
    Rejects UNC, provider-qualified, device-namespace, drive-relative,
    network-backed, SUBST-aliased, and reparse-point-backed paths.
    Relative paths resolve against PowerShell's current location, not the
    .NET process directory. Callers must use the returned absolute path.

    Provider and drive metadata are checked before filesystem inspection.
    The unresolved provider-path API normalizes paths without probing
    their targets; the root-to-leaf reparse walk precedes existence checks.

    Consumed by:
    - .github/skills/analyze-debug-files/Get-DebugFileMetadata.ps1
    - .github/skills/analyze-debug-files/Assert-BaselineTrusted.ps1
    - .github/skills/analyze-debug-files/Get-BaselineDependencyGraph.ps1
    - .github/skills/analyze-debug-files/Write-DebugAnalysisReport.ps1
    - .github/skills/trace-code-introduction/Trace-CodeIntroduction.ps1

.PARAMETER Path
    Caller-supplied path. Invalid or inaccessible paths return null.

.PARAMETER PathType
    Required existing item type: Container (default) or Leaf.

.PARAMETER AllowMissing
    Validate locality without requiring existence or enforcing PathType.
    Used for cache paths that may not have been created yet.

.OUTPUTS
    The validated absolute filesystem path, or null on refusal.
#>
. $PSScriptRoot\Test-IsLocalDosDeviceTarget.ps1
. $PSScriptRoot\Test-PathHasReparsePointRootToLeaf.ps1

function Resolve-SkillLocalPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [ValidateSet('Container', 'Leaf')]
        [string]$PathType = 'Container',

        [switch]$AllowMissing
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains("`0") -or $Path.Contains('::')) {
        return $null
    }
    if ($Path -match '^[\\/]{2}' -or $Path -match '^\\\?\?\\') {
        return $null
    }
    if ($Path -match '^([A-Za-z][A-Za-z0-9_+.-]*):' -and $Matches[1].Length -gt 1) {
        return $null
    }
    if ($Path -match '^[A-Za-z]:(?![\\/])') {
        return $null
    }

    try {
        $isWin = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
        if ($isWin) {
            if ($Path -match '^([A-Za-z]):[\\/]') {
                $inputDrive = $Matches[1]
            } else {
                $location = Get-Location
                if ($location.Provider.Name -ne 'FileSystem' -or
                    $location.ProviderPath -notmatch '^([A-Za-z]):[\\/]') {
                    return $null
                }
                $inputDrive = $Matches[1]
                if ($location.Drive.Root -notmatch '^[A-Za-z]:[\\/]?$') {
                    return $null
                }
            }
            $inputDriveInfo = Get-PSDrive -Name $inputDrive -ErrorAction Stop
            if ($inputDriveInfo.Provider.Name -ne 'FileSystem' -or
                $inputDriveInfo.Root.Replace('/', '\') -ine "${inputDrive}:\") {
                return $null
            }
        }

        $providerInfo = $null
        $driveInfo = $null
        $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $Path, [ref]$providerInfo, [ref]$driveInfo)
        if ($null -eq $providerInfo -or $providerInfo.Name -ne 'FileSystem') {
            return $null
        }
        $fullPath = [System.IO.Path]::GetFullPath($providerPath)
        if ($isWin) {
            if ($fullPath -notmatch '^[A-Za-z]:[\\/]' -or
                $null -eq $driveInfo -or $driveInfo.Root -notmatch '^[A-Za-z]:[\\/]?$') {
                return $null
            }
            $driveLetter = $fullPath.Substring(0, 1)
            $resolvedDriveInfo = Get-PSDrive -Name $driveLetter -ErrorAction Stop
            if ($resolvedDriveInfo.Provider.Name -ne 'FileSystem' -or
                $resolvedDriveInfo.Root.Replace('/', '\') -ine "${driveLetter}:\") {
                return $null
            }
            $volume = [System.IO.DriveInfo]::new("${driveLetter}:\")
            $allowed = @([System.IO.DriveType]::Fixed, [System.IO.DriveType]::Removable, [System.IO.DriveType]::Ram)
            if ($allowed -notcontains $volume.DriveType -or
                -not (Test-IsLocalDosDeviceTarget -DriveLetter "${driveLetter}:")) {
                return $null
            }
        } elseif ($fullPath -notmatch '^/') {
            return $null
        }
        if (Test-PathHasReparsePointRootToLeaf -Path $fullPath) {
            return $null
        }
        if (-not $AllowMissing -and -not (Test-Path -LiteralPath $fullPath -PathType $PathType -ErrorAction Stop)) {
            return $null
        }
        return $fullPath
    } catch {
        return $null
    }
}
