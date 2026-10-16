# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns $true when a bare drive letter maps to a real local volume,
    $false for SUBST/DefineDosDevice-created drives, raw DOS device aliases,
    or drives that fail QueryDosDevice.

.DESCRIPTION
    QueryDosDevice check: reject SUBST/DefineDosDevice-created drives
    (their target is `\??\<real path>`) and raw DOS device aliases
    (`\Device\<name>\<subpath>`). A real local volume maps to a bare
    `\Device\<name>` target with no trailing path component.

    `[System.IO.DriveInfo]` alone is not enough — a SUBST'd drive reports
    DriveType.Fixed but redirects to arbitrary targets (including UNC or
    reparse-point paths), so callers must combine DriveInfo with this
    check to close the SUBST bypass.

    Consumed by:
    - .github/skills/analyze-debug-files/Get-DebugFileMetadata.ps1
    - .github/skills/analyze-debug-files/SKILL.md (Step 5 code block)
    - .github/skills/trace-code-introduction/Trace-CodeIntroduction.ps1

.PARAMETER DriveLetter
    A single drive-letter token: bare (`C`) or colon-suffixed (`C:`). Any
    other shape — multi-character names (`NUL`, `CON`, `LPT1`), embedded
    path separators, empty strings, or non-ASCII characters — is rejected
    without calling `QueryDosDevice`. This defends against caller mistakes
    that would otherwise let multi-character DOS aliases (which resolve to
    a bare `\Device\<name>` target and match the local-volume shape check)
    slip through as "local drives."

.OUTPUTS
    [bool] — $true when the drive maps to `\Device\<name>` with no
    trailing path segment; otherwise $false.

.EXAMPLE
    PS> Test-IsLocalDosDeviceTarget -DriveLetter 'C:'
    True

.EXAMPLE
    PS> subst X: C:\Users
    PS> Test-IsLocalDosDeviceTarget -DriveLetter 'X:'
    False
#>
function Test-IsLocalDosDeviceTarget {
    param([Parameter(Mandatory)][string]$DriveLetter)
    # STRICT shape check first — reject anything that isn't a single ASCII
    # letter, optionally with a trailing colon. Multi-character DOS device
    # names like `NUL`, `CON`, `LPT1`, `COM1`, `PhysicalDrive0` also
    # resolve to a bare `\Device\<name>` target and would otherwise match
    # the local-volume regex below.
    if ($DriveLetter -notmatch '^[A-Za-z]:?$') { return $false }
    # QueryDosDevice requires the trailing colon; accept the bare drive
    # letter form to match the parameter contract and normalize here so
    # callers don't have to remember the format.
    $name = if ($DriveLetter.Length -eq 1) { "${DriveLetter}:" } else { $DriveLetter }
    if (-not ('SkillLib.DosDeviceHelper' -as [type])) {
        Add-Type -Namespace 'SkillLib' -Name 'DosDeviceHelper' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, uint maxChars);
'@ -ErrorAction Stop
    }
    $sb = New-Object System.Text.StringBuilder 1024
    $len = [SkillLib.DosDeviceHelper]::QueryDosDevice($name, $sb, 1024)
    if ($len -eq 0) { return $false }
    $target = $sb.ToString()
    return ($target -match '\A\\Device\\[^\\]+\z')
}
