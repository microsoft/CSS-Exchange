# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Finds the earliest CSS-Exchange GitHub release that shipped a specific
    script version.
.DESCRIPTION
    CSS-Exchange script versions (YY.MM.DD.HHMM) are per-script build stamps
    derived from the newest commit timestamp of the script's sources. They are
    not repo tags, and the same version can appear in multiple consecutive
    releases (with different signed bytes each time).

    This function answers: "which GitHub release first shipped this build of
    the source?"

    Strategy: enumerate GitHub releases (via `gh release list`, not `git tag`)
    whose tag date is on or after the script version's date, download
    ScriptVersions.csv from each in ascending order, and stop at the first
    matching File + Version pair.

    The result includes a Status field so callers can distinguish "confirmed
    earliest" from "matched, but earlier candidates were not inspected
    cleanly" and from "not found within the search window."
.PARAMETER ScriptName
    The script name, with or without .ps1 (e.g., "HealthChecker" or
    "HealthChecker.ps1"). Only these characters are accepted: [A-Za-z0-9._-].
.PARAMETER Version
    The script version string in YY.MM.DD.HHMM format (e.g., "26.03.12.1424").
.PARAMETER MaxCandidates
    Maximum number of candidate releases to inspect. Default: 30. Because
    release cadence in this repo has ranged from days to months, keep this
    generous unless you are diagnosing a specific known range.
.PARAMETER WorkFolder
    Optional folder for CSV downloads. If omitted, a per-run folder under
    $env:TEMP is created and removed. If supplied, only files this invocation
    creates are removed; the folder and its other contents are preserved.
.PARAMETER Repository
    GitHub owner/repo to query. Defaults to "microsoft/CSS-Exchange".
.EXAMPLE
    .\Find-ReleaseTagForScriptVersion.ps1 -ScriptName HealthChecker -Version 26.03.12.1424
.NOTES
    Requires gh on PATH and authenticated. ScriptVersions.csv was not
    published on releases before v21.04.14.1849; older versions cannot be
    resolved by this method.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('\A[A-Za-z0-9._-]+\z')]
    [string]$ScriptName,

    [Parameter(Mandatory)]
    [string]$Version,

    [ValidateRange(1, 500)]
    [int]$MaxCandidates = 30,

    [string]$WorkFolder,

    [ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+\z')]
    [string]$Repository = "microsoft/CSS-Exchange"
)

# Explicitly disable native-command error promotion inside this script's
# scope. If the caller enabled $PSNativeCommandUseErrorActionPreference
# (default in PowerShell 7.4+ under some profiles), a nonzero `gh` exit
# would throw NativeCommandExitException BEFORE our `$LASTEXITCODE`
# handling ran — turning the structured `Status = 'GhUnavailable' /
# 'NotFound' / 'Error'` result contract this script advertises into an
# unhandled terminating error.
$PSNativeCommandUseErrorActionPreference = $false

# Bounds for untrusted content that enters the return object (to keep both the
# on-disk payload and the agent-visible output manageable and non-hostile).
$script:MaxCsvBytes = 1MB
$script:MaxDetailChars = 256

function ConvertTo-VersionDateTime {
    param([string]$VersionString)
    if ($VersionString -notmatch '\A([0-9]{2})\.([0-9]{2})\.([0-9]{2})\.([0-9]{2})([0-9]{2})\z') {
        throw "Version is not in the expected YY.MM.DD.HHMM format."
    }
    $yy = [int]$Matches[1]; $mm = [int]$Matches[2]; $dd = [int]$Matches[3]
    $hh = [int]$Matches[4]; $mi = [int]$Matches[5]
    try {
        return [datetime]::new(2000 + $yy, $mm, $dd, $hh, $mi, 0, [DateTimeKind]::Utc)
    } catch {
        throw "Version has an invalid calendar date/time."
    }
}

function ConvertTo-TagDateTime {
    param([string]$TagName)
    if ($TagName -notmatch '\Av([0-9]{2})\.([0-9]{2})\.([0-9]{2})\.([0-9]{2})([0-9]{2})\z') {
        return $null
    }
    try {
        $yy = [int]$Matches[1]; $mm = [int]$Matches[2]; $dd = [int]$Matches[3]
        $hh = [int]$Matches[4]; $mi = [int]$Matches[5]
        return [datetime]::new(2000 + $yy, $mm, $dd, $hh, $mi, 0, [DateTimeKind]::Utc)
    } catch {
        return $null
    }
}

function ConvertTo-SafeDetail {
    param([object]$Value)
    if ($null -eq $Value) { return "<null>" }
    $text = [string]$Value
    $text = $text -replace '[\p{C}]', ' '
    if ($text.Length -gt $script:MaxDetailChars) {
        $text = $text.Substring(0, $script:MaxDetailChars - 3) + "..."
    }
    return $text
}

function Resolve-ProviderPath {
    param([string]$Path)
    # Return the resolved FileSystem-provider path for a caller-supplied string,
    # or $null if the path is not backed by the FileSystem provider or fails
    # to resolve. A PSDrive backed by a UNC root (e.g. New-PSDrive -Root
    # \\server\share) resolves to its UNC root here even though its DriveInfo
    # type is NoRootDirectory.
    try {
        $providerInfo = $null
        $driveInfo = $null
        $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $Path, [ref]$providerInfo, [ref]$driveInfo)
        if ($null -eq $providerInfo -or $providerInfo.Name -ne 'FileSystem') {
            return $null
        }
        return $resolved
    } catch {
        return $null
    }
}

function Test-PathHasReparsePoint {
    param([string]$Path)
    # Walk ROOT-to-LEAF so we never probe a descendant before confirming its
    # ancestor is not a reparse point. Test-Path/Get-Item on a descendant
    # under a directory symlink would touch the symlink's target (potentially
    # UNC), which is exactly what this check exists to prevent.
    try {
        $root = [System.IO.Path]::GetPathRoot($Path)
        if ([string]::IsNullOrEmpty($root)) { return $true }
        $relative = $Path.Substring($root.Length).TrimStart('\', '/')
        $segments = if ([string]::IsNullOrEmpty($relative)) { @() } else { $relative -split '[\\/]' }
        $cumulative = $root
        foreach ($seg in $segments) {
            if ([string]::IsNullOrEmpty($seg)) { continue }
            $cumulative = [System.IO.Path]::Combine($cumulative, $seg)
            try {
                $item = Get-Item -LiteralPath $cumulative -Force -ErrorAction Stop
                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    return $true
                }
            } catch [System.Management.Automation.ItemNotFoundException] {
                # This component doesn't exist yet; no ancestor was a reparse
                # point, so the path is safe up to this point.
                return $false
            } catch {
                # Access denied, broken link, or other metadata error: treat
                # as unsafe rather than assume no reparse point.
                return $true
            }
        }
        return $false
    } catch {
        return $true
    }
}

function Test-IsSafeLocalPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    # Reject PowerShell provider-qualified paths (e.g. FileSystem::\\host\share)
    if ($Path.Contains('::')) { return $false }
    # Reject NT device namespace, extended-length UNC, and any UNC prefix
    if ($Path -match '^\\\?\?\\') { return $false }
    if ($Path -match '^\\\\\?\\UNC[\\/]') { return $false }
    if ($Path -match '^(\\\\|//)') { return $false }

    # PSDrive shadow guard: a single-letter PSDrive (e.g.
    # `New-PSDrive -Name X -PSProvider FileSystem -Root '\\attacker\share'`
    # or `... -PSProvider Env`) can shadow the OS drive letter within a
    # PowerShell session. `Resolve-ProviderPath` invokes
    # `GetUnresolvedProviderPathFromPSPath`, which routes through the
    # PowerShell provider system and follows the shadowed target — the
    # later UNC / DriveInfo / QueryDosDevice checks then speak for the
    # OS drive, not for the path Resolve just walked. Reject the input
    # lexically here before any provider work runs.
    $isWinInput = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    if ($isWinInput -and $Path -match '^([A-Za-z]):[\\/]?') {
        $inputDrive = $Matches[1]
        try {
            $inputPsd = Get-PSDrive -Name $inputDrive -ErrorAction SilentlyContinue
            if ($null -ne $inputPsd) {
                if ($inputPsd.Provider.Name -ne 'FileSystem') { return $false }
                if ($inputPsd.Root -notmatch '^[A-Za-z]:[\\/]?$') { return $false }
            }
        } catch { return $false }
    }

    # Resolve PSDrive-relative paths (e.g. Z:\x where Z: maps to \\server\share)
    # to their provider-native form. Non-FileSystem drives (HKCU:, Env:, ...)
    # return $null.
    $resolved = Resolve-ProviderPath -Path $Path
    if ([string]::IsNullOrWhiteSpace($resolved)) { return $false }
    if ($resolved.Contains('::')) { return $false }
    if ($resolved -match '^\\\?\?\\') { return $false }
    if ($resolved -match '^\\\\\?\\UNC[\\/]') { return $false }
    if ($resolved -match '^(\\\\|//)') { return $false }

    try {
        $full = [System.IO.Path]::GetFullPath($resolved)
    } catch {
        return $false
    }
    if ($full.Contains('::')) { return $false }
    if ($full -match '^(\\\\|//)') { return $false }
    if ($full -match '^\\\\\?\\UNC[\\/]') { return $false }
    # Require a drive-letter root on Windows, or a leading / on non-Windows.
    # NOTE: Network-filesystem-mount detection on non-Windows platforms is not
    # implemented; SKILL.md documents that this helper is intended for Windows.
    # Use [Environment]::OSVersion.Platform so this works under Windows PowerShell 5.1
    # with StrictMode where $IsWindows is not defined.
    $isWin = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    if ($isWin) {
        if ($full -notmatch '^([A-Za-z]):[\\/]') { return $false }
        $resolvedDrive = $Matches[1]
        # Belt-and-braces: re-check the resolved drive against any
        # PSDrive shadowing. The lexical check above covered the raw
        # input; this covers the (unusual) case where Resolve-
        # ProviderPath emerges with a different drive letter.
        try {
            $resolvedPsd = Get-PSDrive -Name $resolvedDrive -ErrorAction SilentlyContinue
            if ($null -ne $resolvedPsd) {
                if ($resolvedPsd.Provider.Name -ne 'FileSystem') { return $false }
                if ($resolvedPsd.Root -notmatch '^[A-Za-z]:[\\/]?$') { return $false }
            }
        } catch { return $false }
        # Allowlist real local drive types. Reject Network, NoRootDirectory,
        # Unknown, and CDRom explicitly.
        try {
            $driveRoot = $full.Substring(0, 3)
            $driveInfoObj = [System.IO.DriveInfo]::new($driveRoot)
            $allowed = @(
                [System.IO.DriveType]::Fixed
                [System.IO.DriveType]::Removable
                [System.IO.DriveType]::Ram
            )
            if ($allowed -notcontains $driveInfoObj.DriveType) { return $false }
        } catch {
            return $false
        }
        # Reject SUBST drives: their DOS device mapping is a symbolic link
        # into another path (\??\X:\...), so the reparse-point walk below
        # would start at the SUBST root and never traverse a symlink that
        # sits in the real target's ancestry. Real local volumes map to
        # bare \Device\<name> targets.
        try {
            if (-not ('Skill.DosDeviceHelper' -as [type])) {
                Add-Type -Namespace 'Skill' -Name 'DosDeviceHelper' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, uint maxChars);
'@ -ErrorAction Stop
            }
            $sb = New-Object System.Text.StringBuilder 1024
            $driveLetter = $full.Substring(0, 2)
            $len = [Skill.DosDeviceHelper]::QueryDosDevice($driveLetter, $sb, 1024)
            if ($len -eq 0) { return $false }
            $devTarget = $sb.ToString()
            # Real local volumes map to a bare device name (\Device\<name>)
            # with no appended path. Reject any target that isn't of that
            # exact form. This covers:
            #   - SUBST drives (\??\C:\some\path)
            #   - Raw DOS device aliases created via
            #     DefineDosDevice(DDD_RAW_TARGET_PATH, ...) that point at a
            #     subdirectory of a real volume (\Device\<name>\...),
            #     which could hide a reparse point in its own ancestry.
            if ($devTarget -notmatch '\A\\Device\\[^\\]+\z') { return $false }
        } catch {
            return $false
        }
        # Reject any existing reparse point (symlink/junction/DFS link) on the
        # path or an ancestor; its target may redirect off the local drive.
        if (Test-PathHasReparsePoint -Path $full) { return $false }
    } else {
        if ($full -notmatch '^/') { return $false }
    }
    return $true
}

function Get-CommitShaForTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Tag
    )

    # Resolves an annotated or lightweight tag to its target commit SHA via
    # the GitHub API. Returns $null on any failure — a missing commit SHA
    # never fails the caller because the primary result (matched release)
    # is still valid.
    if ($Tag -notmatch '\A[A-Za-z0-9._+\-/]+\z') { return $null }
    if ($Repository -notmatch '\A[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\z') { return $null }
    try {
        $endpoint = "repos/$Repository/commits/$Tag"
        # Pin to github.com so GH_HOST cannot redirect us to another
        # GitHub-flavored host. --jq keeps the entire response server-side
        # so no untrusted JSON reaches our shell.
        $sha = gh api --hostname github.com $endpoint --jq '.sha' 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $sha = ($sha | Select-Object -First 1) -as [string]
        if ([string]::IsNullOrWhiteSpace($sha)) { return $null }
        $sha = $sha.Trim()
        if ($sha -notmatch '\A[0-9a-f]{40}\z') { return $null }
        return $sha
    } catch {
        return $null
    }
}

$fileName = if ($ScriptName -like "*.ps1") { $ScriptName } else { "$ScriptName.ps1" }
$targetDate = ConvertTo-VersionDateTime -VersionString $Version

Write-Verbose "Target file:    $fileName"
Write-Verbose "Target version: $Version ($targetDate UTC)"
Write-Verbose "Repository:     $Repository"

if (-not $WorkFolder) {
    # Default: generate a GUID-named path under `$env:TEMP`. The leaf
    # doesn't exist yet, so `Test-IsSafeLocalPath` (which invokes
    # `Resolve-Path` -> `ItemNotFoundException` -> returns $false) is
    # not usable on the composed path directly. Validate the parent
    # (`$env:TEMP`, guaranteed to exist for a running process) up
    # front, then re-validate the FULL path AFTER `CreateDirectory`
    # succeeds — the existing `Test-Path -PathType Container` +
    # `Test-PathHasReparsePoint` block below catches a reparse-point
    # installed at the leaf between generation and use.
    if ([string]::IsNullOrWhiteSpace($env:TEMP)) {
        throw "Cannot compose default WorkFolder: `$env:TEMP is unset or empty."
    }
    if (-not (Test-IsSafeLocalPath -Path $env:TEMP)) {
        throw "Default WorkFolder parent (`$env:TEMP`) is not a valid local path. UNC, network paths, non-FileSystem PSDrives, PowerShell provider prefixes, PSDrives backed by network shares, and paths containing reparse points are not accepted."
    }
    # `$env:TEMP` passed locality checks; the composed leaf is a fresh
    # GUID under it. Normalize with `GetFullPath` (safe on missing
    # tails) and skip `Resolve-ProviderPath` here — the post-create
    # revalidation below is the definitive locality proof.
    $WorkFolder = [System.IO.Path]::GetFullPath((Join-Path $env:TEMP "find-release-tag-$([guid]::NewGuid().ToString('N'))"))
    $createdWorkFolder = $true
} else {
    $createdWorkFolder = $false
    if (-not (Test-IsSafeLocalPath -Path $WorkFolder)) {
        throw "WorkFolder is not a valid local path. UNC, network paths, non-FileSystem PSDrives, PowerShell provider prefixes, PSDrives backed by network shares, and paths containing reparse points are not accepted."
    }
    # Replace the caller-supplied string with its fully-qualified FileSystem
    # provider-native form so downstream Join-Path and New-Item cannot be
    # reinterpreted by a PSDrive mapping or by drive-relative resolution.
    $WorkFolder = Resolve-ProviderPath -Path $WorkFolder
    $WorkFolder = [System.IO.Path]::GetFullPath($WorkFolder)
}

$createdFiles = New-Object System.Collections.Generic.List[string]

try {
    try {
        [System.IO.Directory]::CreateDirectory($WorkFolder) | Out-Null
    } catch {
        throw "WorkFolder could not be created."
    }
    if (-not (Test-Path -LiteralPath $WorkFolder -PathType Container)) {
        throw "WorkFolder path exists but is not a directory."
    }
    # Note: `Test-IsSafeLocalPath` at intake (default branch: parent
    # `$env:TEMP`; caller-supplied branch: full path) already rejected
    # reparse-point-redirected paths. No revalidation here — same-user
    # filesystem races between intake and use are out of scope for
    # this personal-machine tool (matches the rest of CSS-Exchange).

    Write-Verbose "Enumerating releases from $Repository ..."
    # Pin the request to github.com. Passing the bare `owner/repo` allows an
    # inherited or hostile GH_HOST to redirect this call to another host and
    # potentially attach an ambient enterprise credential. Prefixing the
    # host makes the target explicit for both list and download calls.
    $qualifiedRepository = "github.com/$Repository"
    $jsonFields = 'tagName,publishedAt,isDraft,isPrerelease'
    $releaseListLimit = 1000
    $releaseJson = gh release list --repo $qualifiedRepository --limit $releaseListLimit --json $jsonFields 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to list releases from ${Repository}: $(ConvertTo-SafeDetail ($releaseJson -join ' '))"
    }

    # Preflight top-level shape: gh must return a JSON array. Checking the
    # raw text before ConvertFrom-Json is required because PowerShell's
    # pipeline unwraps single-element arrays: [] parses to $null, [{...}]
    # parses to one PSCustomObject, so the post-parse IEnumerable check
    # cannot distinguish a valid empty/one-element array from an object.
    $jsonText = ($releaseJson -join "`n")
    $jsonTrimmed = $jsonText.TrimStart()
    if (-not $jsonTrimmed.StartsWith('[')) {
        throw "Unexpected release list shape from gh (not an array)."
    }
    # Capture into a variable BEFORE wrapping with @(). In Windows PowerShell
    # 5.1, ConvertFrom-Json emits a top-level JSON array as a single Object[]
    # pipeline value, so @($jsonText | ConvertFrom-Json) produces a
    # single-element array whose only element is the Object[]. Assigning
    # first and then wrapping avoids that pipeline behavior. Use
    # -NoEnumerate on runtimes that support it to reject nested-array
    # shapes like `[[{...}]]` that PowerShell 7 would otherwise flatten.
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('NoEnumerate')) {
        $parsedReleases = $jsonText | ConvertFrom-Json -NoEnumerate -ErrorAction Stop
    } else {
        $parsedReleases = $jsonText | ConvertFrom-Json -ErrorAction Stop
    }
    # Windows PowerShell 5.1 turns a valid empty JSON array `[]` into
    # $null via ConvertFrom-Json. Wrapping $null with @(...) yields a
    # single-element array containing $null, which the shape check
    # below rejects as "Unexpected release entry shape from gh" — the
    # branch that should have produced a clean `not-found-no-candidates`
    # result throws instead. Coerce $null to an empty array before
    # iterating.
    if ($null -eq $parsedReleases) {
        $releases = @()
    } else {
        $releases = @($parsedReleases)
    }
    foreach ($rel in $releases) {
        if ($null -eq $rel -or
            -not ($rel.PSObject.Properties.Match('tagName').Count) -or
            -not ($rel.PSObject.Properties.Match('isDraft').Count) -or
            -not ($rel.PSObject.Properties.Match('isPrerelease').Count) -or
            -not ($rel.tagName -is [string]) -or
            ($rel.isDraft -isnot [bool]) -or
            ($rel.isPrerelease -isnot [bool])) {
            throw "Unexpected release entry shape from gh."
        }
    }
    $enumerationTruncated = @($releases).Count -ge $releaseListLimit
    Write-Verbose "Discovered $($releases.Count) release(s) total; enumeration truncated: $enumerationTruncated."

    $candidates = foreach ($release in $releases) {
        if ($release.isDraft -or $release.isPrerelease) { continue }
        $tagDate = ConvertTo-TagDateTime -TagName $release.tagName
        if ($null -ne $tagDate -and $tagDate -ge $targetDate) {
            [PSCustomObject]@{ Tag = $release.tagName; Date = $tagDate }
        }
    }
    $windowSize = @($candidates).Count
    $candidates = @($candidates | Sort-Object Date | Select-Object -First $MaxCandidates)

    if ($candidates.Count -eq 0) {
        $terminalStatus = if ($enumerationTruncated) { "not-found-inconclusive" } else { "not-found-no-candidates" }
        return [PSCustomObject]@{
            Script             = $fileName
            Version            = $Version
            Repository         = $Repository
            ConfirmedTag       = $null
            ConfirmedCommitSha = $null
            SHA256Hash         = $null
            Status             = $terminalStatus
            WindowExhausted    = $false
            EarlierGaps        = 0
            Tried              = @()
        }
    }

    $windowExhausted = $windowSize -gt $candidates.Count
    Write-Verbose "Inspecting $($candidates.Count) candidate(s); window exhausted: $windowExhausted."

    $tried = New-Object System.Collections.Generic.List[PSCustomObject]
    $earlierGaps = 0

    foreach ($candidate in $candidates) {
        $tag = $candidate.Tag
        Write-Verbose "Checking $tag ..."

        $csvPath = Join-Path $WorkFolder "$tag-$([guid]::NewGuid().ToString('N')).ScriptVersions.csv"
        $matchResult = $null

        try {
            $ghOutput = gh release download $tag --repo $qualifiedRepository -p "ScriptVersions.csv" -O $csvPath 2>&1
            if (Test-Path -LiteralPath $csvPath) {
                $createdFiles.Add($csvPath)
            }

            if ($LASTEXITCODE -ne 0) {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "download-failed"; Detail = (ConvertTo-SafeDetail ($ghOutput -join " ")) })
                $earlierGaps++
                continue
            }

            $fileInfo = Get-Item -LiteralPath $csvPath -ErrorAction SilentlyContinue
            if ($null -eq $fileInfo -or $fileInfo.Length -gt $script:MaxCsvBytes) {
                $sizeDetail = if ($fileInfo) { "$($fileInfo.Length) bytes" } else { "unreadable" }
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "csv-oversize-or-missing"; Detail = $sizeDetail })
                $earlierGaps++
                continue
            }

            $rawLines = @(Get-Content -LiteralPath $csvPath -ErrorAction SilentlyContinue | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $headerOk = ($rawLines.Count -ge 1) -and ($rawLines[0] -cmatch '\A(?:"File"|File),(?:"Version"|Version),(?:"SHA256Hash"|SHA256Hash)\z')
            if (-not $headerOk) {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "csv-malformed"; Detail = "header mismatch" })
                $earlierGaps++
                continue
            }
            # Each row must be exactly three fields, each either fully
            # quoted with no embedded quote/comma or fully bare with no
            # quotes/commas and NO leading whitespace. Import-Csv silently
            # trims leading whitespace on bare fields, so a raw row like
            # ` HealthChecker.ps1,26.03.12.1424,<hash>` parses to the same
            # values a legitimate row would, and ordinal comparison alone
            # cannot see the difference. Requiring the first bare char to
            # be non-whitespace closes that differential.
            $rowFieldRegex = '\A(?:"[^",]*"|(?:[^",\s][^",]*)?),(?:"[^",]*"|(?:[^",\s][^",]*)?),(?:"[^",]*"|(?:[^",\s][^",]*)?)\z'
            $badRow = $false
            for ($i = 1; $i -lt $rawLines.Count; $i++) {
                if ($rawLines[$i] -notmatch $rowFieldRegex) {
                    $badRow = $true
                    break
                }
            }
            if ($badRow) {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "csv-malformed"; Detail = "row structure mismatch" })
                $earlierGaps++
                continue
            }

            try {
                $rows = @(Import-Csv -LiteralPath $csvPath -ErrorAction Stop)
            } catch {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "csv-malformed"; Detail = "CSV parsing failed" })
                $earlierGaps++
                continue
            }

            if ($rows.Count -eq 0) {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "csv-malformed"; Detail = "no rows" })
                $earlierGaps++
                continue
            }

            $props = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
            $required = @('File', 'Version', 'SHA256Hash')
            $missing = $required | Where-Object { $props -notcontains $_ }
            $duplicates = $props | Group-Object | Where-Object { $_.Count -gt 1 }
            $extra = $props.Count -ne $required.Count
            if ($missing -or $duplicates -or $extra) {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "csv-malformed"; Detail = "schema mismatch" })
                $earlierGaps++
                continue
            }

            $hasEmptyRow = $false
            foreach ($r in $rows) {
                if ([string]::IsNullOrWhiteSpace([string]$r.File) -and
                    [string]::IsNullOrWhiteSpace([string]$r.Version) -and
                    [string]::IsNullOrWhiteSpace([string]$r.SHA256Hash)) {
                    $hasEmptyRow = $true
                    break
                }
            }
            if ($hasEmptyRow) {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "csv-malformed"; Detail = "empty row" })
                $earlierGaps++
                continue
            }

            # Match with ordinal, case-sensitive equality to avoid the
            # `-eq` normalization of certain code points (BOM, zero-width
            # joiners) that could otherwise let a row with an invisible
            # prefix appear equal to the requested filename.
            $fileMatches = @($rows | Where-Object { [string]::Equals([string]$_.File, $fileName, [System.StringComparison]::Ordinal) })
            if ($fileMatches.Count -gt 1) {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "csv-malformed"; Detail = "duplicate file rows" })
                $earlierGaps++
                continue
            }
            $row = $fileMatches | Select-Object -First 1
            if (-not $row) {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "file-not-listed"; Detail = (ConvertTo-SafeDetail $fileName) })
                continue
            }

            $rowVersion = [string]$row.Version
            $rowHash = [string]$row.SHA256Hash
            $rowVersionOk = $rowVersion -match '\A[0-9]{2}\.[0-9]{2}\.[0-9]{2}\.[0-9]{4}\z'
            $rowHashOk = $rowHash -match '\A[A-Fa-f0-9]{64}\z'
            if ($rowVersionOk) {
                try {
                    [void](ConvertTo-VersionDateTime -VersionString $rowVersion)
                } catch {
                    $rowVersionOk = $false
                }
            }
            if (-not $rowVersionOk -or -not $rowHashOk) {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "csv-malformed-row"; Detail = (ConvertTo-SafeDetail "$rowVersion|$rowHash") })
                $earlierGaps++
                continue
            }

            if ($rowVersion -eq $Version) {
                $status = if ($earlierGaps -gt 0 -or $enumerationTruncated) { "match-possibly-not-earliest" } else { "match-earliest" }
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "match"; Detail = (ConvertTo-SafeDetail $rowHash) })
                $confirmedSha = Get-CommitShaForTag -Repository $Repository -Tag $tag
                $matchResult = [PSCustomObject]@{
                    Script             = $fileName
                    Version            = $Version
                    Repository         = $Repository
                    ConfirmedTag       = $tag
                    ConfirmedCommitSha = $confirmedSha
                    SHA256Hash         = $rowHash
                    Status             = $status
                    WindowExhausted    = $false
                    EarlierGaps        = $earlierGaps
                    Tried              = $tried.ToArray()
                }
            } else {
                $tried.Add([PSCustomObject]@{ Tag = $tag; Status = "version-mismatch"; Detail = (ConvertTo-SafeDetail $rowVersion) })
            }
        } finally {
            if (Test-Path -LiteralPath $csvPath) {
                Remove-Item -LiteralPath $csvPath -Force -ErrorAction SilentlyContinue
            }
            if (-not (Test-Path -LiteralPath $csvPath)) {
                [void]$createdFiles.Remove($csvPath)
            }
        }

        if ($matchResult) { return $matchResult }
    }

    $status = if ($windowExhausted -or $earlierGaps -gt 0 -or $enumerationTruncated) { "not-found-inconclusive" } else { "not-found-complete" }
    [PSCustomObject]@{
        Script             = $fileName
        Version            = $Version
        Repository         = $Repository
        ConfirmedTag       = $null
        ConfirmedCommitSha = $null
        SHA256Hash         = $null
        Status             = $status
        WindowExhausted    = $windowExhausted
        EarlierGaps        = $earlierGaps
        Tried              = $tried.ToArray()
    }
} finally {
    if ($createdWorkFolder) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $WorkFolder
    } else {
        foreach ($path in $createdFiles) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}
