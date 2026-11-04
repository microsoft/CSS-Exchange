# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Write a rendered analyze-debug-files report into the caller's debug
    directory using exclusive-create semantics.

.DESCRIPTION
    Step 8 of the `analyze-debug-files` skill writes exactly one artifact --
    `DebugAnalysis-<timestamp>.md` (or `DebugAnalysis-<timestamp>-<8hex>.md`
    when that exact name is already taken) -- into the directory the caller
    supplied.
    This helper owns that write so the logic is covered by PSScriptAnalyzer,
    the repository formatter, and Pester. It previously lived in a fenced
    markdown block in `reference/step8-report-authoring.md`, where it had
    none of those.

    Guarantees:

      * NEVER overwrites. The destination is opened with
        `[System.IO.FileMode]::CreateNew`, which fails atomically with an
        IOException when the name already exists. On a same-second
        collision the helper appends 8 hex characters derived from a fresh
        GUID and retries, up to `MaxCollisionRetries` times. Neither
        `File::WriteAllText` nor `File::WriteAllBytes` is used -- both
        truncate an existing destination.
      * REFUSES stray control characters. A character other than tab, CR,
        or LF below U+0020, or anywhere in [U+007F, U+009F], is the
        fingerprint of a report built through a double-quoted here-string
        (`` `v `` silently becomes U+000B). The report contract forbids
        them, so the helper throws rather than persisting a corrupt
        artifact.
      * UTF-8 WITHOUT a BOM, matching the repository's convention for
        markdown.

.PARAMETER DebugDirectory
    Directory to write the report into -- pass `$inventory.DebugDirectory`
    from Step 1. Validated as a real local directory BEFORE any write.

    `Get-DebugFileMetadata.ps1` already validated this path at intake, and
    the skill's threat model (see `reference/filesystem-security.md`)
    deliberately does not revalidate a path on every use. The check is
    repeated HERE because this script is an independent entry point: a
    caller that invokes it directly, out of order, or with a hand-assembled
    value would otherwise reach `File.Open` with no validation at all. This
    mirrors
    `Get-BaselineDependencyGraph.ps1`, which re-verifies its own gate for
    the same reason -- a control that exists only in a sibling script is a
    convention, not a control.

.PARAMETER ReportText
    The fully rendered report body. Build it in memory first (see
    `reference/step8-report-authoring.md`); this helper does not template,
    redact, or encode anything.

.PARAMETER TimeStamp
    Optional `yyyyMMddHHmmss` stamp for the filename. Defaults to the
    current local time. Supplied by tests to make filenames deterministic.

.PARAMETER MaxCollisionRetries
    How many suffixed retries to attempt after a same-second collision.
    Default 5.

.OUTPUTS
    PSCustomObject with:
      .Path          full path of the file that was created
      .FileName      leaf name of that file
      .BytesWritten  number of UTF-8 bytes written
      .Collided      $true when the base name was already taken and a
                     suffixed name had to be used

.EXAMPLE
    $written = & .\.github\skills\analyze-debug-files\Write-DebugAnalysisReport.ps1 `
        -DebugDirectory $inventory.DebugDirectory -ReportText $reportText
    Write-Host "Report written to $($written.Path)"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DebugDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportText,

    [ValidatePattern('\A[0-9]{14}\z')]
    [string]$TimeStamp,

    [ValidateRange(1, 50)]
    [int]$MaxCollisionRetries = 5
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

. $PSScriptRoot\..\..\skill-lib\Resolve-SkillLocalPath.ps1

$resolvedDirectory = Resolve-SkillLocalPath -Path $DebugDirectory
if ($null -eq $resolvedDirectory) {
    throw ("Write-DebugAnalysisReport refuses to write into '$DebugDirectory' — it failed " +
        "local-path validation. The path is UNC, on a non-local drive, on a " +
        "SUBST/DefineDosDevice alias, has a junction/symlink ancestor, or does not exist.")
}

# Stray C0/C1 controls are the fingerprint of a double-quoted here-string
# bug in the generator (`` `v `` -> U+000B, `` `a `` -> U+0007). The report
# contract forbids them outright, so refuse rather than persist a corrupt
# artifact the operator would have to notice by eye.
$controlCharMatch = [regex]::Match($ReportText, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]')
if ($controlCharMatch.Success) {
    $codePoint = '{0:X4}' -f [int][char]$controlCharMatch.Value
    throw ("Write-DebugAnalysisReport refuses to write a report containing the control " +
        "character U+$codePoint at index $($controlCharMatch.Index). Only tab, CR, and LF " +
        "are permitted. This is the signature of a double-quoted here-string in the report " +
        "generator — rebuild the text with a StringBuilder or single-quoted template.")
}

if ([string]::IsNullOrEmpty($TimeStamp)) {
    $TimeStamp = (Get-Date).ToString('yyyyMMddHHmmss')
}

# Markdown in this repository is UTF-8 WITHOUT a BOM. `throwOnInvalidBytes`
# is ON: the default encoder silently substitutes U+FFFD for an unpaired
# UTF-16 surrogate, which would make the persisted bytes differ from
# $ReportText. A report that cannot be encoded faithfully is a generator bug,
# and refusing to persist those is this helper's whole job.
$encoding = [System.Text.UTF8Encoding]::new($false, $true)
$reportBytes = $encoding.GetBytes($ReportText)

$destination = Join-Path -Path $resolvedDirectory -ChildPath "DebugAnalysis-$TimeStamp.md"
$collided = $false
$written = $false

for ($attempt = 0; $attempt -le $MaxCollisionRetries; $attempt++) {
    if ($attempt -gt 0) {
        # Same-second collision. Append 8 hex characters from a fresh GUID
        # and try a new name; do NOT overwrite the existing report.
        $collided = $true
        $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $destination = Join-Path -Path $resolvedDirectory -ChildPath "DebugAnalysis-$TimeStamp-$suffix.md"
    }

    # PHASE 1 -- open ONLY. The collision/retry decision is scoped to this one
    # call and nothing else.
    #
    # `FileMode.CreateNew` fails atomically with IOException when the
    # destination already exists, which is exactly the no-overwrite contract.
    # Win32 surfaces that as ERROR_FILE_EXISTS (80) / ERROR_ALREADY_EXISTS
    # (183) -> HResult 0x80070050 / 0x800700B7. Inside a TYPED catch
    # PowerShell unwraps the MethodInvocationException, so `$_.Exception` is
    # the real `IOException` and its HResult is usable directly (verified).
    #
    # Anything else deriving from IOException -- DirectoryNotFoundException,
    # PathTooLongException, a full disk -- is NOT a collision and must surface
    # immediately instead of burning the retry budget and then being reported
    # as "could not find a free name".
    #
    # Deliberately NO `Test-Path`-based collision fallback. An earlier
    # revision had one and it was wrong in a way that mattered: once
    # `CreateNew` succeeds the destination exists, so ANY later write/dispose
    # failure would have tested true, been misclassified as a collision, left
    # a truncated report behind, retried under a new name, and possibly
    # returned success while hiding the real I/O error.
    $fs = $null
    try {
        $fs = [System.IO.File]::Open(
            $destination,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
    } catch [System.IO.IOException] {
        $hr = $_.Exception.HResult
        if ($hr -ne -2147024816 -and $hr -ne -2147024713) { throw }
        if ($attempt -eq $MaxCollisionRetries) {
            throw ("Write-DebugAnalysisReport could not find a free report name under " +
                "'$resolvedDirectory' after $MaxCollisionRetries collision retries.")
        }
        continue
    }

    # PHASE 2 -- we now own a freshly created, empty file. From here NOTHING
    # is retryable: a failure means a partial artifact exists on disk. Delete
    # it (best effort) so a truncated corpse cannot violate the "exactly one
    # artifact" contract, then let the original error propagate.
    $writeFailure = $null
    try {
        $fs.Write($reportBytes, 0, $reportBytes.Length)
        $fs.Flush()
    } catch {
        $writeFailure = $_
    } finally {
        try {
            $fs.Dispose()
        } catch {
            if ($null -eq $writeFailure) { $writeFailure = $_ }
        }
    }
    if ($null -ne $writeFailure) {
        try {
            Remove-Item -LiteralPath $destination -Force -ErrorAction Stop
        } catch {
            Write-Warning -Message "Failed to remove partial report '$destination': $($_.Exception.Message)" -WarningAction Continue
        }
        throw $writeFailure
    }
    $written = $true
    break
}

if (-not $written) {
    throw "Write-DebugAnalysisReport did not write a report under '$resolvedDirectory'."
}

# Verify rather than assume. A silent non-write would let the skill report
# success for an artifact the operator can never find.
if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
    throw "Write-DebugAnalysisReport completed its write but '$destination' does not exist."
}

[PSCustomObject]@{
    Path         = $destination
    FileName     = [System.IO.Path]::GetFileName($destination)
    BytesWritten = $reportBytes.Length
    Collided     = $collided
}
