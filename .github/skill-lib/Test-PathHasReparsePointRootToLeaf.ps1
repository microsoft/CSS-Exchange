# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns $true if any component from the volume root down to the target
    is a reparse point (junction/symlink); otherwise $false. Segments that
    do not yet exist are treated as safe.

.DESCRIPTION
    Walks root → leaf. Returns $true as soon as any ancestor is a reparse
    point, WITHOUT ever calling filesystem cmdlets on a descendant of a
    reparse ancestor. Uses attribute-only reads (no follow) via
    `[System.IO.File]::GetAttributes` so a directory symlink pointing at
    a UNC share is not opened as part of the check.

    Not-yet-existing tail segments return $false — the caller may create
    a file into an existing safe directory. Any error inspecting an
    ancestor (access denied, broken link, etc.) is treated as UNSAFE and
    returns $true rather than assuming absence of a reparse point.

    Consumed by:
    - .github/skills/analyze-debug-files/Get-DebugFileMetadata.ps1
    - .github/skills/analyze-debug-files/SKILL.md (Step 5 code block)
    - .github/skills/trace-code-introduction/Trace-CodeIntroduction.ps1

.PARAMETER Path
    An absolute filesystem path. Callers should pass a lexically local,
    resolved path — validating the path shape is out of scope for this
    helper.

.OUTPUTS
    [bool] — $true if any ancestor component is a reparse point or a
    filesystem error occurs; $false when the entire chain is a plain
    directory tree.
#>
function Test-PathHasReparsePointRootToLeaf {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $normalized = [System.IO.Path]::GetFullPath($Path)
    } catch {
        return $true
    }
    $parts = New-Object System.Collections.Generic.List[string]
    $cur = $normalized
    while (-not [string]::IsNullOrEmpty($cur)) {
        $parts.Insert(0, $cur)
        $parent = Split-Path -Parent $cur
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cur) { break }
        $cur = $parent
    }
    foreach ($p in $parts) {
        try {
            $attrs = [System.IO.File]::GetAttributes($p)
            if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $true
            }
        } catch [System.IO.FileNotFoundException] {
            # Not-yet-existing tail segments are OK — the workflow may
            # create the report file into an existing directory.
            continue
        } catch [System.IO.DirectoryNotFoundException] {
            continue
        } catch {
            # Any other error while inspecting an ancestor is a hard fail.
            return $true
        }
    }
    return $false
}
