# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Validates that no files in a PR have an older commit time than they do in main.
.DESCRIPTION
    Consider that the version number of a script is the commit time of the most recent commit
    of any file included in that script. Further, consider that PRs can be merged out of order.
    An older commit could be merged after a newer commit. In this scenario, the version number
    of the script has already been set to the newer commit, and the version does not increment
    when the script is modified by the older commit.

    This script validates that no files in a PR have an older commit time than they do in main.
    If they do, we instruct the user to rebase against main. The rebase will update the commit
    time to be the time of the rebase, which will then be newer than main, causing the script
    version to increment as expected.
#>


[CmdletBinding()]
param ()

$repoRoot = Get-Item "$PSScriptRoot\.."
$distFolder = Join-Path $repoRoot "dist"

$deps = Import-Clixml $distFolder\dependencyHashtable.xml

if ($null -eq $deps) {
    throw "Dependency hashtable not found. Run .build\Build.ps1 first."
}

# Files with commit times that are older than one or more dependent files in main.
$preventMergeFiles = @()

# Files with commit times that are newer than all dependents in main.
$allowMergeFiles = @()

# Files we already checked. We only want to check each file once.
$filesAlreadyChecked = New-Object 'System.Collections.Generic.HashSet[string]'

# Get all the commits between origin/main and HEAD.
$gitlog = git log --format="%H %cd" --date=rfc origin/main..HEAD
$m = $gitlog | Select-String "^(\S+) (.*)$"

foreach ($commitMatch in $m) {
    $commitHash = $commitMatch.Matches.Groups[1].Value
    $commitTime = [DateTime]::Parse($commitMatch.Matches.Groups[2].Value).ToUniversalTime()
    Write-Host "Commit $commitHash at $commitTime"

    # All files affected by this one commit. Affected files means not just the file
    # that was modified, but also any files that are dependent on that file.
    $allAffectedFiles = New-Object 'System.Collections.Generic.HashSet[string]'

    $filesChangedInCommit = git diff-tree --no-commit-id --name-only -r $commitHash
    foreach ($fileChanged in $filesChangedInCommit) {
        $filesAffectedByThisChange = New-Object 'System.Collections.Generic.HashSet[string]'
        $fullPath = Join-Path $repoRoot $fileChanged
        if ($filesAlreadyChecked.Contains($fullPath)) {
            # If we have several commits that modify the same file, we only need to check it once,
            # on the latest commit.
            Write-Host "  $fileChanged was modified in a later commit."
            continue
        }

        [void]$filesAlreadyChecked.Add($fullPath)
        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        $stack.Push($fullPath)

        # On each iteration of this loop, we pop a file from the stack and add it to
        # $allAffectedFiles, and then we look up all files that have a dependency on that file.
        # We add those files to the stack. In this way, we walk the dependency tree from the bottom up,
        # finding all files that are affected by this file, and add them to $allAffectedFiles.
        while ($stack.Count -gt 0) {
            $currentFile = $stack.Pop()
            [void]$allAffectedFiles.Add($currentFile)
            [void]$filesAffectedByThisChange.Add($currentFile)
            foreach ($k in $deps.Keys) {
                if ($deps[$k].Contains($currentFile)) {
                    $stack.Push($k)
                }
            }
        }

        Write-Host "  $fileChanged is included directly or transitively in $($filesAffectedByThisChange.Count - 1) files."
    }

    foreach ($affectedFile in $allAffectedFiles) {
        $commitTimeOnMainString = git log origin/main -n 1 --format="%cd" --date=rfc -- $affectedFile
        $commitTimeOnMain = $null
        if (-not [string]::IsNullOrEmpty($commitTimeOnMainString)) {
            $commitTimeOnMain = [DateTime]::Parse($commitTimeOnMainString).ToUniversalTime()
        }

        if ($null -ne $commitTimeOnMain -and $commitTime -lt $commitTimeOnMain) {
            $preventMergeFiles += [PSCustomObject]@{
                File             = $affectedFile
                CommitHash       = $commitHash
                CommitTime       = $commitTime
                CommitTimeOnMain = $commitTimeOnMain
            }
        } else {
            $allowMergeFiles += [PSCustomObject]@{
                File             = $affectedFile
                CommitHash       = $commitHash
                CommitTime       = $commitTime
                CommitTimeOnMain = $commitTimeOnMain
            }
        }
    }
}

Write-Host

if ($preventMergeFiles.Count -gt 0) {
    Write-Host "The following files have a commit time earlier than main branch. Please rebase your branch to update the commit times."
    $preventMergeFiles | Format-Table -AutoSize
    throw "Commit time validation failed."
} else {
    Write-Host "All files are modified after the commit on main branch. You can merge your branch to main branch."
    $allowMergeFiles | Format-Table -AutoSize
}
