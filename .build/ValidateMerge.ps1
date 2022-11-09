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
$times = Import-Clixml $distFolder\commitTimeHashtable.xml

if ($null -eq $deps -or $null -eq $times) {
    throw "Dependency or commit time hashtable not found. Run .build\Build.ps1 first."
}

$preventMergeFiles = @()
$allowMergeFiles = @()
$filesAlreadyChecked = New-Object 'System.Collections.Generic.HashSet[string]'

$gitlog = git log --format="%H %cd" --date=rfc origin/main..HEAD
$m = $gitlog | Select-String "^(\S+) (.*)$"
foreach ($commitMatch in $m) {
    $commitHash = $commitMatch.Matches.Groups[1].Value
    $commitTime = [DateTime]::Parse($commitMatch.Matches.Groups[2].Value).ToUniversalTime()
    Write-Host "Commit $commitHash at $commitTime"
    $allAffectedFiles = New-Object 'System.Collections.Generic.HashSet[string]'
    $filesChangedInCommit = git diff-tree --no-commit-id --name-only -r $commitHash
    foreach ($fileChanged in $filesChangedInCommit) {
        $filesAffectedByThisChange = 0
        $fullPath = Join-Path $repoRoot $fileChanged
        if ($filesAlreadyChecked.Contains($fullPath)) {
            # If we have several commits that modify the same file, we only need to check it once,
            # on the latest commit.
            continue
        }

        [void]$filesAlreadyChecked.Add($fullPath)
        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        $stack.Push($fullPath)
        while ($stack.Count -gt 0) {
            $currentFile = $stack.Pop()
            [void]$allAffectedFiles.Add($currentFile)
            $filesAffectedByThisChange++
            foreach ($k in $deps.Keys) {
                if ($deps[$k].Contains($currentFile)) {
                    $stack.Push($k)
                }
            }
        }

        Write-Host "$fileChanged is included directly or transitively in $($filesAffectedByThisChange - 1) files."
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

if ($preventMergeFiles.Count -gt 0) {
    Write-Host "The following files have a commit time earlier than main branch. Please rebase your branch to update the commit times."
    $preventMergeFiles | Format-Table -AutoSize
    throw "Commit time validation failed."
} else {
    Write-Host "All files are modified after the commit on main branch. You can merge your branch to main branch."
    $allowMergeFiles | Format-Table -AutoSize
}
