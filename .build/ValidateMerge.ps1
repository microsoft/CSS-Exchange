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
param (
    [string]$Branch = "main"
)

. "$PSScriptRoot\BuildFunctions\Get-ScriptDependencyTree.ps1"

$repoRoot = Get-Item "$PSScriptRoot\.."
$distFolder = Join-Path $repoRoot "dist"

$dependenciesTable = Import-Clixml $distFolder\dependencyHashtable.xml
$dependentsTable = Import-Clixml $distFolder\dependentHashtable.xml

if ($null -eq $dependenciesTable -or $null -eq $dependentsTable) {
    throw "Dependency Hashtable not found. Run .build\Build.ps1 first."
}

# Files with commit times that are older than one or more dependent files in main.
$preventMergeFiles = @()

# Files with commit times that are newer than all dependents in main.
$allowMergeFiles = @()

# Files we already checked. We only want to check each file once.
$filesAlreadyChecked = New-Object 'System.Collections.Generic.HashSet[string]'

# Get all the commits between origin/$Branch and HEAD.
$gitLog = git log --format="%H %cd" --date=rfc origin/$Branch..HEAD
$m = $gitLog | Select-String "^(\S+) (.*)$"

foreach ($commitMatch in $m) {
    $commitHash = $commitMatch.Matches.Groups[1].Value
    $commitTime = [DateTime]::Parse($commitMatch.Matches.Groups[2].Value).ToUniversalTime()
    Write-Host "Commit $commitHash at $commitTime"

    # All files affected by this one commit. Affected files means not just the file
    # that was modified, but also any files that are dependent on that file.
    $allAffectedFiles = New-Object 'System.Collections.Generic.HashSet[string]'

    $filesChangedInCommit = git diff-tree --no-commit-id --name-only -r $commitHash
    foreach ($fileChanged in $filesChangedInCommit) {
        $fullPath = Join-Path $repoRoot $fileChanged
        if ($filesAlreadyChecked.Contains($fullPath)) {
            # If we have several commits that modify the same file, we only need to check it once,
            # on the latest commit.
            Write-Host "  $fileChanged was modified in a later commit."
            continue
        } else {
            [void]$filesAlreadyChecked.Add($fullPath)
        }

        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        [void]$stack.Push($fullPath)

        # On each iteration of this loop, we pop a file from the stack and find its
        # dependents (scripts that include it), and put those on the stack. We repeat
        # until we have the top-level scripts that include the file.
        $topLevelDependents = New-Object 'System.Collections.Generic.HashSet[string]'
        while ($stack.Count -gt 0) {
            $currentFile = $stack.Pop()
            $dependents = $dependentsTable[$currentFile]
            if ($null -eq $dependents -or $dependents.Count -eq 0) {
                [void]$topLevelDependents.Add($currentFile)
            } else {
                foreach ($dependent in $dependents) {
                    [void]$stack.Push($dependent)
                }
            }
        }

        Write-Host "  $fileChanged has $($topLevelDependents.Count) top-level dependents:"
        $topLevelDependents | ForEach-Object { Write-Host "    $_" }

        $filesAffectedByThisChange = New-Object 'System.Collections.Generic.HashSet[string]'

        # Now we walk back down the dependency tree, starting from the top-level dependents.
        $stack.Clear()
        $topLevelDependents | ForEach-Object { [void]$stack.Push($_) }
        while ($stack.Count -gt 0) {
            $currentFile = $stack.Pop()
            [void]$filesAffectedByThisChange.Add($currentFile)
            $dependencies = $dependenciesTable[$currentFile]
            if ($null -ne $dependencies) {
                foreach ($dependency in $dependencies) {
                    [void]$stack.Push($dependency)
                }
            }
        }

        Write-Host "  Those top-level dependents affect $($filesAffectedByThisChange.Count) files:"
        $filesAffectedByThisChange | ForEach-Object {
            Write-Host "    $_"
            [void]$allAffectedFiles.Add($_)
        }
    }

    foreach ($affectedFile in $allAffectedFiles) {
        # Only care about .ps1 files for versioning
        if (-not ($affectedFile.EndsWith(".ps1"))) {
            Write-Host "Skipping non ps1 file: $affectedFile"
            continue
        }

        $commitTimeOnMainString = git log origin/$Branch -n 1 --format="%cd" --date=rfc -- $affectedFile
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
