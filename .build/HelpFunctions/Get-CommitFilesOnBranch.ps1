# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This should only be called if we have a branch that we want to compare against
function Get-CommitFilesOnBranch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Branch
    )
    $filesFullPath = New-Object 'System.Collections.Generic.HashSet[string]'
    $repoRoot = Get-Item "$PSScriptRoot\..\.."

    Write-Verbose "Checking commits only"
    # Get all the commits between origin/$Branch and HEAD.
    $gitLog = git log --format="%H %cd" --date=rfc origin/$Branch..HEAD
    $m = $gitLog | Select-String "^(\S+) (.*)$"

    foreach ($commitMatch in $m) {
        $commitHash = $commitMatch.Matches.Groups[1].Value
        $filesChangedInCommit = git diff-tree --no-commit-id --name-only -r $commitHash

        foreach ($fileChanged in $filesChangedInCommit) {
            $fullPath = Join-Path $repoRoot $fileChanged

            if (-not (Test-Path $fullPath)) {
                # not typical scenario, but want to have the pipeline continue
                Write-Verbose "File no longer exists, skip file: $fullPath"
                continue
            }

            Write-Verbose "Adding commit file to list: $fullPath"
            [void]$filesFullPath.Add($fullPath)
        }
    }

    # Also include modified files, but not committed yet for local work.
    $gitStatus = git status --short
    $m = $gitStatus | Select-String "M (.*)"
    foreach ($match in $m) {
        $file = $match.Matches.Groups[1].Value.Trim()
        $fullPath = Join-Path $repoRoot $file

        Write-Verbose "Adding modified file to list: $fullPath"
        [void]$filesFullPath.Add($fullPath)
    }

    Write-Verbose "Files changed or modified"
    $filesFullPath | Write-Verbose

    return $filesFullPath
}
