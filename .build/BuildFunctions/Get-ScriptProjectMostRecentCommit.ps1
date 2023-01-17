# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Gets the most recent commit, considering all files related to the specified script,
    including any embedded dot-sourced scripts or other files.
#>
function Get-ScriptProjectMostRecentCommit {
    [CmdletBinding()]
    [OutputType([DateTime])]
    param (
        [Parameter()]
        [string]
        $File,

        [Parameter()]
        [Hashtable]
        $CommitTimeHashtable,

        [Parameter()]
        [Hashtable]
        $DependencyHashtable
    )

    process {
        Write-Host "Get-ScriptProjectMostRecentCommit called for file $File"

        $mostRecentCommitTime = [DateTime]::MinValue

        $filesAlreadyChecked = New-Object 'System.Collections.Generic.HashSet[string]'
        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        $stack.Push($File)

        while ($stack.Count -gt 0) {
            $scriptFile = $stack.Pop()
            if ($filesAlreadyChecked.Contains($scriptFile)) {
                continue
            }

            $commitTimeForThisFile = $CommitTimeHashtable[$scriptFile]
            if ($commitTimeForThisFile -gt $mostRecentCommitTime) {
                $mostRecentCommitTime = $commitTimeForThisFile
                Write-Host ("Changing commit time to $($mostRecentCommitTime.ToString("yy.MM.dd.HHmm")) from file $($scriptFile)")
            }

            foreach ($dep in $DependencyHashtable[$scriptFile]) {
                $stack.Push($dep)
            }

            [void]$filesAlreadyChecked.Add($scriptFile)
        }

        return $mostRecentCommitTime
    }
}
