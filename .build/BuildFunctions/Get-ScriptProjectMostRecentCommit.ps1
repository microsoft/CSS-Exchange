# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-EmbeddedFileList.ps1
. $PSScriptRoot\Get-FileMostRecentCommit.ps1

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
        $File
    )

    process {
        Write-Verbose "Get-ScriptProjectMostRecentCommit called for file $File"
        $mostRecentCommit = Get-FileMostRecentCommit $File
        foreach ($embeddedFile in (Get-EmbeddedFileList $File)) {
            Write-Verbose "Getting commit time for $embeddedFile"
            $commitTime = Get-FileMostRecentCommit $embeddedFile
            if ($commitTime -gt $mostRecentCommit) {
                $mostRecentCommit = $commitTime
                Write-Host ("Changing commit time to: $($commitTime.ToString("yy.MM.dd.HHmm"))")
            }
        }

        $mostRecentCommit
    }
}
