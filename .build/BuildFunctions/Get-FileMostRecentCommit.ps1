# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Test-PathCaseSensitive.ps1

function Get-FileMostRecentCommit {
    [CmdletBinding()]
    [OutputType([DateTime])]
    param (
        [Parameter()]
        [string]
        $File
    )

    Write-Verbose "Get-FileMostRecentCommit called for file $File"

    if (-not (Test-PathCaseSensitive $File)) {
        Write-Error "Path case is not correct: $File"
    }

    try {
        $commitTime = [DateTime]::Parse((git log -n 1 --format="%ad" --date=rfc $File))
        Write-Verbose "Commit time $commitTime for file $File"
        return $commitTime
    } catch {
        Write-Error "Failed to get commit time for file $File"
        throw
    }
}
