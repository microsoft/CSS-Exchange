# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-FileTimestampHashtable {
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param (
        [Parameter()]
        [Hashtable]
        $DependencyHashtable
    )

    $timestamps = @{}

    foreach ($k in ($DependencyHashtable.Keys | Sort-Object)) {
        $timestamps[$k] = [DateTime]::Parse((git log -n 1 --format="%cd" --date=rfc $k)).ToUniversalTime()
        Write-Host "Commit time $($timestamps[$k]) for file $k"
    }

    return $timestamps
}
