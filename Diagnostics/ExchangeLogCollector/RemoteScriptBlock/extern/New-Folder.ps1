# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function New-Folder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Caller knows that this is an action')]
    [CmdletBinding()]
    param(
        [Alias("NewFolder")]
        [Parameter(Mandatory = $false)][array]$NewFolders,
        [Parameter(Mandatory = $false)][bool]$IncludeDisplayCreate
    )

    if ($NewFolders.Count -gt 1) {
        $verboseDisplayNewFolders = "Multiple ('{0}') Folders Passed" -f $NewFolders.Count
    } else {
        $verboseDisplayNewFolders = $NewFolders[0]
    }
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose "Passed: [string]NewFolders: $verboseDisplayNewFolders | [bool]IncludeDisplayCreate: $IncludeDisplayCreate"

    foreach ($newFolder in $NewFolders) {
        if (-not (Test-Path -Path $newFolder)) {
            if ($IncludeDisplayCreate) {
                Write-Host "Creating Directory: $newFolder"
            }
            [System.IO.Directory]::CreateDirectory($newFolder) | Out-Null
        } else {
            if ($IncludeDisplayCreate) {
                Write-Host "Directory $newFolder is already created!"
            }
        }
    }
}
