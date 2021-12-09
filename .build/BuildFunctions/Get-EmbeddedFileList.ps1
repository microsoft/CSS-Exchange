# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-EmbeddedFile.ps1

<#
.SYNOPSIS
    Gets the list of all embedded scripts and data files in this
    script.
#>
function Get-EmbeddedFileList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter()]
        [string]
        $File,

        [Parameter()]
        [System.Collections.Generic.HashSet[string]]
        $FilesAlreadyAdded = (New-Object 'System.Collections.Generic.HashSet[string]')
    )

    process {
        $files = New-Object 'System.Collections.Generic.List[string]'
        $directoryOfCurrentFile = (Get-Item $File).Directory
        Get-Content $File | Get-EmbeddedFile | ForEach-Object {
            $absolutePath = (Get-Item (Join-Path $directoryOfCurrentFile $_)).FullName
            if ($FilesAlreadyAdded.Add($absolutePath)) {
                $files.Add($absolutePath)
                if ($_ -like "*.ps1") {
                    Get-EmbeddedFileList $absolutePath $FilesAlreadyAdded | ForEach-Object {
                        $files.Add($_)
                    }
                }
            }
        }

        if ($files.Count -gt 0) {
            $files
        }
    }
}
