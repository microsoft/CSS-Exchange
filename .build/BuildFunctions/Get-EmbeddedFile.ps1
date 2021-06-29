# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-DotSourcedScriptName.ps1
. $PSScriptRoot\Get-EmbeddedFileInfo.ps1

<#
.SYNOPSIS
    Returns the embedded file path from this line of PowerShell
    script, if any. This could be a script or a data file.
#>
function Get-EmbeddedFile {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $Line
    )

    process {
        $dotSourcedScript = Get-DotSourcedScriptName $Line
        if ($null -ne $dotSourcedScript) {
            $dotSourcedScript
            return
        }

        $dotSourcedData = Get-EmbeddedFileInfo $Line
        if ($null -ne $dotSourcedData) {
            $dotSourcedData.FilePath
            return
        }
    }
}
