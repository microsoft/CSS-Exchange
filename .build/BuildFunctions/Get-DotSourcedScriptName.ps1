# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns the dot-sourced script path from this line of PowerShell
    script, if any.
#>
function Get-DotSourcedScriptName {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $Line
    )

    process {
        $m = $Line | Select-String "\. (?:\.|\`$PSScriptRoot)\\(.*).ps1"
        if ($null -ne $m) {
            $dotLoadedScriptPath = $m.Matches[0].Groups[1].Value + ".ps1"
            $dotLoadedScriptPath
        }
    }
}
