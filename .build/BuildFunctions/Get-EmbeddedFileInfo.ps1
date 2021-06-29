# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns the embedded data file info from this line of PowerShell
    script, including the file path and variable name it is assigned to.
#>
function Get-EmbeddedFileInfo {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $Line
    )

    process {
        $m = $Line | Select-String "\`$(.+) = Get-Content `"?(\`$PSScriptRoot|\.)\\([\w|\d|\.|\\]+)`"? -AsByteStream -Raw"
        if ($m.Matches.Count -gt 0) {
            [PSCustomObject]@{
                FilePath     = $m.Matches[0].Groups[3].Value
                VariableName = $m.Matches[0].Groups[1].Value
            }
        }
    }
}
