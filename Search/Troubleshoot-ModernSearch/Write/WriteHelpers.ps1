# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-DashLineBox {
    [CmdletBinding()]
    param(
        [string]$Line
    )
    <#
        This is to simply create a quick and easy display around a line
        -------------------------------------
        Line                           Length
        -------------------------------------
        # Empty Line
    #>

    $dashLine = [string]::Empty
    1..$Line.Length | ForEach-Object { $dashLine += "-" }
    Write-Host $dashLine
    Write-Host $Line
    Write-Host $dashLine
    Write-Host
}

