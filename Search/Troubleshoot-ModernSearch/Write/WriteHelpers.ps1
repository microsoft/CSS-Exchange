# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-DashLineBox {
    [CmdletBinding()]
    param(
        [string[]]$Line
    )
    <#
        This is to simply create a quick and easy display around a line
        -------------------------------------
        Line                           Length
        Line                           Length
        -------------------------------------
        # Empty Line
    #>
    $highLineLength = 0
    $dashLine = [string]::Empty
    $Line | ForEach-Object { if ($_.Length -gt $highLineLength) { $highLineLength = $_.Length } }
    1..$highLineLength | ForEach-Object { $dashLine += "-" }
    Write-Host $dashLine
    $Line | ForEach-Object { Write-Host $_ }
    Write-Host $dashLine
    Write-Host
}

