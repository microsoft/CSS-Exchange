# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Function to write a line of text surrounded by a dash line box.

.DESCRIPTION
    The Write-DashLineBoxColor function is used to create a quick and easy display around a line of text. It generates a box made of dash characters ("-") and displays the provided line of text inside the box.

.PARAMETER Line
    Specifies the line of text to be displayed inside the dash line box.

.PARAMETER Color
    Specifies the color of the dash line box and the text. The default value is "White".

.PARAMETER DashChar
    Specifies the character used to create the dash line. The default value is "-".

.EXAMPLE
    Write-DashLineBoxColor -Line "Hello, World!" -Color "Yellow" -DashChar "="
    Displays:
    ==============
    Hello, World!
    ==============
#>
function Write-DashLineBoxColor {
    [CmdletBinding()]
    param(
        [string[]]$Line,
        [string] $Color = "White",
        [char] $DashChar = "-"
    )
    $highLineLength = 0
    $Line | ForEach-Object { if ($_.Length -gt $highLineLength) { $highLineLength = $_.Length } }
    $dashLine = [string]::Empty
    1..$highLineLength | ForEach-Object { $dashLine += $DashChar }
    Write-Host
    Write-Host -ForegroundColor $Color $dashLine
    $Line | ForEach-Object { Write-Host -ForegroundColor $Color $_ }
    Write-Host -ForegroundColor $Color $dashLine
    Write-Host
}
