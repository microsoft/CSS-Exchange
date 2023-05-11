# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-DashLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Length
    )
    $dashLine = [string]::Empty
    1..$Length | ForEach-Object { $dashLine += "-" }
    return $dashLine
}

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
    $Line | ForEach-Object { if ($_.Length -gt $highLineLength) { $highLineLength = $_.Length } }
    $dashLine = Get-DashLine $highLineLength
    Write-Host $dashLine
    $Line | ForEach-Object { Write-Host $_ }
    Write-Host $dashLine
    Write-Host
}

function Write-DisplayObjectInformation {
    [CmdletBinding()]
    param(
        [object]$DisplayObject,
        [string[]]$PropertyToDisplay
    )
    process {
        $width = 0

        foreach ($property in $PropertyToDisplay) {

            if ($property.Length -gt $width) {
                $width = $property.Length + 1
            }
        }

        $dashLine = Get-DashLine $width
        Write-Host $dashLine
        foreach ($property in $PropertyToDisplay) {
            Write-Host ("{0,-$width} = {1}" -f $property, $DisplayObject.($property))
        }
        Write-Host $dashLine
        Write-Host
    }
}
