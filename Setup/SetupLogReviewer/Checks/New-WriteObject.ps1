# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function New-WriteObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Does not change state')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$WriteData,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Host", "Error", "Warning")]
        [string]$WriteType = "Host",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Gray", "Red", "Yellow")]
        [string]$ForegroundColor = "Gray"
    )
    return [PSCustomObject]@{
        WriteType       = $WriteType
        WriteData       = $WriteData
        ForegroundColor = $ForegroundColor
    }
}
