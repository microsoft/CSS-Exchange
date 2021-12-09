# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\New-WriteObject.ps1
Function New-ErrorContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Does not change state')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Line
    )
    begin {
        New-WriteObject "Found Error: `r`n" -WriteType "Warning"
    }
    process {
        New-WriteObject $Line -ForegroundColor "Yellow"
    }
}
