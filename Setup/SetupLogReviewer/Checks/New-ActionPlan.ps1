# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\New-WriteObject.ps1
Function New-ActionPlan {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Does not change state')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string[]]$ActionList
    )
    New-WriteObject "`r`nDo the following action plan:`r`n"
    $ActionList | ForEach-Object { New-WriteObject "`t$_" }
    New-WriteObject "`r`nIf this doesn't resolve your issues, please let us know at ExToolsFeedback@microsoft.com"
}
