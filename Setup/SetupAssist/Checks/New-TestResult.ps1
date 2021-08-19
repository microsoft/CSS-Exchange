# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function New-TestResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Does not change state')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Passed", "Failed", "Warning")]
        [string]$Result,

        [Parameter(Mandatory = $false)]
        [string]$AdditionalContext,

        [Parameter(Mandatory = $false)]
        [object]$CustomData
    )

    return [PSCustomObject]@{
        TestName          = $TestName
        Result            = $Result
        AdditionalContext = $AdditionalContext
        CustomData        = $CustomData
    }
}
