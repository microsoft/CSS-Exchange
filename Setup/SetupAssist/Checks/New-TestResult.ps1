# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function New-TestResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Does not change state')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Passed", "Failed", "Warning", "Information")]
        [string]$Result,

        [Parameter(Mandatory = $false)]
        [object]$Details,

        [Parameter(Mandatory = $false)]
        [object]$ReferenceInfo
    )

    return [PSCustomObject]@{
        TestName      = $TestName
        Result        = $Result
        Details       = $Details
        ReferenceInfo = $ReferenceInfo
    }
}
