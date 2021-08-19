# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function New-TestResult {
    [CmdletBinding()]
    param(
        [string]$TestName,
        [string]$Result,
        [string]$AdditionalContext,
        [object]$CustomData
    )

    return [PSCustomObject]@{
        TestName          = $TestName
        Result            = $Result
        AdditionalContext = $AdditionalContext
        CustomData        = $CustomData
    }
}
