# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-TestResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $TestName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $ResultType,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Information", "Warning", "Error")]
        [string]
        $Severity,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $FolderIdentity,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $FolderEntryId,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $ResultData
    )

    process {
        [PSCustomObject]@{
            TestName       = $TestName
            ResultType     = $ResultType
            Severity       = $Severity
            FolderIdentity = $FolderIdentity
            FolderEntryId  = $FolderEntryId
            ResultData     = $ResultData
        }
    }
}
