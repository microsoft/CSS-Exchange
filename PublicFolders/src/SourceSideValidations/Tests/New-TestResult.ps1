# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-TestResult {
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

    [PSCustomObject]@{
        TestName       = $TestName
        ResultType     = $ResultType
        Severity       = $Severity
        FolderIdentity = $FolderIdentity
        FolderEntryId  = $FolderEntryId
        ResultData     = $ResultData
    }
}
