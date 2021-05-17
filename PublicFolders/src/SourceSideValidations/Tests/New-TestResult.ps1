function New-TestResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TestName,

        [Parameter(Mandatory = $true)]
        [string]
        $ResultType,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Information", "Warning", "Error")]
        [string]
        $Severity,

        [Parameter()]
        [string]
        $FolderIdentity,

        [Parameter()]
        [string]
        $FolderEntryId,

        [Parameter()]
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