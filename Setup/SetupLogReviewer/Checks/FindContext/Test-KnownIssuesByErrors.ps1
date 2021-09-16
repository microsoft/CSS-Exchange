# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\ErrorContext\Test-DisabledService.ps1
. $PSScriptRoot\..\ErrorContext\Test-EndpointMapper.ps1
. $PSScriptRoot\..\ErrorContext\Test-FailedSearchFoundation.ps1
. $PSScriptRoot\..\ErrorContext\Test-ExceptionADOperationFailedAlreadyExist.ps1
. $PSScriptRoot\..\ErrorContext\Test-MissingDirectory.ps1
. $PSScriptRoot\..\ErrorContext\Test-MissingHomeMdb.ps1
. $PSScriptRoot\..\ErrorContext\Test-MountDatabaseFailure.ps1
. $PSScriptRoot\..\ErrorContext\Test-MSExchangeSecurityGroupsContainerDeleted.ps1
. $PSScriptRoot\..\ErrorContext\Test-VirtualDirectoryFailure.ps1
. $PSScriptRoot\..\ErrorReference\Test-FipsUpgradeConfiguration.ps1
. $PSScriptRoot\..\ErrorReference\Test-InitializePermissionsOfDomain.ps1
Function Test-KnownIssuesByErrors {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    begin {
        #Use this to call similar tests and break when we find a result that we like
        Function InvokeTest {
            [CmdletBinding()]
            param(
                [object]$PipeObject,
                [string[]]$Tests
            )

            foreach ($test in $Tests) {
                $result = $PipeObject | & $test

                if ($null -ne $result) {
                    #put the test back on the pipe and let the main caller write the results
                    $result
                    $Script:ReturnNow = $true
                    break
                }
            }
        }
    }
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $errorReference = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "\[ERROR-REFERENCE\] Id=(.+) Component="

        if ($null -eq $errorReference) {
            Write-Verbose "KnownIssuesByErrors - no known issue - No Error Reference"
            return
        }

        $contextOfError = $SetupLogReviewer | GetFirstErrorWithContextToLine $errorReference.LineNumber

        InvokeTest -PipeObject ([PSCustomObject]@{
                ErrorContext = $contextOfError
            }) -Tests @(
            "Test-DisabledService",
            "Test-EndpointMapper",
            "Test-ExceptionADOperationFailedAlreadyExist",
            "Test-FailedSearchFoundation",
            "Test-MissingDirectory",
            "Test-MissingHomeMdb",
            "Test-MountDatabaseFailure",
            "Test-MSExchangeSecurityGroupsContainerDeleted",
            "Test-VirtualDirectoryFailure"
        )

        if ($Script:ReturnNow) {
            return
        }

        InvokeTest -PipeObject ([PSCustomObject]@{
                ErrorReference   = $errorReference
                SetupLogReviewer = $SetupLogReviewer
            }) -Tests @(
            "Test-InitializePermissionsOfDomain",
            "Test-FipsUpgradeConfiguration"
        )
    }
}
