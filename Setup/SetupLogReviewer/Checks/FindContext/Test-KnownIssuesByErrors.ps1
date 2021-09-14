# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Test-DisabledService.ps1
. $PSScriptRoot\Test-ExceptionADOperationFailedAlreadyExist.ps1
. $PSScriptRoot\Test-InitializePermissionsOfDomain.ps1
. $PSScriptRoot\Test-MSExchangeSecurityGroupsContainerDeleted.ps1
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
            "Test-ExceptionADOperationFailedAlreadyExist",
            "Test-MSExchangeSecurityGroupsContainerDeleted"
        )

        if ($Script:ReturnNow) {
            return
        }

        InvokeTest -PipeObject ([PSCustomObject]@{
                ErrorReference   = $errorReference
                SetupLogReviewer = $SetupLogReviewer
            }) -Tests @(
            "Test-InitializePermissionsOfDomain"
        )
    }
}
