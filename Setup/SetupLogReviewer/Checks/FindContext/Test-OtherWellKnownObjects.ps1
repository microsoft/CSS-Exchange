# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-OtherWellKnownObjects {
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $errorLine = $SetupLogReviewer |
            SelectStringLastRunOfExchangeSetup "\[ERROR\] The well-known object entry (.+) on the otherWellKnownObjects attribute in the container object (.+) points to an invalid DN or a deleted object"

        if ($null -ne $errorLine) {

            $errorLine.Line | New-ErrorContext
            New-ActionPlan @(
                "Option 1: Restore the objects that were deleted.",
                "Option 2: Run the SetupAssist.ps1 script to address the deleted objects type"
            )
            return
        }
        Write-Verbose "OtherWellKnownObjects didn't find anything"
    }
}
