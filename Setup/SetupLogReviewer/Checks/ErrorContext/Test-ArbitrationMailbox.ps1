# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This test isn't complete, creating it as we need more context to understand why this is failing in some scenarios
. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
. $PSScriptRoot\..\Test-SetupAssist.ps1
function Test-ArbitrationMailbox {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $selectString = $errorContext | Select-String -Pattern "Microsoft.Exchange.Data.Directory.ADConstraintViolationException.+the operation failed because UPN value provided for addition/modification is not unique forest-wide"

        if ($null -ne $selectString) {
            Write-Verbose "Found Arbitration Mailbox UPN issue."
            $errorContext |
                New-ErrorContext

            New-ActionPlan @(
                "This is a known issue, however, we are still investigating as to why this issue is occurring in some environments. Please email 'ExToolsFeedback@microsoft.com' ASAP to investigate this issue.",
                "Do NOT remove the arbitration mailboxes/accounts as they may contain critical information for your environment."
            )
        }
    }
}
