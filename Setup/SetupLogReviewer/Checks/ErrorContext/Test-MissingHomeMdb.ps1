# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-MissingHomeMdb {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $databaseMandatory = $errorContext | Select-String "\[ERROR\] Database is mandatory on UserMailbox"

        if ($null -ne $databaseMandatory) {
            Write-Verbose "Found missing homeMdb value"
            $databaseMandatory.Line | Select-Object -First 1 | New-ErrorContext
            New-ActionPlan @(
                "Missing homeMdb on critical mailbox. Run SetupAssist.ps1 to find all problem mailboxes that needs to be addressed."
            )
        }
    }
}
