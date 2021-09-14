# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-KnownLdifErrors {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $schemaImportProcessFailure = $SetupLogReviewer |
            SelectStringLastRunOfExchangeSetup "\[ERROR\] There was an error while running 'ldifde.exe' to import the schema file '(.*)'. The error code is: (\d+). More details can be found in the error file: '(.*)'"

        if ($null -ne $schemaImportProcessFailure) {
            $schemaImportProcessFailure.Line | New-ErrorContext
            New-ActionPlan -ActionList @(
                "Failed to import schema setting from file '$($schemaImportProcessFailure.Matches.Groups[1].Value)'",
                "Review ldif.err file '$($schemaImportProcessFailure.Matches.Groups[3].Value)' to help determine which object in the file '$($schemaImportProcessFailure.Matches.Groups[1].Value)' was trying to be imported that was causing problems.",
                "If you can't find the ldf file in the C:\Windows\Temp location, then find the file in the ISO."
            )
            return
        }
        Write-Verbose "KnownLdifErrors - no known issue"
    }
}
