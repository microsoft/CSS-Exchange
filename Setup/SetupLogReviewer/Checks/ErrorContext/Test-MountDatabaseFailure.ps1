# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-MountDatabaseFailure {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $failedMountDatabase = $errorContext | Select-String "was run: `"System.InvalidOperationException: Failed to mount database `"(.+)`"\."

        if ($null -ne $failedMountDatabase) {
            Write-Verbose "Found failure to mount the database"
            $errorContext |
                Select-Object -Last ($errorContext.Count - ($failedMountDatabase.LineNumber | Select-Object -Last 1) + 3) |
                New-ErrorContext

            New-ActionPlan @(
                "Determine why you aren't able to mount the database and have it mounted prior to running setup again."
            )
        }
    }
}
