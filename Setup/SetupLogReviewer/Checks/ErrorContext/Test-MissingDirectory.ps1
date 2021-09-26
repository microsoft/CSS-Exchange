# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-MissingDirectory {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $missingDirectory = $errorContext | Select-String -Pattern "System.Management.Automation.ItemNotFoundException: Cannot find path '(.+)' because it does not exist"

        if ($null -ne $missingDirectory) {
            Write-Verbose "Found missing directory issue"

            $missingDirectory.Line | New-ErrorContext
            New-ActionPlan @(
                "Create the directory: `"$($missingDirectory.Matches.Groups[1].Value)`""
            )
        }
    }
}
