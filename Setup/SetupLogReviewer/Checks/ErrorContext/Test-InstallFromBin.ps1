# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
function Test-InstallFromBin {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $installFromBin = $errorContext | Select-String -Pattern "The term '.+\\V15\\Bin\\ManageScheduledTask.ps1' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again"

        if ($null -ne $installFromBin) {
            Write-Verbose "Found issue for install from bin by ManageScheduledTask"

            $errorContext |
                New-ErrorContext

            New-ActionPlan @(
                "- Run Setup again, but when using powershell.exe you MUST USE '.\' prior to setup.exe."
            )
        }
    }
}
