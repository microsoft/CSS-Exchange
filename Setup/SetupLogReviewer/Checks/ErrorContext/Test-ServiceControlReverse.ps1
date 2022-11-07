# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
function Test-ServiceControlReverse {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $selectString = $errorContext | Select-String -Pattern "System.Management.Automation.MethodInvocationException: Exception calling `"Reverse`" with `"1`" argument"

        if ($null -ne $selectString) {
            Write-Verbose "Found MethodInvocationException with Reverse, making sure we see Service Control as well"
            $selectString = $errorContext | Select-String -Pattern "ServiceControl.ps1"

            if ($null -ne $selectString) {
                Write-Verbose "Found known issue with ServiceControl.ps1, provide valid workaround."
                $errorContext |
                    New-ErrorContext
                New-ActionPlan @(
                    "1. Find the ServiceControl.ps1 in the Exchange Bin Directory",
                    "2. Find the following line in the script, within the StopServices function:"
                    "`t`$services = Get-ServiceToControl `$Roles -Active",
                    "3. Add in the following:",
                    "`tif (`$services -eq `$null) { return `$true }",
                    "4. Save the file and try to run Setup again."
                )
            } else {
                Write-Verbose "Didn't see ServiceControl.ps1, so might not be known issue."
            }
        }
    }
}
