# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-DisabledService {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $serviceNotStarted = $errorContext |
            Select-String "System.ComponentModel.Win32Exception: The service cannot be started, either because it is disabled or because it has no enabled devices associated with it"

        if ($null -ne $serviceNotStarted) {
            Write-Verbose "Found Service isn't starting"
            $errorContext | New-ErrorContext
            New-ActionPlan @(
                "Required Exchange Services are failing to start because it appears to be disabled or dependent services are disabled. Enable them and try again",
                "NOTE: Might need to do this often while setup is running",
                "Example Command: Get-Service MSExchange* | Set-Service -StartupType Automatic"
            )
            return
        }
    }
}
