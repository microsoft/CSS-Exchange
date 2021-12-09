# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-EndpointMapper {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $endpointMapper = $errorContext | Select-String -Pattern "System.Runtime.InteropServices.COMException \(0x800706D9\): There are no more endpoints available from the endpoint mapper. \(Exception from HRESULT: 0x800706D9\)"

        if ($null -ne $endpointMapper) {
            Write-Verbose "Found Endpoint Mapper Issue"
            $errorContext |
                Select-Object -Last ($errorContext.Count - ($endpointMapper.LineNumber | Select-Object -Last 1) + 3) |
                New-ErrorContext

            New-ActionPlan @(
                "Start the Windows Firewall Service, as this is required to run setup."
            )
        }
    }
}
