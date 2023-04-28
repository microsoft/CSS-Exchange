# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Exchange\Get-SearchProcessState.ps1
. $PSScriptRoot\..\Write\Write-SearchProcessStateObject.ps1

<#
    Used to call both the data collection of Get-SearchProcessState
    Then display it to the screen
#>
function Invoke-SearchServiceState {
    [CmdletBinding()]
    param(
        [string[]]$Servers
    )
    process {
        foreach ($server in $Servers) {
            $searchProcessState = Get-SearchProcessState -ComputerName $server
            Write-SearchProcessStateObject $searchProcessState
        }
    }
}
