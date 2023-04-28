# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Exchange\Get-SearchProcessState.ps1
. $PSScriptRoot\..\Write\Write-SearchProcessStateObject.ps1

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
