# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-DefaultConnectExchangeShell.ps1

function Add-JobExchangeInformationCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )
    process {
        <#
            Non Default Script Block Dependencies
                Invoke-DefaultConnectExchangeShell
        #>
        function Invoke-JobExchangeInformationCmdlet {

        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
}
