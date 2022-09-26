# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\Get-AllTlsSettingsFromRegistry.ps1
. $PSScriptRoot\Get-TlsCipherSuiteInformation.ps1

# Gets all related TLS Settings, from registry or other factors
function Get-AllTlsSettings {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [scriptblock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        return [PSCustomObject]@{
            Registry         = (Get-AllTlsSettingsFromRegistry -MachineName $MachineName -CatchActionFunction $CatchActionFunction)
            SecurityProtocol = (Invoke-ScriptBlockHandler -ComputerName $MachineName -ScriptBlock { ([System.Net.ServicePointManager]::SecurityProtocol).ToString() } -CatchActionFunction $CatchActionFunction)
            TlsCipherSuite   = (Get-TlsCipherSuiteInformation -MachineName $MachineName -CatchActionFunction $CatchActionFunction)
        }
    }
}
